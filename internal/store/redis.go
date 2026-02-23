// redis.go

// go-redis client for session caching and rate limiting.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/redis/go-redis/v9"
)

// NewRedisClient parses redisURL, connects, and pings to verify connectivity.
// Returns a shared client to pass to NewRedisStore and NewRedisRateLimiter.
// Call once at startup -- caller is responsible for closing the client.
func NewRedisClient(ctx context.Context, redisURL string) (*redis.Client, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis url: %w", err)
	}
	rdb := redis.NewClient(opt)
	if err = rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("pinging redis: %w", err)
	}
	return rdb, nil
}

// RedisStore wraps Redis client for session cache operations.
type RedisStore struct {
	rdb *redis.Client
}

// NewRedisStore wraps an existing Redis client for session cache operations.
// Client lifecycle (Close) is managed by the caller.
func NewRedisStore(rdb *redis.Client) *RedisStore {
	return &RedisStore{rdb}
}

// Close shuts down the underlying Redis client and releases all resources.
func (s *RedisStore) Close() error {
	if err := s.rdb.Close(); err != nil {
		return fmt.Errorf("closing redis: %w", err)
	}
	return nil
}

// SetSession caches session with given TTL in seconds.
// Also tracks token hash in per-user set for bulk deletion.
func (s *RedisStore) SetSession(ctx context.Context, tokenHash string, sessionData Session, ttl int) error {
	// Put session data into json string format for redis-structured session obj
	cacheOut, err := json.Marshal(CachedSession{
		UserID:    sessionData.UserID,
		CSRFToken: sessionData.CSRFToken,
		ExpiresAt: sessionData.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	// Create pipeline to make sure atomic
	pipe := s.rdb.TxPipeline()
	// Initiate setting
	pipe.Set(ctx,
		/* Key */
		fmt.Sprintf("session:%s", tokenHash),
		/* Val */
		cacheOut,
		/* Exp time (s) */
		time.Duration(ttl)*time.Second)

	// Add session token hash to user's sessions group
	pipe.SAdd(ctx,
		/* Key */
		fmt.Sprintf("user_sessions:%s", sessionData.UserID),
		/* Val */
		tokenHash)

	// If TTL is larger than current group TTL, extend the TTL, otherwise do nothing
	pipe.ExpireGT(ctx,
		/* Key */
		fmt.Sprintf("user_sessions:%s", sessionData.UserID),
		/* TTL */
		time.Duration(ttl)*time.Second)

	// Exec pipeline cmds, return any err
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("caching session: %w", err)
	}
	return nil
}

// GetSession retrieves cached session by token hash.
// Returns error on miss or if Redis unavailable.
func (s *RedisStore) GetSession(ctx context.Context, tokenHash string) (*CachedSession, error) {
	// Attempt to get session JSON from redis cache
	raw, err := s.rdb.Get(ctx, fmt.Sprintf("session:%s", tokenHash)).Result()
	if err != nil {
		return nil, fmt.Errorf("fetching session: %w", err)
	}

	// Unmarshal JSON into CachedSession
	var cached CachedSession
	if err := json.Unmarshal([]byte(raw), &cached); err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}

	return &cached, nil
}

// DeleteSession removes session from cache and from user tracking set.
func (s *RedisStore) DeleteSession(ctx context.Context, tokenHash string, userID uuid.UUID) error {
	pipe := s.rdb.TxPipeline()

	// Delete session data
	pipe.Del(ctx, fmt.Sprintf("session:%s", tokenHash))
	// Remove token hash from user's sessions set
	pipe.SRem(ctx, fmt.Sprintf("user_sessions:%s", userID), tokenHash)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

// DeleteAllUserSessions removes all cached sessions for given user.
// Uses per-user set to find all token hashes belonging to user.
func (s *RedisStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	setKey := fmt.Sprintf("user_sessions:%s", userID)

	// Get all token hashes for this user
	hashes, err := s.rdb.SMembers(ctx, setKey).Result()
	if err != nil {
		return fmt.Errorf("fetching user sessions: %w", err)
	}

	// Delete all session keys + set itself in one atomic pipeline
	pipe := s.rdb.TxPipeline()
	for _, hash := range hashes {
		pipe.Del(ctx, fmt.Sprintf("session:%s", hash))
	}
	pipe.Del(ctx, setKey)

	// Gogogo do it
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// RedisRateLimiter implements auth.RateLimiter using Redis counters and lockout keys.
// Holds a reference to the shared Redis client -- does not own its lifecycle.
type RedisRateLimiter struct {
	rdb *redis.Client
}

// NewRedisRateLimiter wraps an existing Redis client for rate limiting operations.
// Client lifecycle (Close) is managed by the caller.
func NewRedisRateLimiter(rdb *redis.Client) *RedisRateLimiter {
	return &RedisRateLimiter{rdb}
}

// Allow checks whether the action identified by key is within policy limits.
// Returns nil if the attempt is allowed; non-nil error if locked out or threshold exceeded.
// Two Redis keys per action:
//   - "rl:counter:{key}" -- attempt counter, expires after policy.Window
//   - "rl:lockout:{key}" -- lockout flag, expires after policy.LockoutTTL
//
// Check lockout key first (fast reject if already blocked).
// Increment counter; on first increment, set TTL to policy.Window.
// When counter reaches policy.MaxAttempts, write lockout key with TTL = policy.LockoutTTL.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, policy RateLimit) error {
	lockoutKey := fmt.Sprintf("rl:lockout:%s", key)

	// Fast reject if already locked out
	err := r.rdb.Get(ctx, lockoutKey).Err()
	if err == nil {
		return ErrRateLimitExceeded
	}
	if !errors.Is(err, redis.Nil) {
		return fmt.Errorf("checking rate limit lockout: %w", err)
	}

	counterKey := fmt.Sprintf("rl:counter:%s", key)

	// Increment attempt counter
	count, err := r.rdb.Incr(ctx, counterKey).Result()
	if err != nil {
		return fmt.Errorf("incrementing rate limit counter: %w", err)
	}
	// First attempt in window -- set expiry so counter resets after Window
	if count == 1 {
		if err := r.rdb.ExpireNX(ctx, counterKey, policy.Window).Err(); err != nil {
			return fmt.Errorf("setting rate limit window: %w", err)
		}
	}
	// Threshold reached -- write lockout key
	if count >= int64(policy.MaxAttempts) {
		if err := r.rdb.Set(ctx, lockoutKey, "", policy.LockoutTTL).Err(); err != nil {
			return fmt.Errorf("setting rate limit lockout: %w", err)
		}
	}
	return nil
}
