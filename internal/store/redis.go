// redis.go -- go-redis client for session caching.
//
// Stores session data with TTL matching session expiry.
// Fast path for session validation (~0.1ms vs ~1-5ms for Postgres).
// If Redis is unavailable, falls back to Postgres.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/redis/go-redis/v9"
)

// RedisStore wraps a Redis client for session cache operations.
type RedisStore struct {
	rdb *redis.Client
}

// NewRedisStore connects to Redis and returns a ready-to-use cache store.
// It pings Redis to verify connectivity before returning.
// Call once at startup from main.go...returned store is safe for concurrent use.
func NewRedisStore(ctx context.Context, redisURL string) (*RedisStore, error) {
	// Parse redisURL to get option values, if err return it
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	// Create new redis client
	rdb := redis.NewClient(opt)

	// Try and test client to ensure it works correctly
	err = rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}

	return &RedisStore{rdb}, nil
}

// Close shuts down the Redis client and releases all resources.
// Should be called via defer in main.go after creating the store.
func (s *RedisStore) Close() error {
	err := s.rdb.Close()
	return err
}

// SetSession caches a session in Redis with given TTL (in seconds).
// Also tracks token hash in per-user Set for bulk deletion.
func (s *RedisStore) SetSession(ctx context.Context, tokenHash string, sessionData Session, ttl int) error {
	// Put session data into json string format for redis-structured session obj
	cacheOut, err := json.Marshal(CachedSession{
		UserID:    sessionData.UserID,
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

	// Exec pipeline cmds, return any err
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("caching session: %w", err)
	}
	return nil
}

// GetSession retrieves a cached session by its token hash.
// Returns nil if session not found or if Redis unavailable.
func (s *RedisStore) GetSession(ctx context.Context, tokenHash string) (*CachedSession, error) {
	// Attempt to get session JSON from Redis
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

// DeleteSession removes a single session from cache by its token hash.
// Also removes the token hash from the user's tracking Set.
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
// Uses per-user Redis Set to track which token hashes belong to user.
func (s *RedisStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	setKey := fmt.Sprintf("user_sessions:%s", userID)

	// Get all token hashes for this user
	hashes, err := s.rdb.SMembers(ctx, setKey).Result()
	if err != nil {
		return fmt.Errorf("fetching user sessions: %w", err)
	}

	// Delete all session keys + the set itself in one atomic pipeline
	pipe := s.rdb.TxPipeline()
	for _, hash := range hashes {
		pipe.Del(ctx, fmt.Sprintf("session:%s", hash))
	}
	pipe.Del(ctx, setKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}
