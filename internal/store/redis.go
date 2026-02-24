// redis.go

// go-redis client for session caching and rate limiting.
package store

import (
	"context"
	"encoding/json"
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
// Uses a Lua script so the read-and-delete is atomic -- no concurrent SetSession can slip through.
func (s *RedisStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	setKey := fmt.Sprintf("user_sessions:%s", userID)
	if err := deleteAllSessionsScript.Run(ctx, s.rdb, []string{setKey}, "session:").Err(); err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// deleteAllSessionsScript atomically fetches every token hash for a user, deletes each
// session key, then removes the tracking set in a single Redis operation.
// Prevents a concurrent SetSession from slipping through between SMEMBERS and DEL.
// KEYS[1] = "user_sessions:{userID}", ARGV[1] = "session:" prefix.
// Returns the number of session keys deleted.
var deleteAllSessionsScript = redis.NewScript(`
local hashes = redis.call('SMEMBERS', KEYS[1])
for _, hash in ipairs(hashes) do
    redis.call('DEL', ARGV[1] .. hash)
end
redis.call('DEL', KEYS[1])
return #hashes
`)

// allowScript atomically checks lockout, increments the attempt counter, sets the window TTL
// on the first attempt, and writes the lockout key when the threshold is reached.
// Eliminates the TOCTOU window between the lockout check and counter increment.
// KEYS[1] = lockout key, KEYS[2] = counter key.
// ARGV[1] = max_attempts, ARGV[2] = window (ms), ARGV[3] = lockout TTL (ms).
// Returns 1 if the attempt is blocked, 0 if allowed.
var allowScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 1
end
local count = redis.call('INCR', KEYS[2])
if count == 1 then
    redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[2]))
end
if count >= tonumber(ARGV[1]) then
    redis.call('SET', KEYS[1], '', 'PX', tonumber(ARGV[3]))
    return 1
end
return 0
`)

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
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, policy RateLimit) error {
	keys := []string{
		fmt.Sprintf("rl:lockout:%s", key),
		fmt.Sprintf("rl:counter:%s", key),
	}
	blocked, err := allowScript.Run(ctx, r.rdb, keys,
		policy.MaxAttempts,
		policy.Window.Milliseconds(),
		policy.LockoutTTL.Milliseconds(),
	).Int64()
	if err != nil {
		return fmt.Errorf("checking rate limit: %w", err)
	}
	if blocked == 1 {
		return ErrRateLimitExceeded
	}
	return nil
}
