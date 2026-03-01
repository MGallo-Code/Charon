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
		return nil, fmt.Errorf("pinging redis initial: %w", err)
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

// CheckHealth returns an error if there is a problem pinging the cache,
// returns nil when redis cache is healthy
func (s *RedisStore) CheckHealth(ctx context.Context) error {
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("pinging redis: %w", err)
	}
	return nil
}

// SetSession caches session with given TTL in seconds.
// Also tracks token hash in per-user set for bulk deletion.
// No-ops silently if a tombstone is present -- session was recently deleted and must not be repopulated.
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

	sessionKey := "session:" + tokenHash
	userSetKey := "user_sessions:" + sessionData.UserID.String()

	result, err := setSessionScript.Run(ctx, s.rdb,
		[]string{sessionKey, userSetKey},
		cacheOut,
		ttl,
		tokenHash,
	).Int64()
	if err != nil {
		return fmt.Errorf("caching session: %w", err)
	}
	if result == 0 {
		// tombstone present -- session was recently deleted, skip repopulation
		return nil
	}
	return nil
}

// GetSession retrieves cached session by token hash.
// Returns ErrCacheMiss on a true Redis miss; ErrSessionTombstoned if the session
// was recently deleted; other errors indicate infrastructure failures.
func (s *RedisStore) GetSession(ctx context.Context, tokenHash string) (*CachedSession, error) {
	raw, err := s.rdb.Get(ctx, "session:"+tokenHash).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheMiss
		}
		return nil, fmt.Errorf("fetching session: %w", err)
	}

	if raw == "tombstone" {
		return nil, ErrSessionTombstoned
	}

	// Unmarshal JSON into CachedSession
	var cached CachedSession
	if err := json.Unmarshal([]byte(raw), &cached); err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}

	return &cached, nil
}

// DeleteSession writes a 60-second tombstone for the session key and removes it from
// the user tracking set. Tombstone prevents Postgres-fallback repopulation of deleted sessions.
func (s *RedisStore) DeleteSession(ctx context.Context, tokenHash string, userID uuid.UUID) error {
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, "session:"+tokenHash, "tombstone", 60*time.Second)
	pipe.SRem(ctx, "user_sessions:"+userID.String(), tokenHash)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

// DeleteAllUserSessions removes all cached sessions for given user.
// Uses a Lua script so the read-and-delete is atomic -- no concurrent SetSession can slip through.
func (s *RedisStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	setKey := "user_sessions:" + userID.String()
	if err := deleteAllSessionsScript.Run(ctx, s.rdb, []string{setKey}, "session:").Err(); err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// deleteAllSessionsScript atomically fetches every token hash for a user, writes a 60-second
// tombstone for each session key, then removes the tracking set in a single Redis operation.
// Tombstones prevent concurrent Postgres fallbacks from repopulating deleted sessions.
// KEYS[1] = "user_sessions:{userID}", ARGV[1] = "session:" prefix.
// Returns the number of session keys tombstoned.
var deleteAllSessionsScript = redis.NewScript(`
local hashes = redis.call('SMEMBERS', KEYS[1])
for _, hash in ipairs(hashes) do
    redis.call('SET', ARGV[1] .. hash, 'tombstone', 'PX', 60000)
end
redis.call('DEL', KEYS[1])
return #hashes
`)

// setSessionScript atomically guards SetSession against overwriting tombstones.
// Returns 0 without writing if the session key currently holds a tombstone.
// Returns 1 and writes the session, SADD, and a conditional EXPIRE on success.
// When ttl > 0: sets the session key with EX and extends the user-set TTL only if
// the new TTL is greater than the current one (EXPIREGT semantics without Redis 7.0).
// When ttl == 0: stores without expiry (no-expiry sessions never shrink the user set's TTL).
// KEYS[1] = session key, KEYS[2] = user set key.
// ARGV[1] = session JSON, ARGV[2] = TTL in seconds, ARGV[3] = tokenHash (for SADD).
var setSessionScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == 'tombstone' then
    return 0
end
local ttl = tonumber(ARGV[2])
if ttl > 0 then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ttl)
else
    redis.call('SET', KEYS[1], ARGV[1])
end
redis.call('SADD', KEYS[2], ARGV[3])
if ttl > 0 then
    local curTTL = redis.call('TTL', KEYS[2])
    if curTTL == -1 or curTTL < ttl then
        redis.call('EXPIRE', KEYS[2], ttl)
    end
end
return 1
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
		"rl:lockout:" + key,
		"rl:counter:" + key,
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

// NoopSessionCache satisfies the auth.SessionCache interface when Redis is not configured.
// GetSession always returns ErrCacheMiss, driving every validation through Postgres.
// All write operations are no-ops. CheckHealth returns ErrCacheDisabled.
type NoopSessionCache struct{}

// GetSession always returns ErrCacheMiss -- triggers the Postgres fallback in RequireAuth.
func (n *NoopSessionCache) GetSession(_ context.Context, _ string) (*CachedSession, error) {
	return nil, ErrCacheMiss
}

// SetSession is a no-op -- Postgres is the durable store; nothing to cache without Redis.
func (n *NoopSessionCache) SetSession(_ context.Context, _ string, _ Session, _ int) error {
	return nil
}

// DeleteSession is a no-op -- no cache entries exist without Redis.
func (n *NoopSessionCache) DeleteSession(_ context.Context, _ string, _ uuid.UUID) error {
	return nil
}

// DeleteAllUserSessions is a no-op -- no cache entries exist without Redis.
func (n *NoopSessionCache) DeleteAllUserSessions(_ context.Context, _ uuid.UUID) error {
	return nil
}

// CheckHealth returns ErrCacheDisabled -- signals /health that Redis is intentionally absent.
func (n *NoopSessionCache) CheckHealth(_ context.Context) error {
	return ErrCacheDisabled
}

// NewNoopSessionCache returns a NoopSessionCache for use when REDIS_URL is not set.
func NewNoopSessionCache() *NoopSessionCache {
	return &NoopSessionCache{}
}

// NoopRateLimiter satisfies the auth.RateLimiter interface when Redis is not configured.
// Allow always returns nil -- all requests are permitted without tracking.
type NoopRateLimiter struct{}

// Allow always permits the request; rate limiting is unavailable without Redis.
func (n *NoopRateLimiter) Allow(_ context.Context, _ string, _ RateLimit) error {
	return nil
}

// NewNoopRateLimiter returns a NoopRateLimiter for use when REDIS_URL is not set.
func NewNoopRateLimiter() *NoopRateLimiter {
	return &NoopRateLimiter{}
}
