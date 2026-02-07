// redis.go -- go-redis client for session caching.
//
// Stores session data with TTL matching session expiry.
// Fast path for session validation (~0.1ms vs ~1-5ms for Postgres).
// If Redis is unavailable, falls back to Postgres.
package store

import (
	"context"

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

// 5. Session cache operations (add later as you build auth handlers):
//    - SetSession(ctx, tokenHash, sessionData, ttl) → error
//    - GetSession(ctx, tokenHash) → (sessionData, error)
//    - DeleteSession(ctx, tokenHash) → error
//    - DeleteAllUserSessions(ctx, userID) → error
