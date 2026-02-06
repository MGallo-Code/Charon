// redis.go -- go-redis client for session caching.
//
// Stores session data with TTL matching session expiry.
// Fast path for session validation (~0.1ms vs ~1-5ms for Postgres).
// If Redis is unavailable, falls back to Postgres.
package store
