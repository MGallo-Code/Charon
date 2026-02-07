// Package store handles all database and cache interactions.
//
// postgres.go -- pgxpool connection setup and queries.
// Creates a connection pool at startup, shared across all handlers.
// All queries use parameterized statements (no string concatenation).
package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The store used by program to connect with Postgres db
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates and returns a verified connection pool
// to PostgreSQL wrapped in a storeand returns a ready-to-use store.
// Call once at startup from main.go...the returned store is safe for concurrent use.
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	// Create a pool w/ database url, return if err
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}

	// Ping db to make sure connection works
	err = pool.Ping(ctx)
	if err != nil {
		return nil, err
	}

	return &PostgresStore{pool}, nil
}

// Close shuts down the connection pool and releases all resources.
// Supposed to call via defer in main.go after creating the store.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// 4. User queries (add these as you build auth handlers):
//    - CreateUser(ctx, email, passwordHash) → (userID, error)
//    - GetUserByEmail(ctx, email) → (user, error)
//
// 5. Session queries:
//    - CreateSession(ctx, userID, tokenHash, expiresAt, ip, userAgent) → error
//    - GetSessionByTokenHash(ctx, tokenHash) → (session, error)
//    - DeleteSession(ctx, tokenHash) → error
//    - DeleteAllUserSessions(ctx, userID) → error
//
// Key concepts you'll use:
//    - context.Context   -- passed into every query for timeouts/cancellation
//    - pool.QueryRow()   -- for single-row results (login, session lookup)
//    - pool.Exec()       -- for inserts/deletes with no return value
//    - .Scan(&vars)      -- reads query results into Go variables
//    - defer rows.Close() -- always close row iterators when done
