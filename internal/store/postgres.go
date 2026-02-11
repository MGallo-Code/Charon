// Package store handles all database and cache interactions.
//
// postgres.go -- pgxpool connection setup and queries.
// Creates a connection pool at startup, shared across all handlers.
// All queries use parameterized statements (no string concatenation).
package store

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User represents a row in the users table.
// Nullable columns are pointers — nil means SQL NULL.
type User struct {
	ID               uuid.UUID
	Email            *string
	Phone            *string
	EmailConfirmedAt *time.Time
	PhoneConfirmedAt *time.Time
	FirstName        *string
	LastName         *string
	PasswordHash     string
	OAuthProvider    *string
	OAuthProviderID  *string
	AvatarURL        *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

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

// CreateUserByEmail inserts a new user with email + password credentials.
// The caller has to generate the UUID v7 and Argon2id hash BEFORE calling this.
// Returns raw pgx error, handler inspects it for unique violations (duplicate email, etc...)
func (s *PostgresStore) CreateUserByEmail(ctx context.Context, id uuid.UUID, email string, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
		id, email, passwordHash)
	return err
}

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
