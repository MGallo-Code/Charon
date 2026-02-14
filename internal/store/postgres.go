// Package store handles all database and cache interactions.
//
// postgres.go -- pgxpool connection setup and queries.
// Creates a connection pool at startup, shared across all handlers.
// All queries use parameterized statements (no string concatenation).
package store

import (
	"context"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore wraps a pgxpool connection pool for database ops
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates and returns a VERIFIED connection pool to PostgreSQL.
// Call once at startup from main.go. Given store safe for concurrent use...
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
// Call using defer in main.go after creating the store.
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

// GetUserByEmail fetches a user by their email address.
// (For login by email for verification)
// Returns pgx.ErrNoRows if no user exists with that email.
func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	// Initialize user pointer
	user := new(User)

	// Query db for user info where email matches
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, created_at, updated_at,
			email_confirmed_at, phone, phone_confirmed_at,
			first_name, last_name, oauth_provider, oauth_provider_id, avatar_url
		FROM users WHERE email = $1;
	`, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
		&user.EmailConfirmedAt, &user.Phone, &user.PhoneConfirmedAt,
		&user.FirstName, &user.LastName, &user.OAuthProvider, &user.OAuthProviderID, &user.AvatarURL,
	)

	// If err, return it
	if err != nil {
		return nil, err
	}

	// Otherwise, return user!
	return user, nil
}

// GetUserByID fetches a user by their UUID.
// For after login, profile lookups, password changes, etc...
// Returns pgx.ErrNoRows if no user exists with that ID.
func (s *PostgresStore) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	// Init user var
	user := new(User)

	// Attempt to fetch user by ID
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, created_at, updated_at,
			email_confirmed_at, phone, phone_confirmed_at,
			first_name, last_name, oauth_provider, oauth_provider_id, avatar_url
		FROM users WHERE id = $1
	`, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
		&user.EmailConfirmedAt, &user.Phone, &user.PhoneConfirmedAt,
		&user.FirstName, &user.LastName, &user.OAuthProvider, &user.OAuthProviderID, &user.AvatarURL,
	)

	// If an error, return it
	if err != nil {
		return nil, err
	}

	// Otherwise return user!
	return user, nil
}

// 5. Session queries:
//    - CreateSession(ctx, userID, tokenHash, expiresAt, ip, userAgent) → error
//    - GetSessionByTokenHash(ctx, tokenHash) → (session, error)
//    - DeleteSession(ctx, tokenHash) → error
//    - DeleteAllUserSessions(ctx, userID) → error
//
// Key concepts
//    - context.Context   -- passed into every query for timeouts/cancellation
//    - pool.QueryRow()   -- for single-row results (login, session lookup)
//    - pool.Exec()       -- for inserts/deletes with no return value
//    - .Scan(&vars)      -- reads query results into Go variables
//    - defer rows.Close() -- always close row iterators when done
