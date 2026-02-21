// postgres.go

// pgxpool connection setup and SQL queries.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore wraps pgxpool connection pool for database ops
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates and returns a VERIFIED connection pool to PostgreSQL.
// Call once at startup from main.go. Given store safe for concurrent use...
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	// Create a pool w/ database url, return if err
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	// Ping db to make sure connection works
	err = pool.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return &PostgresStore{pool}, nil
}

// Close shuts down connection pool, releases all resources.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// CreateUserByEmail inserts new user with email and password hash.
// Caller generates UUID v7 and Argon2id hash before calling.
// Returns raw pgx error so handler can inspect for unique violations.
func (s *PostgresStore) CreateUserByEmail(ctx context.Context, id uuid.UUID, email string, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users
			(id, email, password_hash)
		VALUES
			($1, $2, $3)
		`, id, email, passwordHash)
	if err != nil {
		return fmt.Errorf("creating user by email: %w", err)
	}
	return nil
}

// GetUserByEmail fetches user by email address.
// Returns pgx.ErrNoRows if no user exists with that email.
func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	// Initialize user pointer
	user := &User{}

	// Query db for user info where email matches
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, created_at, updated_at,
			email_confirmed_at, phone, phone_confirmed_at,
			first_name, last_name, oauth_provider, oauth_provider_id, avatar_url
		FROM users
		WHERE email = $1;
	`, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
		&user.EmailConfirmedAt, &user.Phone, &user.PhoneConfirmedAt,
		&user.FirstName, &user.LastName, &user.OAuthProvider, &user.OAuthProviderID, &user.AvatarURL,
	)

	// If err, return it
	if err != nil {
		return nil, fmt.Errorf("fetching user by email: %w", err)
	}

	// Otherwise, return user!
	return user, nil
}

// GetUserByID fetches user by UUID.
// Returns pgx.ErrNoRows if no user exists with that ID.
func (s *PostgresStore) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	// Init user var
	user := &User{}

	// Attempt to fetch user by ID
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, created_at, updated_at,
			email_confirmed_at, phone, phone_confirmed_at,
			first_name, last_name, oauth_provider, oauth_provider_id, avatar_url
		FROM users
		WHERE id = $1
	`, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
		&user.EmailConfirmedAt, &user.Phone, &user.PhoneConfirmedAt,
		&user.FirstName, &user.LastName, &user.OAuthProvider, &user.OAuthProviderID, &user.AvatarURL,
	)

	// If an error, return it
	if err != nil {
		return nil, fmt.Errorf("fetching user by id: %w", err)
	}

	// Otherwise return user!
	return user, nil
}

// UpdateUserPassword replaces the stored Argon2id hash for the given user.
// Caller is responsible for hashing the new password before calling.
func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET
			password_hash = $2,
			updated_at = NOW()
		WHERE id = $1
	`, id, passwordHash)
	// report any errs
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	return nil
}

// CreateSession inserts new session row.
// Caller generates UUID v7, SHA-256 token hash, and expiresAt before calling.
// ip and userAgent are optional - pass nil to omit.
func (s *PostgresStore) CreateSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error {
	// Insert session into pg table
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions
			(id, user_id, token_hash, csrf_token, expires_at, ip_address, user_agent)
		VALUES
			($1, $2, $3, $4, $5, $6, $7)
	`, id, userID, tokenHash, csrfToken, expiresAt, ip, userAgent)
	// if err, report!
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}

// GetSessionByTokenHash fetches non-expired session by hashed token.
// Returns pgx.ErrNoRows if no valid session exists with that hash.
func (s *PostgresStore) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	// Init sesh obj..
	session := &Session{}
	// Fetch matching NON-EXPIRED sessions
	err := s.pool.QueryRow(ctx, `
		SELECT
			id, user_id, token_hash, csrf_token, expires_at, ip_address, user_agent, created_at
		FROM sessions
		WHERE
			token_hash = $1
			AND expires_at > NOW()
	`, tokenHash).Scan(&session.ID, &session.UserID, &session.TokenHash, &session.CSRFToken, &session.ExpiresAt,
		&session.IPAddress, &session.UserAgent, &session.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("fetching session by token hash: %w", err)
	}
	return session, nil
}

// DeleteSession removes a single session by its hashed token.
func (s *PostgresStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	// Delete session w/ matching token hash
	_, err := s.pool.Exec(ctx, `
		DELETE FROM sessions
		WHERE token_hash = $1
	`, tokenHash)
	if err != nil {
		return fmt.Errorf("deleting session by token hash: %w", err)
	}
	return nil
}

// DeleteAllUserSessions removes all sessions for a given user.
// Used for "log out everywhere" or after a password change.
func (s *PostgresStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	// Delete session w/ matching user ids
	_, err := s.pool.Exec(ctx, `
		DELETE FROM sessions
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("deleting session by user id: %w", err)
	}
	return nil
}

// CleanupExpiredSessions deletes sessions expired before retention cutoff.
// Pass a grace window (e.g. 7*24*time.Hour) to retain sessions for audit before deletion.
// Returns rows deleted.
func (s *PostgresStore) CleanupExpiredSessions(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	result, err := s.pool.Exec(ctx, `
		DELETE FROM sessions
		WHERE expires_at < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleaning up expired sessions: %w", err)
	}
	return result.RowsAffected(), nil
}
