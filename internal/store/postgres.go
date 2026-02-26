// postgres.go

// pgxpool connection setup and SQL queries.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
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
		return nil, fmt.Errorf("pinging database initial: %w", err)
	}

	return &PostgresStore{pool}, nil
}

// Close shuts down connection pool, releases all resources.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// CheckHealth returns an error if there is a problem pinging the database,
// returns nil when database is healthy
func (s *PostgresStore) CheckHealth(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	return nil
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
	user := &User{
		Email: &email,
	}

	// Query db for user info where email matches
	err := s.pool.QueryRow(ctx, `
		SELECT id, password_hash, email_confirmed_at, first_name, last_name
		FROM users
		WHERE email = $1;
	`, email).Scan(
		&user.ID, &user.PasswordHash, &user.EmailConfirmedAt, &user.FirstName, &user.LastName,
	)

	// If err, return it
	if err != nil {
		return nil, fmt.Errorf("fetching user by email: %w", err)
	}

	// Otherwise, return user!
	return user, nil
}

// GetPwdHashByUserID fetches Argon2id password hash for the given user.
// Returns pgx.ErrNoRows if no user exists with that ID.
// Returns ErrNoPassword if the user exists but has no password_hash (OAuth-only account).
func (s *PostgresStore) GetPwdHashByUserID(ctx context.Context, id uuid.UUID) (string, error) {
	var passwordHash *string
	err := s.pool.QueryRow(ctx, `
		SELECT password_hash
		FROM users
		WHERE id = $1
	`, id).Scan(&passwordHash)
	if err != nil {
		return "", fmt.Errorf("fetching password hash by user id: %w", err)
	}
	if passwordHash == nil {
		return "", fmt.Errorf("fetching password hash by user id: %w", ErrNoPassword)
	}
	return *passwordHash, nil
}

// UpdateUserPassword replaces the stored Argon2id hash for the given user.
// Caller is responsible for hashing the new password before calling.
// Returns pgx.ErrNoRows if no user exists with that ID.
func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2,
			updated_at = NOW()
		WHERE id = $1
	`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("updating user password: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("updating user password: %w", pgx.ErrNoRows)
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
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

// GetSessionByTokenHash fetches non-expired session by hashed token.
// Returns pgx.ErrNoRows if no valid session exists with that hash.
func (s *PostgresStore) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	// Init sesh obj..
	session := &Session{
		TokenHash: tokenHash,
	}
	// Fetch matching NON-EXPIRED sessions
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, csrf_token, expires_at
		FROM sessions
		WHERE token_hash = $1
			AND expires_at > NOW()
	`, tokenHash).Scan(&session.ID, &session.UserID, &session.CSRFToken, &session.ExpiresAt)
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

// CreateToken inserts a new verification token row.
// Caller generates the UUID, hashes the raw token (SHA-256), and sets expires_at.
// tokenType must be a valid CHECK value ('password_reset', 'email_verification').
func (s *PostgresStore) CreateToken(ctx context.Context, id, userID uuid.UUID, tokenType string, tokenHash []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tokens
			(id, user_id, token_type, token_hash, expires_at, created_at)
		VALUES
			($1, $2, $3, $4, $5, NOW())
	`, id, userID, tokenType, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("creating token: %w", err)
	}
	return nil
}

// GetTokenByHash fetches a token row by its SHA-256 hash.
// Returns pgx.ErrNoRows if not found, expired, or already used.
// Validates expires_at > NOW() and used_at IS NULL in the query -- never returns a stale token.
func (s *PostgresStore) GetTokenByHash(ctx context.Context, tokenHash []byte, tokenType string) (*Token, error) {
	// init token
	token := &Token{
		TokenType: tokenType,
		TokenHash: tokenHash,
	}
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, used_at, expires_at
		FROM tokens
		WHERE token_hash = $1
			AND token_type = $2
			AND used_at IS NULL
			AND expires_at > NOW()
	`, tokenHash, tokenType).Scan(&token.ID, &token.UserID, &token.UsedAt, &token.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("fetching token by token hash: %w", err)
	}
	return token, nil
}

// MarkTokenUsed sets used_at = NOW() for the token with the given hash.
// Returns pgx.ErrNoRows if no matching unused token exists (already used or never existed).
// Call only after verifying the token -- prevents double-use.
func (s *PostgresStore) MarkTokenUsed(ctx context.Context, tokenHash []byte) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE tokens
		SET used_at = NOW()
		WHERE token_hash = $1
			AND used_at IS NULL
	`, tokenHash)
	if err != nil {
		return fmt.Errorf("marking token as used: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("marking token as used: %w", pgx.ErrNoRows)
	}
	return nil
}

// SetEmailConfirmedAt sets email_confirmed_at = NOW() for userID if not already confirmed.
func (s *PostgresStore) SetEmailConfirmedAt(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET email_confirmed_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
			AND email_confirmed_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("updating email_confirmed_at: %w", err)
	}
	return nil
}

// ConsumeToken atomically marks a valid token as used and returns the associated user_id in one query.
func (s *PostgresStore) ConsumeToken(ctx context.Context, tokenHash []byte, tokenType string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		UPDATE tokens
		SET used_at = NOW()
		WHERE token_hash = $1
			AND token_type = $2
			AND used_at IS NULL
			AND expires_at > NOW()
		RETURNING user_id
	`, tokenHash, tokenType).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.UUID{}, fmt.Errorf("consuming token: %w", pgx.ErrNoRows)
		}
		return uuid.UUID{}, fmt.Errorf("consuming token: %w", err)
	}
	return userID, nil
}

// WriteAuditLog inserts a single audit event row into audit_logs table.
func (s *PostgresStore) WriteAuditLog(ctx context.Context, entry AuditEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs
			(user_id, action, ip_address, user_agent, metadata)
		VALUES
			($1, $2, $3, $4, $5)
	`, entry.UserID, entry.Action, entry.IPAddress, entry.UserAgent, entry.Metadata)
	if err != nil {
		return fmt.Errorf("creating audit log: %w", err)
	}
	return nil
}

// GetUserByOAuthProvider fetches a user by oauth_provider + oauth_provider_id.
func (s *PostgresStore) GetUserByOAuthProvider(ctx context.Context, oauthProvider, oauthProviderID string) (*User, error) {
	user := &User{
		OAuthProvider:   &oauthProvider,
		OAuthProviderID: &oauthProviderID,
	}
	err := s.pool.QueryRow(ctx, `
		SELECT
			id, email, email_confirmed_at
		FROM users
		WHERE oauth_provider = $1
			AND oauth_provider_id = $2
	`, oauthProvider, oauthProviderID).Scan(&user.ID, &user.Email, &user.EmailConfirmedAt)
	if err != nil {
		return nil, fmt.Errorf("fetching user by oauth provider: %w", err)
	}
	return user, nil
}

// CreateOAuthUser inserts a new user authenticated via an OAuth provider.
func (s *PostgresStore) CreateOAuthUser(ctx context.Context, id uuid.UUID, email, oauthProvider, oauthProviderID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users
			(id, email, oauth_provider, oauth_provider_id, email_confirmed_at)
		VALUES
			($1, $2, $3, $4, NOW())
	`, id, email, oauthProvider, oauthProviderID)
	if err != nil {
		return fmt.Errorf("creating oauth user: %w", err)
	}
	return nil
}

// LinkOAuthToUser sets oauth_provider and oauth_provider_id on an existing user.
func (s *PostgresStore) LinkOAuthToUser(ctx context.Context, id uuid.UUID, oauthProvider, oauthProviderID string) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE users
		SET oauth_provider = $1,
			oauth_provider_id = $2,
			updated_at = NOW()
		WHERE id = $3
			AND oauth_provider IS NULL
	`, oauthProvider, oauthProviderID, id)
	if err != nil {
		return fmt.Errorf("linking oauth to user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("linking oauth to not-found user: %w", pgx.ErrNoRows)
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
