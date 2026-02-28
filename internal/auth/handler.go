// handler.go -- Interfaces, policy types, and AuthHandler struct for the auth package.
package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/MGallo-Code/charon/internal/mail"
	"github.com/MGallo-Code/charon/internal/oauth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// SessionCache defines session cache operations needed by auth handlers.
// Satisfied by *store.RedisStore — defined here (at consumer) per Go convention.
type SessionCache interface {
	// GetSession retrieves cached session by token hash.
	GetSession(ctx context.Context, tokenHash string) (*store.CachedSession, error)

	// SetSession caches session with given TTL in seconds.
	SetSession(ctx context.Context, tokenHash string, sessionData store.Session, ttl int) error

	// DeleteSession removes session and its entry in the user tracking set.
	DeleteSession(ctx context.Context, tokenHash string, userID uuid.UUID) error

	// DeleteAllUserSessions removes all cached sessions for a user.
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error

	// CheckHealth returns nil if Redis is reachable, non-nil otherwise.
	CheckHealth(ctx context.Context) error
}

// Store defines database operations needed by auth handlers.
// Satisfied by *store.PostgresStore — defined here (at consumer) per Go convention.
type Store interface {
	// CreateUserByEmail inserts new user with email and hashed password.
	CreateUserByEmail(ctx context.Context, uuid uuid.UUID, email, passwordHash string) error

	// GetUserByEmail fetches user by email for login verification.
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)

	// GetPwdHashByUserID fetches Argon2id hash for password verification.
	GetPwdHashByUserID(ctx context.Context, id uuid.UUID) (string, error)

	// UpdateUserPassword attempts to update the password of user attached to given id.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// CreateSession inserts new session row with token hash and CSRF token.
	CreateSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error

	// GetSessionByTokenHash fetches valid (non-expired) session by token hash.
	// Returns pgx.ErrNoRows if not found or expired.
	GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*store.Session, error)

	// DeleteSession removes single session row by token hash.
	DeleteSession(ctx context.Context, tokenHash []byte) error

	// DeleteAllUserSessions removes all sessions for a user.
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error

	// CreateToken inserts a new single-use verification token for the user.
	CreateToken(ctx context.Context, id, userID uuid.UUID, tokenType string, tokenHash []byte, expiresAt time.Time) error

	// GetTokenByHash fetches a valid, unused, non-expired token by its SHA-256 hash.
	// Returns pgx.ErrNoRows if not found, already used, or expired.
	GetTokenByHash(ctx context.Context, tokenHash []byte, tokenType string) (*store.Token, error)

	// MarkTokenUsed sets used_at = NOW() for the token with the given hash.
	// Returns pgx.ErrNoRows if no matching unused token exists.
	MarkTokenUsed(ctx context.Context, tokenHash []byte) error

	// ConsumeToken fetches a valid, unused, non-expired token by its SHA-256 hash.
	// Returns user_id associated with token if valid token found, pgx.ErrNoRows if no token found.
	ConsumeToken(ctx context.Context, tokenHash []byte, tokenType string) (uuid.UUID, error)

	// SetEmailConfirmedAt sets email_confirmed_at = NOW() for userID if not already confirmed.
	SetEmailConfirmedAt(ctx context.Context, userID uuid.UUID) error

	// WriteAuditLog inserts a single audit event into audit_logs.
	// Non-fatal: callers log the error but never fail the request on audit write failure.
	WriteAuditLog(ctx context.Context, entry store.AuditEntry) error

	// GetUserByOAuthProvider fetches user by OAuth provider name and provider-specific user ID.
	// Returns pgx.ErrNoRows if no user exists with that provider identity.
	GetUserByOAuthProvider(ctx context.Context, provider, providerID string) (*store.User, error)

	// CreateOAuthUser inserts a new user authenticated via OAuth.
	// Sets email_confirmed_at automatically; no password_hash.
	// firstName, lastName, avatarURL are optional -- pass nil to leave them NULL.
	CreateOAuthUser(ctx context.Context, id uuid.UUID, email, provider, providerID string, firstName, lastName, avatarURL *string) error

	// LinkOAuthToUser sets oauth_provider and oauth_provider_id for a user with no provider linked.
	// Returns pgx.ErrNoRows if the user already has a provider linked.
	LinkOAuthToUser(ctx context.Context, userID uuid.UUID, provider, providerID string) error

	// SetOAuthProfile updates first_name, last_name, and avatar_url using COALESCE --
	// each column is only written if currently NULL, preserving any user-set values.
	SetOAuthProfile(ctx context.Context, userID uuid.UUID, firstName, lastName, avatarURL *string) error

	// CreateOAuthPendingLink stores a pending OAuth link token for later confirmation.
	// Caller supplies the SHA-256 hash of the raw token.
	CreateOAuthPendingLink(ctx context.Context, tokenHash []byte, userID uuid.UUID, provider, providerID string, givenName, familyName, picture *string, expiresAt time.Time) error

	// ConsumeOAuthPendingLink atomically deletes and returns a pending link by token hash.
	// Returns pgx.ErrNoRows if not found or expired.
	ConsumeOAuthPendingLink(ctx context.Context, tokenHash []byte) (*store.OAuthPendingLink, error)

	// CheckHealth returns nil if Postgres is reachable, non-nil otherwise.
	CheckHealth(ctx context.Context) error
}

// RateLimiter checks and records rate limit state for a given key and policy.
// Satisfied by *store.RedisRateLimiter -- defined here per Go convention.
type RateLimiter interface {
	// Allow checks whether the action is within policy, records the attempt.
	// Returns nil if allowed; non-nil error if locked out or threshold exceeded.
	Allow(ctx context.Context, key string, policy store.RateLimit) error
}

// CaptchaVerifier verifies a client-supplied CAPTCHA token.
// Satisfied by *captcha.TurnstileVerifier -- defined here per Go convention.
type CaptchaVerifier interface {
	// Verify checks the token against the CAPTCHA provider. Returns nil on success.
	Verify(ctx context.Context, token, remoteIP string) error
}

// RateLimitPolicies holds rate limit policies for all auth endpoints.
// Configured via RATE_* env vars with defaults set in config.go.
type RateLimitPolicies struct {
	RegisterEmail      store.RateLimit
	LoginEmail         store.RateLimit
	PasswordReset      store.RateLimit
	ResendVerification store.RateLimit
}

// CaptchaPolicies controls which endpoints require a verified CAPTCHA token.
// Each field maps to one handler; false means the check is skipped for that endpoint.
type CaptchaPolicies struct {
	Register             bool
	Login                bool
	PasswordResetRequest bool
	ResendVerification   bool
}

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS       Store
	RS       SessionCache
	RL       RateLimiter
	ML       mail.Mailer
	Policies RateLimitPolicies

	// CV is the CAPTCHA verifier. Nil disables all captcha checks.
	CV        CaptchaVerifier
	CaptchaCP CaptchaPolicies

	// RequireEmailVerification blocks login until email_confirmed_at is set.
	// Controlled by REQUIRE_EMAIL_VERIFICATION env var (default true).
	RequireEmailVerification bool

	// Session durations. Populated from config at startup.
	SessionTTL        time.Duration
	SessionRememberMe time.Duration

	// Policy defines password complexity rules for registration and password changes.
	Policy PasswordPolicy

	// OAuthProviders is a map of registered OAuth providers keyed by provider name (e.g. "google").
	// Nil or missing key disables that provider -- handlers return 404.
	OAuthProviders map[string]oauth.Provider

	// SMTPEnabled indicates whether SMTP is configured. When true, OAuth account linking
	// requires email confirmation instead of auto-linking.
	SMTPEnabled bool
}

// checkCaptcha verifies the captcha token when CV is set and required is true.
// Returns true to continue, false if verification failed (response already written).
func (h *AuthHandler) checkCaptcha(w http.ResponseWriter, r *http.Request, token string, required bool) bool {
	if h.CV == nil || !required {
		return true
	}
	if err := h.CV.Verify(r.Context(), token, r.RemoteAddr); err != nil {
		logWarn(r, "captcha verification failed", "error", err)
		BadRequest(w, r, "captcha verification failed")
		return false
	}
	return true
}
