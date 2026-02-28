// models.go -- Shared domain types for the store package.
// Used by both Postgres (durable store) and Redis (cache layer).
package store

import (
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

// ErrRateLimitExceeded is returned by Allow when the caller is locked out.
// Callers use errors.Is to distinguish rate limit rejections from Redis failures.
var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// ErrNoPassword is returned by GetPwdHashByUserID when the user exists but has no password_hash.
// This occurs for OAuth-only users.
var ErrNoPassword = errors.New("user has no password")

// ErrCacheMiss is returned by GetSession when the key is not in Redis.
// Callers use errors.Is to distinguish a true miss from a Redis infrastructure failure.
var ErrCacheMiss = errors.New("cache miss")

// ErrCacheDisabled is returned by NoopSessionCache.CheckHealth when Redis is not configured.
// Callers use errors.Is to distinguish "not configured" from a real infrastructure failure.
var ErrCacheDisabled = errors.New("cache disabled")

// ErrSessionTombstoned is returned by GetSession when the session key holds a
// tombstone -- session was recently deleted and must not be repopulated.
var ErrSessionTombstoned = errors.New("session tombstoned")

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
	PasswordHash     *string
	OAuthProvider    *string
	OAuthProviderID  *string
	AvatarURL        *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Session represents a row in the sessions table.
// Nullable columns are pointers — nil means SQL NULL.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	CSRFToken []byte
	ExpiresAt time.Time
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
}

// CachedSession is the JSON shape stored in Redis for cached sessions.
// Only the fields needed for fast session validation — full metadata lives in Postgres.
type CachedSession struct {
	UserID    uuid.UUID `json:"user_id"`
	CSRFToken []byte    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RateLimit defines the policy for a rate-limited action.
// All three fields required, zero values disable the respective behaviour.
type RateLimit struct {
	MaxAttempts int           // attempts allowed within Window before lockout
	Window      time.Duration // rolling window for attempt counting
	LockoutTTL  time.Duration // how long to block after MaxAttempts is hit
}

// AuditEntry represents a row in the audit_logs table.
// UserID is nil for pre-auth failures where no user is identified.
// IPAddress and UserAgent are nil for server-side or admin-triggered events.
// Metadata holds optional event context as a raw JSON blob (e.g. session_id, token_type).
type AuditEntry struct {
	UserID    *uuid.UUID
	Action    string
	IPAddress *string
	UserAgent *string
	Metadata  []byte
}

// OAuthPendingLink holds OAuth identity data for a pending account-link confirmation.
// Created when an OAuth email matches an existing password account; consumed after the owner confirms.
type OAuthPendingLink struct {
	UserID     uuid.UUID
	Provider   string
	ProviderID string
	GivenName  *string
	FamilyName *string
	Picture    *string
	ExpiresAt  time.Time
}

// Token represents a row in the tokens table.
// TokenType is constrained by DB CHECK ('password_reset', 'email_verification').
// UsedAt is nil until consumed; set once on use to prevent replay.
type Token struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenType string
	TokenHash []byte
	UsedAt    *time.Time
	ExpiresAt time.Time
	CreatedAt time.Time
}
