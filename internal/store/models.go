// models.go -- Shared domain types for the store package.
// Used by both Postgres (durable store) and Redis (cache layer).
package store

import (
	"time"

	"github.com/gofrs/uuid/v5"
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

// Session represents a row in the sessions table.
// Nullable columns are pointers — nil means SQL NULL.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
}
