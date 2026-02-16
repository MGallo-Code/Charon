// Package auth contains HTTP handlers and core authentication logic.
//
// handler.go -- HTTP handlers for all /auth/* endpoints.
// Registers routes on a chi router, returns JSON responses.
// Delegates to session, password, and csrf packages for logic.
package auth

import (
	"context"

	"github.com/MGallo-Code/charon/internal/store"
)

// SessionCache defines session cache operations needed by auth handlers.
// Satisfied by *store.RedisStore — defined here (at consumer) per Go convention.
type SessionCache interface {
	GetSession(ctx context.Context, tokenHash string) (*store.CachedSession, error)
}

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS *store.PostgresStore
	RS SessionCache
}
