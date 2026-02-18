// middleware.go -- HTTP middleware for the auth service.
//
// RequireAuth validates the session cookie on every protected request.
// Checks Redis first (fast path, ~0.1ms), falls back to Postgres on miss (~1-5ms).
// Injects user_id into request context for downstream handlers.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// contextKey is an unexported type for context keys in this package.
// Using a named type (not plain string) prevents collisions with other
// packages that may also store values on the same request context.
type contextKey string

const userIDKey contextKey = "user_id"
const tokenHashKey contextKey = "token_hash"

// UserIDFromContext retrieves the authenticated user's ID from the request context.
// Returns the zero UUID and false if not present (i.e. request didn't pass RequireAuth).
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// TokenHashFromContext retrieves the session token hash from the request context.
// Returns nil and false if not present (i.e. request didn't pass RequireAuth).
func TokenHashFromContext(ctx context.Context) ([]byte, bool) {
	hash, ok := ctx.Value(tokenHashKey).([32]byte)
	return hash[:], ok
}

// RequireAuth is middleware that enforces session authentication.
// Reads the __Host-session cookie, hashes the token, and validates
// the session against Redis (fast path) then Postgres (fallback).
// On success, injects the user_id into the request context and calls next.
// On failure, returns 401 with a generic error — no detail about why.
func (h *AuthHandler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the __Host-session cookie. Missing or empty → 401.
		sessCookie, err := r.Cookie("__Host-session")
		if err != nil {
			logWarn(r, "require auth failed", "reason", "missing_session_cookie")
			Unauthorized(w, r, "unauthorized")
			return
		}
		if sessCookie.Value == "" {
			logWarn(r, "require auth failed", "reason", "empty_session_cookie")
			Unauthorized(w, r, "unauthorized")
			return
		}
		// Decode the base64 cookie value back to raw bytes. Invalid encoding → 401.
		decoded, err := base64.RawURLEncoding.DecodeString(sessCookie.Value)
		if err != nil {
			logWarn(r, "require auth failed", "reason", "invalid_cookie_encoding")
			Unauthorized(w, r, "unauthorized")
			return
		}
		// SHA-256 hash the raw token to produce the Redis lookup key.
		tokenHash := sha256.Sum256(decoded)
		redisKey := base64.RawURLEncoding.EncodeToString(tokenHash[:])

		// Check Redis for the session (fast path, ~0.1ms).
		// On hit: session is implicitly valid — Redis TTL already expired any stale keys.
		var userID uuid.UUID
		sess, err := h.RS.GetSession(r.Context(), redisKey)
		if err != nil {
			// Redis miss — fall back to Postgres (~1-5ms).
			pgSess, err := h.PS.GetSessionByTokenHash(r.Context(), tokenHash[:])
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					// Session not found or expired — expected, not a server error.
					logWarn(r, "require auth failed", "reason", "session_not_found")
				} else {
					// Real database failure — unexpected, needs alerting.
					logError(r, "require auth failed fetching session from db", "error", err)
				}
				Unauthorized(w, r, "unauthorized")
				return
			}
			// Repopulate Redis so the next request hits the cache.
			// Non-fatal: a cache miss on the next request is acceptable.
			ttl := max(0, int(time.Until(pgSess.ExpiresAt).Seconds()))
			if err := h.RS.SetSession(r.Context(), redisKey, store.Session{
				ID:        pgSess.ID,
				UserID:    pgSess.UserID,
				TokenHash: pgSess.TokenHash,
				CSRFToken: pgSess.CSRFToken,
				ExpiresAt: pgSess.ExpiresAt,
			}, ttl); err != nil {
				logWarn(r, "failed to repopulate session cache", "error", err)
			}
			userID = pgSess.UserID
		} else {
			userID = sess.UserID
		}

		// Inject the authenticated user_id and token hash into the request context.
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, tokenHashKey, tokenHash)

		// All good — pass the enriched context to the next handler.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
