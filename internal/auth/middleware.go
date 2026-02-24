// middleware.go

// Session authentication middleware.
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

// contextKey is unexported to prevent collisions with other packages using the same context.
type contextKey string

const userIDKey contextKey = "user_id"
const tokenHashKey contextKey = "token_hash"
const csrfTokenKey contextKey = "csrf_token"

// UserIDFromContext retrieves authenticated user's ID from context.
// Returns zero UUID and false if RequireAuth hasn't run.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// TokenHashFromContext retrieves session token hash from context.
// Returns nil and false if RequireAuth hasn't run.
func TokenHashFromContext(ctx context.Context) ([]byte, bool) {
	hash, ok := ctx.Value(tokenHashKey).([]byte)
	return hash, ok
}

// CSRFTokenFromContext retrieves session CSRF token from context.
// Returns nil and false if RequireAuth hasn't run.
func CSRFTokenFromContext(ctx context.Context) ([]byte, bool) {
	token, ok := ctx.Value(csrfTokenKey).([]byte)
	return token, ok
}

// RequireAuth validates the session cookie, checking Redis then Postgres as fallback.
// Injects user_id, token_hash, and csrf_token into context on success; returns 401 on failure.
func (h *AuthHandler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the __Host-session cookie. If missing or empty, 401 ERR
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

		// Redis fast path, TTL expiry already handles stale keys.
		var userID uuid.UUID
		var csrfToken []byte
		sess, err := h.RS.GetSession(r.Context(), redisKey)
		if err != nil {
			if !errors.Is(err, store.ErrCacheMiss) {
				// Real Redis failure -- log it; Postgres is the fallback but this warrants attention.
				logError(r, "redis session lookup failed, falling back to postgres", "error", err)
			}
			// Miss or infra failure -- fall back to Postgres.
			pgSess, err := h.PS.GetSessionByTokenHash(r.Context(), tokenHash[:])
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					logWarn(r, "require auth failed", "reason", "session_not_found")
				} else {
					logError(r, "require auth failed fetching session from db", "error", err)
				}
				Unauthorized(w, r, "unauthorized")
				return
			}
			// Repopulate cache, non-fatal on failure.
			// Skip if TTL <= 0 -- Redis SET with TTL=0 means no expiry, not immediate expiry.
			ttl := max(0, int(time.Until(pgSess.ExpiresAt).Seconds()))
			if ttl > 0 {
				if err := h.RS.SetSession(r.Context(), redisKey, store.Session{
					ID:        pgSess.ID,
					UserID:    pgSess.UserID,
					TokenHash: pgSess.TokenHash,
					CSRFToken: pgSess.CSRFToken,
					ExpiresAt: pgSess.ExpiresAt,
				}, ttl); err != nil {
					logWarn(r, "failed to repopulate session cache", "error", err)
				}
			}
			userID = pgSess.UserID
			csrfToken = pgSess.CSRFToken
		} else {
			userID = sess.UserID
			csrfToken = sess.CSRFToken
		}

		// Inject user_id, tokenHash, csrfToken into context for downstream handlers.
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, tokenHashKey, tokenHash[:])
		ctx = context.WithValue(ctx, csrfTokenKey, csrfToken)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}