// csrf.go

// CSRF token generation and validation.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
)

// GenerateCSRFToken returns 256-bit cryptographically random CSRF token.
func GenerateCSRFToken() (*[32]byte, error) {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		return nil, fmt.Errorf("generating token with rand: %w", err)
	}
	return &token, nil
}

// ValidateCSRFToken compares provided and stored tokens using constant-time comparison.
func ValidateCSRFToken(provided, stored [32]byte) bool {
	return subtle.ConstantTimeCompare(provided[:], stored[:]) == 1
}

// csrfForbidden writes generic 403 JSON, intentionally vague to avoid leaking validation stage.
func csrfForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"forbidden"}`))
}

// CSRFMiddleware enforces CSRF protection on state-changing requests (POST, PUT, DELETE, PATCH).
// Reads token from X-CSRF-Token header, validates against token injected by RequireAuth.
// Must run after RequireAuth in the middleware chain.
func (h *AuthHandler) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce on state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// Decode client CSRF token from X-CSRF-Token header
			reqCSRFToken, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-CSRF-Token"))
			if err != nil || len(reqCSRFToken) != 32 {
				logWarn(r, "csrf validation failed", "reason", "invalid_token_format")
				csrfForbidden(w)
				return
			}

			// Read token injected by RequireAuth, no extra DB/Redis lookup.
			storedCSRFToken, ok := CSRFTokenFromContext(r.Context())
			if !ok || len(storedCSRFToken) != 32 {
				logWarn(r, "csrf validation failed", "reason", "missing_csrf_context")
				csrfForbidden(w)
				return
			}
			// Constant-time comparison to prevent timing attacks
			if !ValidateCSRFToken([32]byte(reqCSRFToken), [32]byte(storedCSRFToken)) {
				logWarn(r, "csrf validation failed", "reason", "token_mismatch")
				csrfForbidden(w)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}