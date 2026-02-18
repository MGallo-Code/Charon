// csrf.go -- CSRF token generation and validation.
//
// Generates a per-session CSRF token (crypto/rand).
// Validates on all state-changing requests (POST, PUT, DELETE).
// SameSite=Lax handles most cases; CSRF tokens cover the rest.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
)

// GenerateCSRFToken creates a 256-bit cryptographically random CSRF token
// and returns a pointer to the raw token for storage and client delivery.
func GenerateCSRFToken() (*[32]byte, error) {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		return nil, fmt.Errorf("generating token with rand: %w", err)
	}
	return &token, nil
}

// ValidateCSRFToken compares a raw CSRF token from the request against
// the stored token using constant-time comparison to prevent timing attacks.
func ValidateCSRFToken(provided, stored [32]byte) bool {
	return subtle.ConstantTimeCompare(provided[:], stored[:]) == 1
}

// csrfForbidden writes a generic 403 JSON response for CSRF failures.
// Intentionally vague to avoid leaking validation stage.
func csrfForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"forbidden"}`))
}

// CSRFMiddleware enforces CSRF protection on state-changing requests
// (POST, PUT, DELETE, PATCH). Reads token from X-CSRF-Token header,
// validates it against the CSRF token injected by RequireAuth, and rejects mismatches with 403.
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
			// Read the session's CSRF token injected by RequireAuth — no extra DB/Redis lookup.
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
