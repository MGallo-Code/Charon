// csrf.go -- CSRF token generation and validation.
//
// Generates a per-session CSRF token (crypto/rand).
// Validates on all state-changing requests (POST, PUT, DELETE).
// SameSite=Lax handles most cases; CSRF tokens cover the rest.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
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
// validates it against session's stored token, and rejects mismatches with 403.
func (h *AuthHandler) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce on state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// Decode client CSRF token from header
			reqCSRFToken, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-CSRF-Token"))
			// Invalid or missing CSRF token
			if err != nil || len(reqCSRFToken) != 32 {
				logWarn(r, "csrf validation failed", "reason", "invalid_token_format")
				csrfForbidden(w)
				return
			}
			// Get session cookie
			sessCookie, err := r.Cookie("__Host-session")
			if err != nil || sessCookie.Value == "" {
				logWarn(r, "csrf validation failed", "reason", "missing_session_cookie")
				csrfForbidden(w)
				return
			}
			// Decode cookie value back to raw bytes, hash it, hex-encode for Redis key
			rawToken, err := base64.RawURLEncoding.DecodeString(sessCookie.Value)
			if err != nil {
				logWarn(r, "csrf validation failed", "reason", "invalid_cookie_encoding")
				csrfForbidden(w)
				return
			}
			// Hash token to match Redis session storage
			tokenHash := sha256.Sum256(rawToken)
			session, err := h.RS.GetSession(r.Context(), base64.RawURLEncoding.EncodeToString(tokenHash[:]))
			// Couldn't find session with hashed token
			if err != nil {
				logWarn(r, "csrf validation failed", "reason", "session_not_found")
				csrfForbidden(w)
				return
			}
			// Compare tokens in constant time
			if len(session.CSRFToken) != 32 ||
				!ValidateCSRFToken([32]byte(reqCSRFToken), [32]byte(session.CSRFToken)) {
				logWarn(r, "csrf validation failed", "reason", "token_mismatch")
				csrfForbidden(w)
				return
			}
		}
		// Next middleware, passed token check!!
		next.ServeHTTP(w, r)
	})
}
