// csrf.go -- CSRF token generation and validation.
//
// Generates a per-session CSRF token (crypto/rand).
// Validates on all state-changing requests (POST, PUT, DELETE).
// SameSite=Lax handles most cases; CSRF tokens cover the rest.
package auth

import (
	"crypto/rand"
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
func ValidateCSRFToken(provided, stored [32]byte) bool

// CSRFMiddleware enforces CSRF protection on state-changing requests
// (POST, PUT, DELETE). Reads the token from the X-CSRF-Token header,
// validates it against the session's stored token, and rejects mismatches with 403.
func CSRFMiddleware(next http.Handler) http.Handler
