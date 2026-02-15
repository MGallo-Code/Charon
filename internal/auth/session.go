// session.go -- Session token generation, validation, and destruction.
//
// Tokens: 256-bit cryptographically random (crypto/rand).
// Storage: tokens are SHA-256 hashed before storing (never store plaintext).
// Validation: check Redis first (fast path), fall back to Postgres.
// Cookies: HttpOnly, Secure, SameSite=Lax, __Host-session prefix.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// GenerateToken creates a 256-bit cryptographically random session token
// and returns both the raw token (for the cookie) and its SHA-256 hash (for storage).
func GenerateToken() (*[32]byte, *[32]byte, error) {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		return nil, nil, fmt.Errorf("generating token with rand: %w", err)
	}
	hash := sha256.Sum256(token[:])
	return &token, &hash, nil
}

// SetSessionCookie writes a __Host-session cookie to the response with the raw token.
// Uses HttpOnly, Secure, SameSite=Lax, Path=/ (required by __Host- prefix).
func SetSessionCookie(w http.ResponseWriter, rawToken [32]byte, expiresAt time.Time) {
	// Convert vars and set cookie ( *  v  * )
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-session",
		Value:    base64.RawURLEncoding.EncodeToString(rawToken[:]),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}
