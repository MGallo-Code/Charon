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
	"fmt"
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
