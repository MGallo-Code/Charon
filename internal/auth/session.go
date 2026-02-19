// session.go

// Session token generation and cookie management.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// GenerateToken returns 256-bit random session token and its SHA-256 hash.
// Token goes in the cookie; hash goes in storage.
func GenerateToken() (*[32]byte, *[32]byte, error) {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		return nil, nil, fmt.Errorf("generating token with rand: %w", err)
	}
	hash := sha256.Sum256(token[:])
	return &token, &hash, nil
}

// SetSessionCookie writes __Host-session cookie with HttpOnly, Secure, SameSite=Lax.
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

// ClearSessionCookie overwrites __Host-session with MaxAge=-1 to trigger browser deletion.
func ClearSessionCookie(w http.ResponseWriter) {
	// Essentially just nulling out cookie by setting new expired vals
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}