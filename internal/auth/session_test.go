package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- GenerateToken ---

func TestGenerateToken(t *testing.T) {
	t.Run("returns token and hash without error", func(t *testing.T) {
		token, hash, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken returned error: %v", err)
		}
		if token == nil {
			t.Fatal("token should not be nil")
		}
		if hash == nil {
			t.Fatal("hash should not be nil")
		}
	})

	t.Run("hash matches SHA-256 of token", func(t *testing.T) {
		token, hash, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken returned error: %v", err)
		}

		expected := sha256.Sum256(token[:])
		if *hash != expected {
			t.Error("hash does not match SHA-256 of token")
		}
	})
}

// --- SetSessionCookie ---

func TestSetSessionCookie(t *testing.T) {
	t.Run("sets cookie with correct security fields", func(t *testing.T) {
		w := httptest.NewRecorder()
		var token [32]byte
		token[0] = 0xAA // non-zero so we can spot it
		expiresAt := time.Now().Add(24 * time.Hour)

		SetSessionCookie(w, token, expiresAt)

		// Extract cookie from recorded response
		resp := w.Result()
		cookies := resp.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}
		c := cookies[0]

		if c.Name != "__Host-session" {
			t.Errorf("name: expected __Host-session, got %q", c.Name)
		}
		if c.Path != "/" {
			t.Errorf("path: expected /, got %q", c.Path)
		}
		if !c.HttpOnly {
			t.Error("HttpOnly should be true")
		}
		if !c.Secure {
			t.Error("Secure should be true")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite: expected Lax, got %v", c.SameSite)
		}
		if c.MaxAge <= 0 {
			t.Errorf("MaxAge should be positive, got %d", c.MaxAge)
		}
	})

	t.Run("cookie value round-trips to original token", func(t *testing.T) {
		w := httptest.NewRecorder()
		var token [32]byte
		for i := range token {
			token[i] = byte(i)
		}
		expiresAt := time.Now().Add(1 * time.Hour)

		SetSessionCookie(w, token, expiresAt)

		c := w.Result().Cookies()[0]
		decoded, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil {
			t.Fatalf("decoding cookie value: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("decoded length: expected 32, got %d", len(decoded))
		}

		var got [32]byte
		copy(got[:], decoded)
		if got != token {
			t.Error("decoded cookie value does not match original token")
		}
	})
}
