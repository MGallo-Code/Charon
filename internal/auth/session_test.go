package auth

import (
	"crypto/sha256"
	"testing"
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
