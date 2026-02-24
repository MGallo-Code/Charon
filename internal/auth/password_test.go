// password_test.go

// unit tests for HashPassword, VerifyPassword, and ValidatePassword.
package auth

import (
	"strings"
	"testing"
)

// --- HashPassword ---

func TestHashPassword(t *testing.T) {
	t.Run("output matches PHC format", func(t *testing.T) {
		hash, err := HashPassword("correcthorsebatterystaple")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}

		// PHC format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
		// Make sure string splits into 6 parts
		parts := strings.Split(hash, "$")
		if len(parts) != 6 {
			t.Fatalf("expected 6 parts, got %d: %q", len(parts), hash)
		}
		// Validate var values
		if parts[1] != "argon2id" {
			t.Errorf("algorithm: expected argon2id, got %q", parts[1])
		}
		if parts[2] != "v=19" {
			t.Errorf("version: expected v=19, got %q", parts[2])
		}
		if parts[3] != "m=65536,t=3,p=2" {
			t.Errorf("params: expected m=65536,t=3,p=2, got %q", parts[3])
		}
	})

	// Make sure same password returns diff hashes w/ salts
	t.Run("unique salts per call", func(t *testing.T) {
		h1, err := HashPassword("same-password")
		if err != nil {
			t.Fatalf("first hash: %v", err)
		}
		h2, err := HashPassword("same-password")
		if err != nil {
			t.Fatalf("second hash: %v", err)
		}
		if h1 == h2 {
			t.Error("two hashes of the same password should differ (unique salts)")
		}
	})
}

// --- VerifyPassword ---

func TestVerifyPassword(t *testing.T) {
	t.Run("correct password verifies", func(t *testing.T) {
		password := "correcthorsebatterystaple"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}

		match, err := VerifyPassword(password, hash)
		if err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
		if !match {
			t.Error("correct password should verify")
		}
	})

	t.Run("wrong password rejected", func(t *testing.T) {
		hash, err := HashPassword("real-password")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}

		match, err := VerifyPassword("wrong-password", hash)
		if err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
		if match {
			t.Error("wrong password should not verify")
		}
	})

	// Make sure invalid hash returns error
	t.Run("invalid hash format", func(t *testing.T) {
		_, err := VerifyPassword("password", "not-a-valid-hash")
		if err == nil {
			t.Error("expected error for invalid hash format")
		}
	})

	// Make sure invalid alg returns error
	t.Run("unsupported algorithm", func(t *testing.T) {
		bad := "$bcrypt$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZWhhc2g"
		_, err := VerifyPassword("password", bad)
		if err == nil {
			t.Error("expected error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "unsupported algorithm") {
			t.Errorf("expected 'unsupported algorithm' in error, got: %v", err)
		}
	})

	// Make sure invalid salts return err
	t.Run("invalid base64 salt", func(t *testing.T) {
		bad := "$argon2id$v=19$m=65536,t=3,p=2$!!!invalid!!!$c29tZWhhc2g"
		_, err := VerifyPassword("password", bad)
		if err == nil {
			t.Error("expected error for invalid base64 salt")
		}
	})

	// Make sure invalid base64 hash returns error...
	t.Run("invalid base64 hash", func(t *testing.T) {
		bad := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$!!!invalid!!!"
		_, err := VerifyPassword("password", bad)
		if err == nil {
			t.Error("expected error for invalid base64 hash")
		}
	})
}

// --- ValidatePassword ---

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMsg string
	}{
		{"empty string", "", "No password provided!"},
		{"one under minimum", "seven77", "Password too short!"},
		{"exactly minimum", "eightchr", ""},
		{"exactly maximum", strings.Repeat("a", 128), ""},
		{"one over maximum", strings.Repeat("a", 129), "Password too long!"},
		{"valid password", "correcthorsebatterystaple*", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidatePassword(tc.input)
			if got != tc.wantMsg {
				t.Errorf("ValidatePassword(%q): expected %q, got %q", tc.input, tc.wantMsg, got)
			}
		})
	}
}
