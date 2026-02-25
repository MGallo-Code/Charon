// password_test.go

// unit tests for HashPassword, VerifyPassword, ValidatePassword, and PasswordPolicy.Validate.
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

// --- PasswordPolicy.Validate ---

func TestPasswordPolicyValidate(t *testing.T) {
	tests := []struct {
		name     string
		policy   PasswordPolicy
		input    string
		wantMsgs []string // nil means expect nil return (valid password)
	}{
		// Zero value policy: all fields false/zero -- any password passes.
		{
			name:     "zero value policy accepts anything",
			policy:   PasswordPolicy{},
			input:    "",
			wantMsgs: nil,
		},
		{
			name:     "zero value policy accepts single char",
			policy:   PasswordPolicy{},
			input:    "x",
			wantMsgs: nil,
		},

		// MinLength: too short fails, exact length passes, longer passes.
		{
			name:     "MinLength fails when password too short",
			policy:   PasswordPolicy{MinLength: 8},
			input:    "abc",
			wantMsgs: []string{"password must be at least 8 characters"},
		},
		{
			name:     "MinLength passes at exact length",
			policy:   PasswordPolicy{MinLength: 8},
			input:    "abcdefgh", // exactly 8 runes
			wantMsgs: nil,
		},
		{
			name:     "MinLength passes when longer than minimum",
			policy:   PasswordPolicy{MinLength: 8},
			input:    "abcdefghi",
			wantMsgs: nil,
		},

		// MaxLength: too long (by rune count) fails; exact rune count passes.
		{
			name:     "MaxLength fails when password too long",
			policy:   PasswordPolicy{MaxLength: 10},
			input:    "12345678901", // 11 runes
			wantMsgs: []string{"password must be at most 10 characters"},
		},
		{
			name:     "MaxLength passes at exact rune count",
			policy:   PasswordPolicy{MaxLength: 10},
			input:    "1234567890", // exactly 10 runes
			wantMsgs: nil,
		},
		// Multi-byte: rune count < MaxLength even though byte count > MaxLength.
		// "é" is 2 bytes in UTF-8; 6 × "é" = 12 bytes, rune count = 6.
		// With MaxLength: 10, this should PASS (6 runes <= 10).
		{
			name:     "MaxLength uses rune count not byte count",
			policy:   PasswordPolicy{MaxLength: 10},
			input:    "éééééé", // 6 runes, 12 bytes -- passes because rune count <= MaxLength
			wantMsgs: nil,
		},

		// RequireUppercase.
		{
			name:     "RequireUppercase fails when no uppercase present",
			policy:   PasswordPolicy{RequireUppercase: true},
			input:    "alllowercase",
			wantMsgs: []string{"password must contain at least one uppercase letter"},
		},
		{
			name:     "RequireUppercase passes when uppercase present",
			policy:   PasswordPolicy{RequireUppercase: true},
			input:    "hasUpperA",
			wantMsgs: nil,
		},

		// RequireDigit.
		{
			name:     "RequireDigit fails when no digit present",
			policy:   PasswordPolicy{RequireDigit: true},
			input:    "nodigitshere",
			wantMsgs: []string{"password must contain at least one digit"},
		},
		{
			name:     "RequireDigit passes when digit present",
			policy:   PasswordPolicy{RequireDigit: true},
			input:    "hasdigit1",
			wantMsgs: nil,
		},

		// RequireSpecial.
		{
			name:     "RequireSpecial fails when no special char present",
			policy:   PasswordPolicy{RequireSpecial: true},
			input:    "nospecialchars1A",
			wantMsgs: []string{"password must contain at least one special character"},
		},
		{
			name:     "RequireSpecial passes with exclamation mark",
			policy:   PasswordPolicy{RequireSpecial: true},
			input:    "hasSpecial!",
			wantMsgs: nil,
		},
		{
			name:     "RequireSpecial passes with at sign",
			policy:   PasswordPolicy{RequireSpecial: true},
			input:    "hasSpecial@",
			wantMsgs: nil,
		},
		{
			name:     "RequireSpecial passes with underscore",
			policy:   PasswordPolicy{RequireSpecial: true},
			input:    "has_underscore",
			wantMsgs: nil,
		},

		// Multiple rules: all failures collected, not just first.
		{
			name: "all three char rules fail together",
			policy: PasswordPolicy{
				RequireUppercase: true,
				RequireDigit:     true,
				RequireSpecial:   true,
			},
			input: "alllowercase", // no upper, no digit, no special
			wantMsgs: []string{
				"password must contain at least one uppercase letter",
				"password must contain at least one digit",
				"password must contain at least one special character",
			},
		},
		{
			name: "length plus char rule both fail",
			policy: PasswordPolicy{
				MinLength:    10,
				RequireDigit: true,
			},
			input: "short", // too short and no digit
			wantMsgs: []string{
				"password must be at least 10 characters",
				"password must contain at least one digit",
			},
		},

		// Control characters: always rejected regardless of policy.
		{
			name:     "control character rejected",
			policy:   PasswordPolicy{},
			input:    "valid\x00password",
			wantMsgs: []string{"password contains invalid characters"},
		},
		{
			name:     "tab character rejected",
			policy:   PasswordPolicy{},
			input:    "valid\tpassword",
			wantMsgs: []string{"password contains invalid characters"},
		},

		// Unicode: MinLength counts runes, not bytes.
		// "日本語" is 3 runes but 9 bytes. MinLength=3 should pass.
		{
			name:     "MinLength counts runes not bytes for unicode input",
			policy:   PasswordPolicy{MinLength: 3},
			input:    "日本語", // 3 runes, 9 bytes
			wantMsgs: nil,
		},
		// 2 runes should fail MinLength=3.
		{
			name:     "MinLength fails when unicode rune count is below minimum",
			policy:   PasswordPolicy{MinLength: 3},
			input:    "日本", // 2 runes, 6 bytes
			wantMsgs: []string{"password must be at least 3 characters"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.Validate(tc.input)

			if tc.wantMsgs == nil {
				// Valid password: return must be nil, not just empty.
				if got != nil {
					t.Errorf("Validate(%q): expected nil, got %v", tc.input, got)
				}
				return
			}

			// Invalid password: check each expected message is present.
			if len(got) != len(tc.wantMsgs) {
				t.Errorf("Validate(%q): expected %d failure(s) %v, got %d: %v",
					tc.input, len(tc.wantMsgs), tc.wantMsgs, len(got), got)
				return
			}
			for i, want := range tc.wantMsgs {
				if got[i] != want {
					t.Errorf("Validate(%q) failure[%d]: expected %q, got %q",
						tc.input, i, want, got[i])
				}
			}
		})
	}
}

// TestPasswordPolicyValidateReturnsNilNotEmpty verifies the nil-not-empty contract
// explicitly, since len(nil) == len([]string{}) and a naive test could miss it.
func TestPasswordPolicyValidateReturnsNilNotEmpty(t *testing.T) {
	p := PasswordPolicy{MinLength: 4}
	result := p.Validate("abcde") // longer than MinLength, all other rules off
	if result != nil {
		t.Errorf("expected nil on valid password, got %v (type: %T)", result, result)
	}
}
