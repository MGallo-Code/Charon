// queue_test.go
//
// Unit tests for QueuedMailer dispatch logic.
// Integration tests (enqueue + StartWorker against real Redis) are covered by e2e_test.go.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// mockInner records the most recent call for assertion.
type mockInner struct {
	lastType    string
	lastToEmail string
	lastToken   string
	lastExpiry  time.Duration
	lastVars    map[string]string
	err         error
}

func (m *mockInner) SendPasswordReset(_ context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	m.lastType = jobPasswordReset
	m.lastToEmail = toEmail
	m.lastToken = token
	m.lastExpiry = expiresIn
	m.lastVars = vars
	return m.err
}

func (m *mockInner) SendEmailVerification(_ context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	m.lastType = jobEmailVerification
	m.lastToEmail = toEmail
	m.lastToken = token
	m.lastExpiry = expiresIn
	m.lastVars = vars
	return m.err
}

func (m *mockInner) SendOAuthLinkConfirmation(_ context.Context, _, _ string, _ time.Duration, _ map[string]string) error {
	return m.err
}

func TestQueuedMailer_Dispatch_PasswordReset(t *testing.T) {
	inner := &mockInner{}
	q := &QueuedMailer{inner: inner}

	job := EmailJob{
		Type:      jobPasswordReset,
		ToEmail:   "reset@example.com",
		Token:     "tok-reset",
		ExpiresIn: int64(time.Hour),
		Vars:      map[string]string{"firstName": "Alice"},
	}
	q.dispatch(context.Background(), job)

	if inner.lastType != jobPasswordReset {
		t.Errorf("type: got %q, want %q", inner.lastType, jobPasswordReset)
	}
	if inner.lastToEmail != "reset@example.com" {
		t.Errorf("toEmail: got %q, want %q", inner.lastToEmail, "reset@example.com")
	}
	if inner.lastToken != "tok-reset" {
		t.Errorf("token: got %q, want %q", inner.lastToken, "tok-reset")
	}
	if inner.lastExpiry != time.Hour {
		t.Errorf("expiry: got %v, want %v", inner.lastExpiry, time.Hour)
	}
	if inner.lastVars["firstName"] != "Alice" {
		t.Errorf("vars[firstName]: got %q, want %q", inner.lastVars["firstName"], "Alice")
	}
}

func TestQueuedMailer_Dispatch_EmailVerification(t *testing.T) {
	inner := &mockInner{}
	q := &QueuedMailer{inner: inner}

	job := EmailJob{
		Type:      jobEmailVerification,
		ToEmail:   "verify@example.com",
		Token:     "tok-verify",
		ExpiresIn: int64(24 * time.Hour),
		Vars:      map[string]string{"firstName": "Bob"},
	}
	q.dispatch(context.Background(), job)

	if inner.lastType != jobEmailVerification {
		t.Errorf("type: got %q, want %q", inner.lastType, jobEmailVerification)
	}
	if inner.lastToEmail != "verify@example.com" {
		t.Errorf("toEmail: got %q, want %q", inner.lastToEmail, "verify@example.com")
	}
	if inner.lastToken != "tok-verify" {
		t.Errorf("token: got %q, want %q", inner.lastToken, "tok-verify")
	}
	if inner.lastExpiry != 24*time.Hour {
		t.Errorf("expiry: got %v, want %v", inner.lastExpiry, 24*time.Hour)
	}
}

func TestQueuedMailer_Dispatch_UnknownType(t *testing.T) {
	inner := &mockInner{}
	q := &QueuedMailer{inner: inner}

	// Should not panic or call inner; just log and return.
	q.dispatch(context.Background(), EmailJob{Type: "bogus_type"})

	if inner.lastType != "" {
		t.Error("dispatch should not call inner for unknown job type")
	}
}

func TestQueuedMailer_Dispatch_SendError_DoesNotPanic(t *testing.T) {
	inner := &mockInner{err: errors.New("smtp timeout")}
	q := &QueuedMailer{inner: inner}

	// dispatch logs the error and returns -- must not panic or propagate.
	q.dispatch(context.Background(), EmailJob{
		Type:    jobPasswordReset,
		ToEmail: "err@example.com",
		Token:   "tok",
	})
}

func TestErrQueueFull_Sentinel(t *testing.T) {
	// Verify ErrQueueFull can be identified with errors.Is after wrapping.
	wrapped := fmt.Errorf("outer: %w", ErrQueueFull)
	if !errors.Is(wrapped, ErrQueueFull) {
		t.Error("errors.Is: wrapped ErrQueueFull not detected")
	}
}

// testEncKey is a 32-byte AES-256 key for use in tests only.
var testEncKey = []byte("test-key-32-bytes-long-for-aes!!")

func TestEncryptDecryptToken(t *testing.T) {
	t.Run("round-trip returns original plaintext", func(t *testing.T) {
		plaintext := []byte("tok_abc123_reset_token_value")

		encrypted, err := encryptToken(testEncKey, plaintext)
		if err != nil {
			t.Fatalf("encryptToken: %v", err)
		}
		decrypted, err := decryptToken(testEncKey, encrypted)
		if err != nil {
			t.Fatalf("decryptToken: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("different calls produce different ciphertexts", func(t *testing.T) {
		plaintext := []byte("same-token-value")

		enc1, err := encryptToken(testEncKey, plaintext)
		if err != nil {
			t.Fatalf("encryptToken first call: %v", err)
		}
		enc2, err := encryptToken(testEncKey, plaintext)
		if err != nil {
			t.Fatalf("encryptToken second call: %v", err)
		}
		// Nonce randomness means the two ciphertexts must differ.
		if string(enc1) == string(enc2) {
			t.Error("two encryptions of the same plaintext produced identical ciphertexts; nonce randomness broken")
		}
	})

	t.Run("tampered ciphertext returns error", func(t *testing.T) {
		plaintext := []byte("tok_sensitive_value")

		encrypted, err := encryptToken(testEncKey, plaintext)
		if err != nil {
			t.Fatalf("encryptToken: %v", err)
		}
		// Flip a byte in the ciphertext portion (after the 12-byte nonce).
		tampered := make([]byte, len(encrypted))
		copy(tampered, encrypted)
		tampered[12] ^= 0xFF

		_, err = decryptToken(testEncKey, tampered)
		if err == nil {
			t.Error("expected error decrypting tampered ciphertext, got nil")
		}
	})

	t.Run("ciphertext shorter than nonce returns error", func(t *testing.T) {
		_, err := decryptToken(testEncKey, []byte("short"))
		if err == nil {
			t.Error("expected error for too-short ciphertext, got nil")
		}
	})

	t.Run("wrong key returns error", func(t *testing.T) {
		plaintext := []byte("tok_value")
		wrongKey := []byte("wrong-key-32-bytes-long-for-aes!")

		encrypted, err := encryptToken(testEncKey, plaintext)
		if err != nil {
			t.Fatalf("encryptToken: %v", err)
		}
		_, err = decryptToken(wrongKey, encrypted)
		if err == nil {
			t.Error("expected error when decrypting with wrong key, got nil")
		}
	})
}

func TestEmailJob_JSONRoundTrip(t *testing.T) {
	original := EmailJob{
		Type:      jobPasswordReset,
		ToEmail:   "round@example.com",
		Token:     "tok-round",
		ExpiresIn: int64(2 * time.Hour),
		Vars:      map[string]string{"firstName": "Carol", "lastName": "Smith"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailJob
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("Type: got %q, want %q", decoded.Type, original.Type)
	}
	if decoded.ToEmail != original.ToEmail {
		t.Errorf("ToEmail: got %q, want %q", decoded.ToEmail, original.ToEmail)
	}
	if decoded.Token != original.Token {
		t.Errorf("Token: got %q, want %q", decoded.Token, original.Token)
	}
	if decoded.ExpiresIn != original.ExpiresIn {
		t.Errorf("ExpiresIn: got %d, want %d", decoded.ExpiresIn, original.ExpiresIn)
	}
	if decoded.Vars["firstName"] != "Carol" || decoded.Vars["lastName"] != "Smith" {
		t.Errorf("Vars: got %v, want Carol/Smith", decoded.Vars)
	}
}
