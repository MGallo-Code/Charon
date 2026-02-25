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
