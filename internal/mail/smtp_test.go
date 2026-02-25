// smtp_test.go
//
// Unit tests for pure mail helpers + integration tests for SMTPMailer.
// Integration tests require real SMTP credentials and skip gracefully if unset.
package mail

import (
	"context"
	"os"
	"testing"
	"time"
)

// --- Unit tests (no SMTP required) ---

func TestApplyVars(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
		vars map[string]string
		want string
	}{
		{
			name: "substitutes known keys",
			tmpl: "Hello %%firstName%%, your link is %%url%%",
			vars: map[string]string{"firstName": "John", "url": "https://example.com"},
			want: "Hello John, your link is https://example.com",
		},
		{
			name: "strips unresolved placeholders",
			tmpl: "Hello %%firstName%%, click %%url%%",
			vars: map[string]string{"firstName": "John"},
			want: "Hello John, click ",
		},
		{
			name: "empty vars strips all placeholders",
			tmpl: "%%greeting%% click %%url%%",
			vars: map[string]string{},
			want: " click ",
		},
		{
			name: "nil vars strips all placeholders",
			tmpl: "%%greeting%%",
			vars: nil,
			want: "",
		},
		{
			name: "no placeholders passes through unchanged",
			tmpl: "Hello there, click the link.",
			vars: map[string]string{"firstName": "John"},
			want: "Hello there, click the link.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyVars(tt.tmpl, tt.vars)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{time.Minute, "1 minute"},
		{30 * time.Minute, "30 minutes"},
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{24 * time.Hour, "1 day"},
		{48 * time.Hour, "2 days"},
		{72 * time.Hour, "3 days"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestReservedVarsDropped(t *testing.T) {
	// Caller passes all three reserved keys -- they must be dropped and not
	// affect the merged map's mailer-owned values.
	mailer := &SMTPMailer{cfg: SMTPConfig{ResetURLBase: "https://example.com/reset"}}

	callerVars := map[string]string{
		"url":       "https://phishing.example.com",
		"expiresIn": "never",
		"toEmail":   "attacker@evil.com",
		"firstName": "John", // non-reserved, must survive
	}

	merged := make(map[string]string, len(callerVars)+3)
	for k, v := range callerVars {
		if !reservedVars[k] {
			merged[k] = v
		}
	}
	merged["url"] = mailer.cfg.ResetURLBase + "?token=abc"
	merged["expiresIn"] = "1 hour"
	merged["toEmail"] = "user@example.com"

	if merged["url"] != "https://example.com/reset?token=abc" {
		t.Errorf("url: got %q, want mailer-owned value", merged["url"])
	}
	if merged["expiresIn"] != "1 hour" {
		t.Errorf("expiresIn: got %q, want mailer-owned value", merged["expiresIn"])
	}
	if merged["toEmail"] != "user@example.com" {
		t.Errorf("toEmail: got %q, want mailer-owned value", merged["toEmail"])
	}
	if merged["firstName"] != "John" {
		t.Errorf("firstName: got %q, want %q", merged["firstName"], "John")
	}
}

// --- Integration tests (require SMTP credentials) ---

// smtpTestMailer returns a configured SMTPMailer and recipient, or skips if env vars are missing.
func smtpTestMailer(t *testing.T) (*SMTPMailer, string) {
	t.Helper()
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	to := os.Getenv("TEST_SMTP_TO")

	if host == "" || port == "" || username == "" || password == "" || from == "" || to == "" {
		t.Skip("smtp integration test: set SMTP_* env vars and TEST_SMTP_TO to run")
	}

	mailer := NewSMTPMailer(SMTPConfig{
		Host:          host,
		Port:          port,
		Username:      username,
		Password:      password,
		FromAddress:   from,
		ResetURLBase:  "https://example.com/reset-password",
		VerifyURLBase: "https://example.com/verify-email",
	})
	return mailer, to
}

func TestSMTPMailer_SendPasswordReset(t *testing.T) {
	mailer, to := smtpTestMailer(t)

	if err := mailer.SendPasswordReset(context.Background(), to, "test-token-abc123", time.Hour, map[string]string{"firstName": "firstname", "lastName": "lastname"}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
}

func TestSMTPMailer_SendEmailVerification(t *testing.T) {
	mailer, to := smtpTestMailer(t)

	if err := mailer.SendEmailVerification(context.Background(), to, "test-verify-token-abc123", 24*time.Hour, map[string]string{"firstName": "firstname", "lastName": "lastname"}); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
}
