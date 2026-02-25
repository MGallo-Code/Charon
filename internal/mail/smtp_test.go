// smtp_test.go
//
// Integration test for SMTPMailer. Requires real SMTP credentials.
// Uses the same vars as production (SMTP_*) plus TEST_SMTP_TO for the recipient.
// Skips gracefully if any var is unset.
package mail

import (
	"context"
	"os"
	"testing"
	"time"
)

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
