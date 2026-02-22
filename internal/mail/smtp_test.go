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
)

func TestSMTPMailer_SendPasswordReset(t *testing.T) {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	to := os.Getenv("TEST_SMTP_TO") // test-only recipient

	if host == "" || port == "" || username == "" || password == "" || from == "" || to == "" {
		t.Skip("smtp integration test: set SMTP_* env vars and TEST_SMTP_TO to run")
	}

	mailer := NewSMTPMailer(host, port, username, password, from, "https://example.com/reset-password")

	err := mailer.SendPasswordReset(context.Background(), to, "test-token-abc123")
	if err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
}
