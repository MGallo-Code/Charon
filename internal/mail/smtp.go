// smtp.go
//
// Mailer interface and SMTPMailer implementation.
// Add other implementations (ses.go, etc.) as separate files in this package.
package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Mailer sends transactional emails.
type Mailer interface {
	// SendPasswordReset sends a password reset email containing the raw token.
	// vars is a map of %%key%% placeholder names to replacement values (e.g. "firstName": "John").
	// The mailer substitutes all %%key%% occurrences in subject and body before sending.
	// Unresolved placeholders are stripped rather than left in the email.
	// Reserved keys (url, toEmail, expiresIn) are owned by the mailer and cannot be overridden via vars.
	SendPasswordReset(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error

	// SendEmailVerification sends an email verification link containing the raw token.
	// vars is a map of %%key%% placeholder names to replacement values.
	// Unresolved placeholders are stripped rather than left in the email.
	// Reserved keys (url, toEmail, expiresIn) are owned by the mailer and cannot be overridden via vars.
	SendEmailVerification(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error

	// SendOAuthLinkConfirmation sends an account-link confirmation email.
	// The recipient must click the link to approve linking their OAuth identity to this account.
	// vars is a map of %%key%% placeholder names to replacement values.
	// Reserved keys (url, toEmail, expiresIn) are owned by the mailer and cannot be overridden via vars.
	SendOAuthLinkConfirmation(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error
}

// SMTPConfig holds all configuration for SMTPMailer.
type SMTPConfig struct {
	Host             string
	Port             string
	Username         string
	Password         string
	FromAddress      string
	ResetURLBase     string
	VerifyURLBase    string
	OAuthLinkURLBase string
}

// SMTPMailer sends transactional email via SMTP.
// Compatible with any SMTP provider: SES, Mailgun, Mailpit (local dev), etc.
type SMTPMailer struct {
	cfg SMTPConfig
}

// NewSMTPMailer creates an SMTPMailer with the given config.
func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

// NopMailer discards all outbound email. Used when SMTP is not configured.
type NopMailer struct{}

func (n *NopMailer) SendPasswordReset(_ context.Context, _, _ string, _ time.Duration, _ map[string]string) error {
	return nil
}

func (n *NopMailer) SendEmailVerification(_ context.Context, _, _ string, _ time.Duration, _ map[string]string) error {
	return nil
}

func (n *NopMailer) SendOAuthLinkConfirmation(_ context.Context, _, _ string, _ time.Duration, _ map[string]string) error {
	return nil
}

// reservedVars holds placeholder keys owned by the mailer.
// Caller-supplied vars with these keys are silently dropped to prevent override.
var reservedVars = map[string]bool{
	"url":       true,
	"toEmail":   true,
	"expiresIn": true,
}

// unresolvedPlaceholder matches any %%word%% placeholder left after substitution.
var unresolvedPlaceholder = regexp.MustCompile(`%%\w+%%`)

// applyVars substitutes %%key%% placeholders in tmpl using vars, then strips any
// that remain unresolved rather than leaving them in the output.
func applyVars(tmpl string, vars map[string]string) string {
	pairs := make([]string, 0, len(vars)*2)
	for key, value := range vars {
		pairs = append(pairs, "%%"+key+"%%", value)
	}
	substituted := strings.NewReplacer(pairs...).Replace(tmpl)
	return unresolvedPlaceholder.ReplaceAllString(substituted, "")
}

// formatDuration renders a duration as a human-readable expiry string.
// e.g. time.Hour → "1 hour", 48*time.Hour → "2 days", 30*time.Minute → "30 minutes".
func formatDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	case d >= time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	default:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
}

// sendMail dials the SMTP server, enforces STARTTLS (rejects plaintext sessions),
// authenticates, and delivers msg. The connection respects ctx cancellation.
func (m *SMTPMailer) sendMail(ctx context.Context, toEmail, msg string) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.cfg.Host+":"+m.cfg.Port)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	// Enforce STARTTLS -- reject the session if server does not advertise it.
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp server does not advertise STARTTLS: refusing plaintext session")
	}
	if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}

	if err := c.Mail(m.cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(toEmail); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}

	return c.Quit()
}

// SendPasswordReset emails a password reset link to toEmail.
// token is the raw (unhashed) token generated by the handler.
func (m *SMTPMailer) SendPasswordReset(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	// Copy caller vars, skipping reserved keys, then inject mailer-owned keys.
	merged := make(map[string]string, len(vars)+3)
	for k, v := range vars {
		if !reservedVars[k] {
			merged[k] = v
		}
	}
	merged["toEmail"] = toEmail
	merged["expiresIn"] = formatDuration(expiresIn)
	merged["url"] = m.cfg.ResetURLBase + "?token=" + url.QueryEscape(token)

	body := "You requested a password reset.\n\n" +
		"Click the link below to choose a new password:\n\n" +
		"%%url%%\n\n" +
		"This link expires in %%expiresIn%%. If you did not request a reset, ignore this email."

	msg := "From: " + m.cfg.FromAddress + "\r\n" +
		"To: " + toEmail + "\r\n" +
		"Subject: Reset your password\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body

	if err := m.sendMail(ctx, toEmail, applyVars(msg, merged)); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}

// SendEmailVerification emails a verification link to toEmail.
// token is the raw (unhashed) token generated by the handler.
func (m *SMTPMailer) SendEmailVerification(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	// Copy caller vars, skipping reserved keys, then inject mailer-owned keys.
	merged := make(map[string]string, len(vars)+3)
	for k, v := range vars {
		if !reservedVars[k] {
			merged[k] = v
		}
	}
	merged["toEmail"] = toEmail
	merged["expiresIn"] = formatDuration(expiresIn)
	merged["url"] = m.cfg.VerifyURLBase + "?token=" + url.QueryEscape(token)

	body := "Please verify your email address to complete registration.\n\n" +
		"Click the link below to confirm your email:\n\n" +
		"%%url%%\n\n" +
		"This link expires in %%expiresIn%%. If you did not create an account, ignore this email."

	msg := "From: " + m.cfg.FromAddress + "\r\n" +
		"To: " + toEmail + "\r\n" +
		"Subject: Confirm your email address\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body

	if err := m.sendMail(ctx, toEmail, applyVars(msg, merged)); err != nil {
		return fmt.Errorf("sending email verification: %w", err)
	}
	return nil
}

// SendOAuthLinkConfirmation emails an account-link confirmation link to toEmail.
// The recipient must click the link to approve linking their OAuth identity to this account.
func (m *SMTPMailer) SendOAuthLinkConfirmation(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	merged := make(map[string]string, len(vars)+3)
	for k, v := range vars {
		if !reservedVars[k] {
			merged[k] = v
		}
	}
	merged["toEmail"] = toEmail
	merged["expiresIn"] = formatDuration(expiresIn)
	merged["url"] = m.cfg.OAuthLinkURLBase + "?token=" + url.QueryEscape(token)

	body := "Someone signed in with a social account that matches your email address.\n\n" +
		"Click the link below to approve linking that account to yours:\n\n" +
		"%%url%%\n\n" +
		"This link expires in %%expiresIn%%. If you did not request this, ignore this email -- your account is safe."

	msg := "From: " + m.cfg.FromAddress + "\r\n" +
		"To: " + toEmail + "\r\n" +
		"Subject: Approve account linking\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body

	if err := m.sendMail(ctx, toEmail, applyVars(msg, merged)); err != nil {
		return fmt.Errorf("sending oauth link confirmation: %w", err)
	}
	return nil
}
