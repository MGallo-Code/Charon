// config.go

// Environment variable loading and validation.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all env configuration vars for Charon.
type Config struct {
	DatabaseURL  string
	RedisURL     string
	Port         string
	CookieDomain string
	LogLevel     slog.Level

	// SMTP configuration for outbound email. All optional -- empty Host disables sending.
	SMTPHost          string
	SMTPPort          string // defaults to 587
	SMTPUsername      string
	SMTPPassword      string
	SMTPFromAddress   string
	SMTPResetURLBase     string
	SMTPVerifyURLBase    string
	SMTPOAuthLinkURLBase string
	// MailQueueEncKey is the 32-byte AES-256 key used to encrypt tokens stored in the Redis mail queue.
	// If empty when SMTP is configured, tokens sit unencrypted in Redis.
	MailQueueEncKey string

	// Rate limit policy for registration attempts per email.
	// Defaults: max=5, window=1h, lockout=1h.
	RateRegisterEmailMax     int
	RateRegisterEmailWindow  time.Duration
	RateRegisterEmailLockout time.Duration

	// Rate limit policy for login attempts per email.
	// Defaults: max=10, window=10m, lockout=15m.
	RateLoginEmailMax     int
	RateLoginEmailWindow  time.Duration
	RateLoginEmailLockout time.Duration

	// Rate limit policy for password reset requests per email.
	// Defaults: max=3, window=1h, lockout=1h.
	RateResetMax     int
	RateResetWindow  time.Duration
	RateResetLockout time.Duration

	// Rate limit policy for resend verification email requests per email.
	// Defaults: max=3, window=1h, lockout=1h.
	RateResendMax     int
	RateResendWindow  time.Duration
	RateResendLockout time.Duration

	// RequireEmailVerification gates login on email_confirmed_at being set.
	// Default true; set REQUIRE_EMAIL_VERIFICATION=false to disable.
	RequireEmailVerification bool

	// Session TTLs. Defaults: 24h standard, 720h (30d) remember-me.
	SessionTTL        time.Duration
	SessionRememberMe time.Duration

	// Password complexity policy. All optional -- zero values are permissive.
	// Passed to auth.PasswordPolicy in main.go.
	PasswordMinLength        int
	PasswordMaxLength        int
	PasswordRequireUppercase bool
	PasswordRequireDigit     bool
	PasswordRequireSpecial   bool

	// Google OAuth -- all three required together to enable Google sign-in.
	// Leave GOOGLE_CLIENT_ID unset to disable Google OAuth entirely.
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	// CAPTCHA -- leave SECURITY_CAPTCHA_ENABLED unset or false to disable entirely.
	// CaptchaEnabled is reset to false at startup if CaptchaSecret is empty.
	CaptchaEnabled              bool
	CaptchaProvider             string
	CaptchaSecret               string
	CaptchaRegister             bool
	CaptchaLogin                bool
	CaptchaPasswordResetRequest bool
	CaptchaResendVerification   bool
}

// LoadConfig reads environment variables and returns a validated Config.
// Returns an error if DATABASE_URL is missing. REDIS_URL is optional -- empty disables Redis.
func LoadConfig() (*Config, error) {
	// Create config obj
	cfg := &Config{}

	// Attempt to get db url, if missing, err
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	// Optional -- empty disables Redis (sessions from Postgres, rate limiting inactive).
	cfg.RedisURL = os.Getenv("REDIS_URL")

	// Attempt to get port num, default to 7865
	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "7865"
	}

	// Attempt to get cookie domain
	cfg.CookieDomain = os.Getenv("COOKIE_DOMAIN")

	// Parse log level, default to info
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "warn":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		cfg.LogLevel = slog.LevelInfo
	}

	// SMTP -- all optional; empty Host means no email sending (NopMailer).
	cfg.SMTPHost = os.Getenv("SMTP_HOST")
	cfg.SMTPPort = os.Getenv("SMTP_PORT")
	cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
	cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
	cfg.SMTPFromAddress = os.Getenv("SMTP_FROM")
	cfg.SMTPResetURLBase = os.Getenv("SMTP_RESET_URL")
	cfg.SMTPVerifyURLBase = os.Getenv("SMTP_VERIFY_URL")
	cfg.SMTPOAuthLinkURLBase = os.Getenv("SMTP_OAUTH_LINK_URL")
	cfg.MailQueueEncKey = os.Getenv("MAIL_QUEUE_ENC_KEY")

	// When SMTP is configured, URL bases must be present and use HTTPS.
	// Tokens in reset/verify/oauth-link links must not travel over plain HTTP.
	if cfg.SMTPHost != "" {
		if !strings.HasPrefix(cfg.SMTPResetURLBase, "https://") {
			return nil, fmt.Errorf("SMTP_RESET_URL must be set and start with https://")
		}
		if !strings.HasPrefix(cfg.SMTPVerifyURLBase, "https://") {
			return nil, fmt.Errorf("SMTP_VERIFY_URL must be set and start with https://")
		}
		if !strings.HasPrefix(cfg.SMTPOAuthLinkURLBase, "https://") {
			return nil, fmt.Errorf("SMTP_OAUTH_LINK_URL must be set and start with https://")
		}
		if cfg.MailQueueEncKey == "" {
			slog.Warn("MAIL_QUEUE_ENC_KEY not set: mail queue tokens stored unencrypted in Redis")
		}
	}

	// Rate limit: registration by email.
	cfg.RateRegisterEmailMax = envInt("RATE_REGISTER_EMAIL_MAX", 5)
	cfg.RateRegisterEmailWindow = envDuration("RATE_REGISTER_EMAIL_WINDOW", 1*time.Hour)
	cfg.RateRegisterEmailLockout = envDuration("RATE_REGISTER_EMAIL_LOCKOUT", 1*time.Hour)

	// Rate limit: login by email. All three fields required -- if any are missing or invalid,
	// fall back to the default so a misconfigured env doesn't silently disable rate limiting.
	cfg.RateLoginEmailMax = envInt("RATE_LOGIN_EMAIL_MAX", 10)
	cfg.RateLoginEmailWindow = envDuration("RATE_LOGIN_EMAIL_WINDOW", 10*time.Minute)
	cfg.RateLoginEmailLockout = envDuration("RATE_LOGIN_EMAIL_LOCKOUT", 15*time.Minute)

	// Rate limit: password reset.
	cfg.RateResetMax = envInt("RATE_RESET_MAX", 3)
	cfg.RateResetWindow = envDuration("RATE_RESET_WINDOW", 1*time.Hour)
	cfg.RateResetLockout = envDuration("RATE_RESET_LOCKOUT", 1*time.Hour)

	// Rate limit: resend verification email.
	cfg.RateResendMax = envInt("RATE_RESEND_MAX", 3)
	cfg.RateResendWindow = envDuration("RATE_RESEND_WINDOW", 1*time.Hour)
	cfg.RateResendLockout = envDuration("RATE_RESEND_LOCKOUT", 1*time.Hour)

	// Default true -- only explicit "false" disables.
	cfg.RequireEmailVerification = os.Getenv("REQUIRE_EMAIL_VERIFICATION") != "false"

	cfg.SessionTTL = envDuration("SESSION_TTL", 24*time.Hour)
	cfg.SessionRememberMe = envDuration("SESSION_REMEMBER_ME_TTL", 720*time.Hour)

	// Password complexity policy -- optional, all default to permissive values.
	cfg.PasswordMinLength = envInt("PASSWORD_MIN_LENGTH", 8)
	cfg.PasswordMaxLength = envInt("PASSWORD_MAX_LENGTH", 128)
	cfg.PasswordRequireUppercase = envBool("PASSWORD_REQUIRE_UPPERCASE")
	cfg.PasswordRequireDigit = envBool("PASSWORD_REQUIRE_DIGIT")
	cfg.PasswordRequireSpecial = envBool("PASSWORD_REQUIRE_SPECIAL")

	// Google OAuth -- optional; all three must be set together.
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.GoogleRedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
	hasID := cfg.GoogleClientID != ""
	hasSecret := cfg.GoogleClientSecret != ""
	hasURL := cfg.GoogleRedirectURL != ""
	if (hasID || hasSecret || hasURL) && !(hasID && hasSecret && hasURL) {
		if !hasID {
			slog.Warn("google oauth disabled: GOOGLE_CLIENT_ID not set")
		}
		if !hasSecret {
			slog.Warn("google oauth disabled: GOOGLE_CLIENT_SECRET not set")
		}
		if !hasURL {
			slog.Warn("google oauth disabled: GOOGLE_REDIRECT_URL not set")
		}
		cfg.GoogleClientID = ""
		cfg.GoogleClientSecret = ""
		cfg.GoogleRedirectURL = ""
	}

	// CAPTCHA -- optional; disabled when SECURITY_CAPTCHA_ENABLED is unset or secret is missing.
	cfg.CaptchaEnabled = envBool("SECURITY_CAPTCHA_ENABLED")
	cfg.CaptchaProvider = os.Getenv("SECURITY_CAPTCHA_PROVIDER")
	cfg.CaptchaSecret = os.Getenv("SECURITY_CAPTCHA_SECRET")
	cfg.CaptchaRegister = envBool("SECURITY_CAPTCHA_REGISTER")
	cfg.CaptchaLogin = envBool("SECURITY_CAPTCHA_LOGIN")
	cfg.CaptchaPasswordResetRequest = envBool("SECURITY_CAPTCHA_PASSWORD_RESET")
	cfg.CaptchaResendVerification = envBool("SECURITY_CAPTCHA_RESEND_VERIFICATION")
	if cfg.CaptchaEnabled && cfg.CaptchaSecret == "" {
		slog.Warn("SECURITY_CAPTCHA_ENABLED=true but SECURITY_CAPTCHA_SECRET is not set: captcha disabled")
		cfg.CaptchaEnabled = false
	}

	return cfg, nil
}

// WarnIfMisconfigured logs a warning for any rate limit policy with a zero Window or LockoutTTL.
// Zero durations cause Redis Lua script failures at request time; catching them at startup is safer.
// Call from run() so configs built directly (e.g. in tests) are also validated.
func (c *Config) WarnIfMisconfigured() {
	type policy struct {
		name    string
		window  time.Duration
		lockout time.Duration
	}
	policies := []policy{
		{"RATE_REGISTER_EMAIL", c.RateRegisterEmailWindow, c.RateRegisterEmailLockout},
		{"RATE_LOGIN_EMAIL", c.RateLoginEmailWindow, c.RateLoginEmailLockout},
		{"RATE_RESET", c.RateResetWindow, c.RateResetLockout},
		{"RATE_RESEND", c.RateResendWindow, c.RateResendLockout},
	}
	for _, p := range policies {
		if p.window <= 0 {
			slog.Warn("rate limit policy misconfigured: zero Window will cause Redis errors", "policy", p.name)
		}
		if p.lockout <= 0 {
			slog.Warn("rate limit policy misconfigured: zero LockoutTTL will cause Redis errors", "policy", p.name)
		}
	}
}

// envInt reads an env var as int, returning def if missing or unparseable.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", def)
		return def
	}
	return n
}

// envBool reads an env var as bool; returns true only when the value is exactly "true".
func envBool(key string) bool {
	return os.Getenv(key) == "true"
}

// envDuration reads an env var as time.Duration, returning def if missing or unparseable.
func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", def)
		return def
	}
	return d
}
