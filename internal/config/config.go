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
	SMTPResetURLBase  string
	SMTPVerifyURLBase string

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

	// RequireEmailVerification gates login on email_confirmed_at being set.
	// Default true; set REQUIRE_EMAIL_VERIFICATION=false to disable.
	RequireEmailVerification bool

	// Session TTLs. Defaults: 24h standard, 720h (30d) remember-me.
	SessionTTL         time.Duration
	SessionRememberMe  time.Duration
}

// LoadConfig reads environment variables and returns a validated Config.
// Returns an error if required variables (DATABASE_URL, REDIS_URL) are missing.
func LoadConfig() (*Config, error) {
	// Create config obj
	cfg := &Config{}

	// Attempt to get db url, if missing, err
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	// Attempt to get redis url, if missing, err
	cfg.RedisURL = os.Getenv("REDIS_URL")
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("REDIS_URL is required")
	}

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
	if cfg.SMTPPort == "" {
		cfg.SMTPPort = "587"
	}
	cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
	cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
	cfg.SMTPFromAddress = os.Getenv("SMTP_FROM")
	cfg.SMTPResetURLBase = os.Getenv("SMTP_RESET_URL")
	cfg.SMTPVerifyURLBase = os.Getenv("SMTP_VERIFY_URL")

	// When SMTP is configured, URL bases must be present and use HTTPS.
	// Tokens in reset/verify links must not travel over plain HTTP.
	if cfg.SMTPHost != "" {
		if !strings.HasPrefix(cfg.SMTPResetURLBase, "https://") {
			return nil, fmt.Errorf("SMTP_RESET_URL must be set and start with https://")
		}
		if !strings.HasPrefix(cfg.SMTPVerifyURLBase, "https://") {
			return nil, fmt.Errorf("SMTP_VERIFY_URL must be set and start with https://")
		}
	}

	// Rate limit: login by email. All three fields required -- if any are missing or invalid,
	// fall back to the default so a misconfigured env doesn't silently disable rate limiting.
	cfg.RateLoginEmailMax = envInt("RATE_LOGIN_EMAIL_MAX", 10)
	cfg.RateLoginEmailWindow = envDuration("RATE_LOGIN_EMAIL_WINDOW", 10*time.Minute)
	cfg.RateLoginEmailLockout = envDuration("RATE_LOGIN_EMAIL_LOCKOUT", 15*time.Minute)

	// Rate limit: password reset.
	cfg.RateResetMax = envInt("RATE_RESET_MAX", 3)
	cfg.RateResetWindow = envDuration("RATE_RESET_WINDOW", 1*time.Hour)
	cfg.RateResetLockout = envDuration("RATE_RESET_LOCKOUT", 1*time.Hour)

	// Default true -- only explicit "false" disables.
	cfg.RequireEmailVerification = os.Getenv("REQUIRE_EMAIL_VERIFICATION") != "false"

	cfg.SessionTTL = envDuration("SESSION_TTL", 24*time.Hour)
	cfg.SessionRememberMe = envDuration("SESSION_REMEMBER_ME_TTL", 720*time.Hour)

	return cfg, nil
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