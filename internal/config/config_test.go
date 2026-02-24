package config

import (
	"log/slog"
	"testing"
	"time"
)

// --- LoadConfig ---

func TestLoadConfig(t *testing.T) {
	// Helper sets the minimum required env vars for a valid config
	setRequired := func(t *testing.T) {
		t.Helper()
		t.Setenv("DATABASE_URL", "postgres://localhost/charon")
		t.Setenv("REDIS_URL", "redis://localhost:6379")
	}

	t.Run("returns valid config with all required vars", func(t *testing.T) {
		setRequired(t)

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.DatabaseURL != "postgres://localhost/charon" {
			t.Errorf("DatabaseURL: expected %q, got %q", "postgres://localhost/charon", cfg.DatabaseURL)
		}
		if cfg.RedisURL != "redis://localhost:6379" {
			t.Errorf("RedisURL: expected %q, got %q", "redis://localhost:6379", cfg.RedisURL)
		}
	})

	t.Run("errors when DATABASE_URL is missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("REDIS_URL", "redis://localhost:6379")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("expected error for missing DATABASE_URL, got nil")
		}
	})

	t.Run("errors when REDIS_URL is missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://localhost/charon")
		t.Setenv("REDIS_URL", "")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("expected error for missing REDIS_URL, got nil")
		}
	})

	t.Run("defaults PORT to 7865", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PORT", "")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Port != "7865" {
			t.Errorf("Port: expected %q, got %q", "7865", cfg.Port)
		}
	})

	t.Run("uses custom PORT when set", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PORT", "9090")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Port != "9090" {
			t.Errorf("Port: expected %q, got %q", "9090", cfg.Port)
		}
	})

	t.Run("LogLevel defaults to info when unset", func(t *testing.T) {
		setRequired(t)
		t.Setenv("LOG_LEVEL", "")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.LogLevel != slog.LevelInfo {
			t.Errorf("LogLevel: expected %v, got %v", slog.LevelInfo, cfg.LogLevel)
		}
	})

	t.Run("LogLevel parses all valid levels", func(t *testing.T) {
		setRequired(t)

		cases := map[string]slog.Level{
			"debug": slog.LevelDebug,
			"info":  slog.LevelInfo,
			"warn":  slog.LevelWarn,
			"error": slog.LevelError,
		}
		for input, expected := range cases {
			t.Setenv("LOG_LEVEL", input)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig failed for %q: %v", input, err)
			}
			if cfg.LogLevel != expected {
				t.Errorf("LogLevel for %q: expected %v, got %v", input, expected, cfg.LogLevel)
			}
		}
	})

	t.Run("LogLevel is case-insensitive", func(t *testing.T) {
		setRequired(t)

		for _, input := range []string{"DEBUG", "Debug", "dEbUg"} {
			t.Setenv("LOG_LEVEL", input)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig failed for %q: %v", input, err)
			}
			if cfg.LogLevel != slog.LevelDebug {
				t.Errorf("LogLevel for %q: expected %v, got %v", input, slog.LevelDebug, cfg.LogLevel)
			}
		}
	})

	t.Run("LogLevel defaults to info for unrecognized value", func(t *testing.T) {
		setRequired(t)
		t.Setenv("LOG_LEVEL", "verbose")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.LogLevel != slog.LevelInfo {
			t.Errorf("LogLevel: expected %v, got %v", slog.LevelInfo, cfg.LogLevel)
		}
	})
}

// --- Rate limit config ---

func TestRateLimitConfig(t *testing.T) {
	setRequired := func(t *testing.T) {
		t.Helper()
		t.Setenv("DATABASE_URL", "postgres://localhost/charon")
		t.Setenv("REDIS_URL", "redis://localhost:6379")
	}

	t.Run("login email defaults when vars absent", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_MAX", "")
		t.Setenv("RATE_LOGIN_EMAIL_WINDOW", "")
		t.Setenv("RATE_LOGIN_EMAIL_LOCKOUT", "")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailMax != 10 {
			t.Errorf("RateLoginEmailMax: expected 10, got %d", cfg.RateLoginEmailMax)
		}
		if cfg.RateLoginEmailWindow != 10*time.Minute {
			t.Errorf("RateLoginEmailWindow: expected 10m, got %v", cfg.RateLoginEmailWindow)
		}
		if cfg.RateLoginEmailLockout != 15*time.Minute {
			t.Errorf("RateLoginEmailLockout: expected 15m, got %v", cfg.RateLoginEmailLockout)
		}
	})

	t.Run("password reset defaults when vars absent", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_RESET_MAX", "")
		t.Setenv("RATE_RESET_WINDOW", "")
		t.Setenv("RATE_RESET_LOCKOUT", "")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateResetMax != 3 {
			t.Errorf("RateResetMax: expected 3, got %d", cfg.RateResetMax)
		}
		if cfg.RateResetWindow != 1*time.Hour {
			t.Errorf("RateResetWindow: expected 1h, got %v", cfg.RateResetWindow)
		}
		if cfg.RateResetLockout != 1*time.Hour {
			t.Errorf("RateResetLockout: expected 1h, got %v", cfg.RateResetLockout)
		}
	})

	t.Run("valid login email vars parse correctly", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_MAX", "5")
		t.Setenv("RATE_LOGIN_EMAIL_WINDOW", "5m")
		t.Setenv("RATE_LOGIN_EMAIL_LOCKOUT", "30m")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailMax != 5 {
			t.Errorf("RateLoginEmailMax: expected 5, got %d", cfg.RateLoginEmailMax)
		}
		if cfg.RateLoginEmailWindow != 5*time.Minute {
			t.Errorf("RateLoginEmailWindow: expected 5m, got %v", cfg.RateLoginEmailWindow)
		}
		if cfg.RateLoginEmailLockout != 30*time.Minute {
			t.Errorf("RateLoginEmailLockout: expected 30m, got %v", cfg.RateLoginEmailLockout)
		}
	})

	t.Run("valid password reset vars parse correctly", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_RESET_MAX", "5")
		t.Setenv("RATE_RESET_WINDOW", "2h")
		t.Setenv("RATE_RESET_LOCKOUT", "3h")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateResetMax != 5 {
			t.Errorf("RateResetMax: expected 5, got %d", cfg.RateResetMax)
		}
		if cfg.RateResetWindow != 2*time.Hour {
			t.Errorf("RateResetWindow: expected 2h, got %v", cfg.RateResetWindow)
		}
		if cfg.RateResetLockout != 3*time.Hour {
			t.Errorf("RateResetLockout: expected 3h, got %v", cfg.RateResetLockout)
		}
	})

	t.Run("invalid RATE_LOGIN_EMAIL_MAX falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_MAX", "bad")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailMax != 10 {
			t.Errorf("RateLoginEmailMax: expected default 10, got %d", cfg.RateLoginEmailMax)
		}
	})

	t.Run("negative RATE_LOGIN_EMAIL_MAX falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_MAX", "-1")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailMax != 10 {
			t.Errorf("RateLoginEmailMax: expected default 10, got %d", cfg.RateLoginEmailMax)
		}
	})

	t.Run("zero RATE_LOGIN_EMAIL_MAX falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_MAX", "0")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailMax != 10 {
			t.Errorf("RateLoginEmailMax: expected default 10, got %d", cfg.RateLoginEmailMax)
		}
	})

	t.Run("invalid RATE_LOGIN_EMAIL_WINDOW falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_LOGIN_EMAIL_WINDOW", "bad")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateLoginEmailWindow != 10*time.Minute {
			t.Errorf("RateLoginEmailWindow: expected default 10m, got %v", cfg.RateLoginEmailWindow)
		}
	})

	t.Run("invalid RATE_RESET_MAX falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_RESET_MAX", "bad")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateResetMax != 3 {
			t.Errorf("RateResetMax: expected default 3, got %d", cfg.RateResetMax)
		}
	})

	t.Run("invalid RATE_RESET_WINDOW falls back to default", func(t *testing.T) {
		setRequired(t)
		t.Setenv("RATE_RESET_WINDOW", "bad")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.RateResetWindow != 1*time.Hour {
			t.Errorf("RateResetWindow: expected default 1h, got %v", cfg.RateResetWindow)
		}
	})
}
