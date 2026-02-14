package config

import (
	"testing"
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

	t.Run("CookieSecure defaults to true when unset", func(t *testing.T) {
		setRequired(t)
		t.Setenv("COOKIE_SECURE", "")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if !cfg.CookieSecure {
			t.Error("CookieSecure should default to true when COOKIE_SECURE is unset")
		}
	})

	t.Run("CookieSecure is false only when explicitly set to false", func(t *testing.T) {
		setRequired(t)
		t.Setenv("COOKIE_SECURE", "false")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.CookieSecure {
			t.Error("CookieSecure should be false when COOKIE_SECURE is \"false\"")
		}
	})

	t.Run("CookieSecure stays true for any non-false value", func(t *testing.T) {
		setRequired(t)
		// "true", "1", "yes", typos — all should result in secure cookies
		for _, val := range []string{"true", "1", "yes", "FALSE", "typo"} {
			t.Setenv("COOKIE_SECURE", val)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig failed for %q: %v", val, err)
			}
			if !cfg.CookieSecure {
				t.Errorf("CookieSecure should be true for %q", val)
			}
		}
	})
}
