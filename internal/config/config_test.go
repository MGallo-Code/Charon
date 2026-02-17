package config

import (
	"log/slog"
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
