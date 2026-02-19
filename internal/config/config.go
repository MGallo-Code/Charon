// config.go

// Environment variable loading and validation.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Config holds all env configuration vars for Charon.
type Config struct {
	DatabaseURL  string
	RedisURL     string
	Port         string
	CookieDomain string
	LogLevel     slog.Level
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

	return cfg, nil
}