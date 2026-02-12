// Package config loads and validates environment variables.
package config

import (
	"fmt"
	"os"
)

// Config holds all env configuration vars for Charon.
type Config struct {
	DatabaseURL  string
	RedisURL     string
	Port         string
	CookieDomain string
	CookieSecure bool
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

	// Attempt to get cookie secure value as bool
	cfg.CookieSecure = os.Getenv("COOKIE_SECURE") != "false"

	return cfg, nil
}
