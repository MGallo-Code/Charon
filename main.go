package main

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Embeds the migration files INTO the go bin

//go:embed migrations/*.sql
var migrationsDir embed.FS

func main() {
	// Set up slog to output as json
	handler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(handler))

	// Load config from env variables
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Create a new context
	ctx := context.Background()

	// Create new postgres store, log errors if any
	ps, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to set up postgres store", "err", err)
		os.Exit(1)
	}
	// Close at end of main
	defer ps.Close()

	// Run database migrations
	migrationsFS, err := fs.Sub(migrationsDir, "migrations")
	if err != nil {
		slog.Error("failed to access embedded migrations", "err", err)
		os.Exit(1)
	}
	if err := ps.Migrate(ctx, migrationsFS); err != nil {
		slog.Error("failed to run migrations", "err", err)
		os.Exit(1)
	}

	// Create new redis store, log errors if any
	rs, err := store.NewRedisStore(ctx, cfg.RedisURL)
	if err != nil {
		slog.Error("failed to set up redis store", "err", err)
		os.Exit(1)
	}
	// Close at end of main
	defer rs.Close()

	// Create new router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Handle GET req to /health, respond ok
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Concat port var
	addr := ":" + cfg.Port
	// Log listening and attempt to serve
	slog.Info("charon listening", "addr", addr)
	err = http.ListenAndServe(addr, r)
	if err != nil {
		slog.Error("failed to start server", "err", err)
		os.Exit(1)
	}
}
