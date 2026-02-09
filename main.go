package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

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
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

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
