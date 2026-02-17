package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MGallo-Code/charon/internal/auth"
	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Embeds the migration files INTO the go bin

//go:embed migrations/*.sql
var migrationsDir embed.FS

func main() {
	// Load config first so we can set log level
	cfg, err := config.LoadConfig()
	if err != nil {
		// Fallback logger before config is available
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}

	// Show file, line, and function in every log entry at debug level, otherwise don't
	addSrc := cfg.LogLevel == slog.LevelDebug

	// Set up slog to output as json with configured level
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     cfg.LogLevel,
		AddSource: addSrc,
	})))

	// Put main server running in a function so deferred calls actually run when we have to call os.Exit(1), then we can exit here
	if err := run(cfg); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run contains all server logic. Returns error instead of os.Exit
// so defers (ps.Close, rs.Close) always run.
func run(cfg *config.Config) error {
	// Create a new context
	ctx := context.Background()

	// Create new postgres store, return errors if any
	ps, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to set up postgres store: %w", err)
	}
	// Close at end of run func
	defer ps.Close()

	// Run database migrations
	migrationsFS, err := fs.Sub(migrationsDir, "migrations")
	if err != nil {
		return fmt.Errorf("failed to access embedded migrations: %w", err)
	}
	if err := ps.Migrate(ctx, migrationsFS); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create new redis store, return errors if any
	rs, err := store.NewRedisStore(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("failed to set up redis store: %w", err)
	}
	// Close at end of run
	defer rs.Close()

	// Create AuthHandler
	h := auth.AuthHandler{
		PS: ps,
		RS: rs,
	}

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
	r.Post("/registerEmail", h.RegisterByEmail)
	r.Post("/loginEmail", h.LoginByEmail)

	// Create server (& format port)
	addr := ":" + cfg.Port
	server := &http.Server{Addr: addr, Handler: r}

	// Start session cleanup goroutine — deletes sessions expired >7 days ago, runs every 24h.
	// cleanupCtx is cancelled when run() returns, stopping the goroutine cleanly on shutdown.
	cleanupCtx, cancelCleanup := context.WithCancel(ctx)
	defer cancelCleanup()
	go func() {
		const retention = 7 * 24 * time.Hour
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n, err := ps.CleanupExpiredSessions(cleanupCtx, retention)
				if err != nil {
					slog.Warn("session cleanup failed", "error", err)
				} else {
					slog.Info("session cleanup complete", "deleted", n)
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	// Start server in a goroutine, run() func continues past this
	errCh := make(chan error, 1)
	go func() {
		slog.Info("charon listening", "addr", addr)
		// If server closes for reason other than user stopping server, send err to channel
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Channel listens to os.Signal values...holds 1 signal
	quit := make(chan os.Signal, 1)
	// Tell go when program told to terminate -> send signal to quit chan instead of instantly killing proc
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Wait for server error (server never started) or shutdown signal
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-quit:
	}

	// Graceful shutdown ! :)
	slog.Info("shutting down server...")
	// Create context with 30s timeout, defer the cancel function to release the context's resources
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// server.Shutdown
	//  1. Stops accepting new conns
	//  2. Waits for all in-progress requests to finish their handlers and get responses sent
	//  3. Returnn nil when done or an error if the shutdown context's 30s hits first
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}
	slog.Info("server stopped")
	return nil
}
