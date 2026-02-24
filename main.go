package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MGallo-Code/charon/internal/auth"
	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/mail"
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

	// Include source location in log entries at debug level only.
	addSrc := cfg.LogLevel == slog.LevelDebug

	// Set up slog to output as json with configured level
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     cfg.LogLevel,
		AddSource: addSrc,
	})))

	// Cancel ctx on SIGINT/SIGTERM; run() shuts down when ctx is done.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// run() is a separate func so deferred closes (ps, rs) always execute before os.Exit.
	if err := run(ctx, cfg, nil); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run holds all server logic and returns error instead of calling os.Exit,
// so deferred resource cleanup (ps.Close, rs.Close) always runs.
// Shuts down when ctx is cancelled (signal handling is the caller's concern).
// If ready is non-nil, the server's base URL is sent on it once the listener is bound.
func run(ctx context.Context, cfg *config.Config, ready chan<- string) error {
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

	// Create shared Redis client; all Redis structs share one connection pool.
	rdb, err := store.NewRedisClient(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("failed to set up redis client: %w", err)
	}
	defer rdb.Close()

	rs := store.NewRedisStore(rdb)
	rl := store.NewRedisRateLimiter(rdb)

	// Use NopMailer until SMTP is configured via env vars.
	var ml mail.Mailer = &mail.NopMailer{}

	// Create AuthHandler
	h := auth.AuthHandler{PS: ps, RS: rs, RL: rl, ML: ml}

	// Bind listener; ":0" picks a free port (useful in tests).
	ln, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	server := &http.Server{Handler: buildRouter(&h)}

	// Session cleanup goroutine; removes sessions expired >7 days ago, runs every 24h.
	// Cancelled via cleanupCtx when run() returns.
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

	// Start server in a goroutine; run() continues past this.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("charon listening", "addr", ln.Addr().String())
		// Send error only if server stops for a reason other than explicit shutdown.
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Signal readiness to caller (used by tests; nil in production).
	if ready != nil {
		ready <- "http://" + ln.Addr().String()
	}

	// Wait for server error or shutdown signal from ctx.
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
	}

	// Graceful shutdown ! :)
	slog.Info("shutting down server...")
	// Create context with 30s timeout, defer the cancel function to release the context's resources
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// server.Shutdown:
	//  1. Stops accepting new conns
	//  2. Waits for all in-progress requests to finish and responses to be sent
	//  3. Returnn nil when done or an error if the 30s timeout hits first
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	slog.Info("server stopped")
	return nil
}

// buildRouter wires all routes and middleware.
// Called from run() for smoke tests.
func buildRouter(h *auth.AuthHandler) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Post("/register/email", h.RegisterByEmail)
	r.Post("/login/email", h.LoginByEmail)
	r.Post("/password/reset", h.PasswordReset)
	r.Post("/password/confirm", h.PasswordConfirm)

	// Authentication required routes
	r.Group(func(r chi.Router) {
		r.Use(h.RequireAuth)
		// CSRF reads token injected by RequireAuth above
		// DO NOT RUN CSRF BEFORE RequireAuth
		r.Use(h.CSRFMiddleware)
		r.Post("/logout", h.Logout)
		r.Post("/logout-all", h.LogoutAll)
		r.Post("/password/change", h.PasswordChange)
	})

	return r
}
