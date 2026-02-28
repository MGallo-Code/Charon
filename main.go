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
	"github.com/MGallo-Code/charon/internal/captcha"
	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/mail"
	"github.com/MGallo-Code/charon/internal/oauth"
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
	// Passing nil for ml, run() builds the real mailer from config.
	if err := run(ctx, cfg, nil, nil); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run holds all server logic and returns error instead of calling os.Exit,
// so deferred resource cleanup (ps.Close, rs.Close) always runs.
// Shuts down when ctx is cancelled (signal handling is the caller's concern).
// If ready is non-nil, the server's base URL is sent on it once the listener is bound.
// If ml is nil, NopMailer is used.
func run(ctx context.Context, cfg *config.Config, ready chan<- string, ml mail.Mailer) error {
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

	// Redis is optional. When REDIS_URL is unset: sessions served from Postgres,
	// rate limiting disabled, mail sent synchronously without a retry queue.
	var (
		rs       auth.SessionCache = store.NewNoopSessionCache()
		rl       auth.RateLimiter  = store.NewNoopRateLimiter()
		hasRedis bool
	)
	smtpCfg := mail.SMTPConfig{
		Host:             cfg.SMTPHost,
		Port:             cfg.SMTPPort,
		Username:         cfg.SMTPUsername,
		Password:         cfg.SMTPPassword,
		FromAddress:      cfg.SMTPFromAddress,
		ResetURLBase:     cfg.SMTPResetURLBase,
		VerifyURLBase:    cfg.SMTPVerifyURLBase,
		OAuthLinkURLBase: cfg.SMTPOAuthLinkURLBase,
	}
	if cfg.RedisURL != "" {
		// Rate limit policy zeros only matter when Redis is active.
		cfg.WarnIfMisconfigured()
		rdb, err := store.NewRedisClient(ctx, cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("failed to set up redis client: %w", err)
		}
		defer rdb.Close()
		rs = store.NewRedisStore(rdb)
		rl = store.NewRedisRateLimiter(rdb)
		hasRedis = true
		// QueuedMailer requires Redis for its queue backend; only created when both are available.
		if ml == nil && cfg.SMTPHost != "" {
			qm := mail.NewQueuedMailer(mail.NewSMTPMailer(smtpCfg), rdb, mail.DefaultMaxQueueSize, []byte(cfg.MailQueueEncKey))
			go qm.StartWorker(ctx)
			ml = qm
		}
	}

	// Build remaining mailer: no Redis path, test-injected nil with no Redis, or no SMTP.
	if ml == nil {
		if cfg.SMTPHost != "" {
			ml = mail.NewSMTPMailer(smtpCfg) // synchronous -- no retry queue without Redis
		} else {
			ml = &mail.NopMailer{}
		}
	}

	// Set up OAuth providers. Non-fatal -- missing/unreachable config disables the provider.
	oauthProviders := map[string]oauth.Provider{}
	if cfg.GoogleClientID != "" {
		gp, err := oauth.NewGoogleProvider(ctx, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
		if err != nil {
			slog.Error("google oauth setup failed, google sign-in disabled", "error", err)
		} else {
			oauthProviders["google"] = gp
		}
	}

	// Set up CAPTCHA verifier. Nil when disabled -- handlers skip verification.
	var cv auth.CaptchaVerifier
	if cfg.CaptchaEnabled {
		switch cfg.CaptchaProvider {
		case "turnstile":
			cv = captcha.NewTurnstileVerifier(cfg.CaptchaSecret)
		default:
			slog.Warn("unknown captcha provider, captcha disabled", "provider", cfg.CaptchaProvider)
		}
	}

	// Create AuthHandler
	h := auth.AuthHandler{
		PS:                       ps,
		RS:                       rs,
		RL:                       rl,
		ML:                       ml,
		RequireEmailVerification: cfg.RequireEmailVerification,
		SessionTTL:               cfg.SessionTTL,
		SessionRememberMe:        cfg.SessionRememberMe,
		Policies: auth.RateLimitPolicies{
			RegisterEmail: store.RateLimit{
				MaxAttempts: cfg.RateRegisterEmailMax,
				Window:      cfg.RateRegisterEmailWindow,
				LockoutTTL:  cfg.RateRegisterEmailLockout,
			},
			LoginEmail: store.RateLimit{
				MaxAttempts: cfg.RateLoginEmailMax,
				Window:      cfg.RateLoginEmailWindow,
				LockoutTTL:  cfg.RateLoginEmailLockout,
			},
			PasswordReset: store.RateLimit{
				MaxAttempts: cfg.RateResetMax,
				Window:      cfg.RateResetWindow,
				LockoutTTL:  cfg.RateResetLockout,
			},
			ResendVerification: store.RateLimit{
				MaxAttempts: cfg.RateResendMax,
				Window:      cfg.RateResendWindow,
				LockoutTTL:  cfg.RateResendLockout,
			},
		},
		Policy: auth.PasswordPolicy{
			MinLength:        cfg.PasswordMinLength,
			MaxLength:        cfg.PasswordMaxLength,
			RequireUppercase: cfg.PasswordRequireUppercase,
			RequireDigit:     cfg.PasswordRequireDigit,
			RequireSpecial:   cfg.PasswordRequireSpecial,
		},
		OAuthProviders: oauthProviders,
		SMTPEnabled:    cfg.SMTPHost != "",
		CV:             cv,
		CaptchaCP: auth.CaptchaPolicies{
			Register:             cfg.CaptchaRegister,
			Login:                cfg.CaptchaLogin,
			PasswordResetRequest: cfg.CaptchaPasswordResetRequest,
			ResendVerification:   cfg.CaptchaResendVerification,
		},
	}

	logStartupSummary(hasRedis, cfg.SMTPHost != "", cv != nil, oauthProviders, cfg.RequireEmailVerification)

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

	r.Get("/health", h.CheckHealth)
	r.Get("/oauth/{provider}", h.OAuthRedirect)
	r.Get("/oauth/{provider}/callback", h.OAuthCallback)
	r.Post("/oauth/link/confirm", h.ConfirmOAuthLink)
	r.Post("/register/email", h.RegisterByEmail)
	r.Post("/login/email", h.LoginByEmail)
	r.Post("/verify/email", h.VerifyEmail)
	r.Post("/send/verify/email", h.ResendVerificationEmail)
	r.Post("/send/reset/password", h.PasswordReset)
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

// logStartupSummary logs one line per subsystem so operators can verify configuration at a glance.
// Called once after all features are wired, before the listener binds.
func logStartupSummary(hasRedis, hasSMTP, hasCaptcha bool, oauthProviders map[string]oauth.Provider, requireEmailVerification bool) {
	if hasRedis {
		slog.Info("redis enabled — session cache and rate limiting active")
	} else {
		slog.Warn("redis disabled — sessions served from postgres, rate limiting inactive")
	}

	if hasSMTP {
		if hasRedis {
			slog.Info("smtp enabled", "mode", "queued")
		} else {
			slog.Info("smtp enabled", "mode", "synchronous")
		}
	} else {
		slog.Warn("smtp disabled — email features unavailable")
	}

	if len(oauthProviders) > 0 {
		names := make([]string, 0, len(oauthProviders))
		for k := range oauthProviders {
			names = append(names, k)
		}
		slog.Info("oauth enabled", "providers", names)
	} else {
		slog.Info("oauth disabled")
	}

	if hasCaptcha {
		slog.Info("captcha enabled")
	} else {
		slog.Info("captcha disabled")
	}

	if requireEmailVerification {
		slog.Info("email verification required")
	} else {
		slog.Warn("email verification disabled — any registered email can log in")
	}
}
