// handler.go -- HTTP handlers for all /auth/* endpoints.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MGallo-Code/charon/internal/mail"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SessionCache defines session cache operations needed by auth handlers.
// Satisfied by *store.RedisStore — defined here (at consumer) per Go convention.
type SessionCache interface {
	// GetSession retrieves cached session by token hash.
	GetSession(ctx context.Context, tokenHash string) (*store.CachedSession, error)

	// SetSession caches session with given TTL in seconds.
	SetSession(ctx context.Context, tokenHash string, sessionData store.Session, ttl int) error

	// DeleteSession removes session and its entry in the user tracking set.
	DeleteSession(ctx context.Context, tokenHash string, userID uuid.UUID) error

	// DeleteAllUserSessions removes all cached sessions for a user.
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error

	// CheckHealth returns nil if Redis is reachable, non-nil otherwise.
	CheckHealth(ctx context.Context) error
}

// Store defines database operations needed by auth handlers.
// Satisfied by *store.PostgresStore — defined here (at consumer) per Go convention.
type Store interface {
	// CreateUserByEmail inserts new user with email and hashed password.
	CreateUserByEmail(ctx context.Context, uuid uuid.UUID, email, passwordHash string) error

	// GetUserByEmail fetches user by email for login verification.
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)

	// GetPwdHashByUserID fetches Argon2id hash for password verification.
	GetPwdHashByUserID(ctx context.Context, id uuid.UUID) (string, error)

	// UpdateUserPassword attempts to update the password of user attached to given id.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// CreateSession inserts new session row with token hash and CSRF token.
	CreateSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error

	// GetSessionByTokenHash fetches valid (non-expired) session by token hash.
	// Returns pgx.ErrNoRows if not found or expired.
	GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*store.Session, error)

	// DeleteSession removes single session row by token hash.
	DeleteSession(ctx context.Context, tokenHash []byte) error

	// DeleteAllUserSessions removes all sessions for a user.
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error

	// CreateToken inserts a new single-use verification token for the user.
	CreateToken(ctx context.Context, id, userID uuid.UUID, tokenType string, tokenHash []byte, expiresAt time.Time) error

	// GetTokenByHash fetches a valid, unused, non-expired token by its SHA-256 hash.
	// Returns pgx.ErrNoRows if not found, already used, or expired.
	GetTokenByHash(ctx context.Context, tokenHash []byte, tokenType string) (*store.Token, error)

	// MarkTokenUsed sets used_at = NOW() for the token with the given hash.
	// Returns pgx.ErrNoRows if no matching unused token exists.
	MarkTokenUsed(ctx context.Context, tokenHash []byte) error

	// ConsumeToken fetches a valid, unused, non-expired token by its SHA-256 hash.
	// Returns user_id associated with token if valid token found, pgx.ErrNoRows if no token found.
	ConsumeToken(ctx context.Context, tokenHash []byte, tokenType string) (uuid.UUID, error)

	// SetEmailConfirmedAt sets email_confirmed_at = NOW() for userID if not already confirmed.
	SetEmailConfirmedAt(ctx context.Context, userID uuid.UUID) error

	// WriteAuditLog inserts a single audit event into audit_logs.
	// Non-fatal: callers log the error but never fail the request on audit write failure.
	WriteAuditLog(ctx context.Context, entry store.AuditEntry) error

	// CheckHealth returns nil if Postgres is reachable, non-nil otherwise.
	CheckHealth(ctx context.Context) error
}

// RateLimiter checks and records rate limit state for a given key and policy.
// Satisfied by *store.RedisRateLimiter -- defined here per Go convention.
type RateLimiter interface {
	// Allow checks whether the action is within policy, records the attempt.
	// Returns nil if allowed; non-nil error if locked out or threshold exceeded.
	Allow(ctx context.Context, key string, policy store.RateLimit) error
}

// RateLimitPolicies holds rate limit policies for all auth endpoints.
// Configured via RATE_* env vars with defaults set in config.go.
type RateLimitPolicies struct {
	RegisterEmail      store.RateLimit
	LoginEmail         store.RateLimit
	PasswordReset      store.RateLimit
	ResendVerification store.RateLimit
}

// dummyPasswordHash generates a live Argon2id hash at startup for timing attack mitigation.
// When a user doesn't exist, verify against this so both paths take equal time (~100ms).
// Generated from live constants so it tracks any future parameter changes in password.go.
var dummyPasswordHash = sync.OnceValue(func() string {
	h, _ := HashPassword("dummy")
	return h
})

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS       Store
	RS       SessionCache
	RL       RateLimiter
	ML       mail.Mailer
	Policies RateLimitPolicies

	// RequireEmailVerification blocks login until email_confirmed_at is set.
	// Controlled by REQUIRE_EMAIL_VERIFICATION env var (default true).
	RequireEmailVerification bool

	// Session durations. Populated from config at startup.
	SessionTTL        time.Duration
	SessionRememberMe time.Duration

	// Policy defines password complexity rules for registration and password changes.
	Policy PasswordPolicy
}

// CheckHealth handles GET /health — pings Postgres and Redis, returns per-dependency status.
// Returns 200 if both are healthy, 503 if either is down.
func (h *AuthHandler) CheckHealth(w http.ResponseWriter, r *http.Request) {
	redisStatus := "ok"
	postgresStatus := "ok"

	if err := h.RS.CheckHealth(r.Context()); err != nil {
		logError(r, "redis health check failed", "error", err)
		redisStatus = "error"
	}
	if err := h.PS.CheckHealth(r.Context()); err != nil {
		logError(r, "postgres health check failed", "error", err)
		postgresStatus = "error"
	}

	w.Header().Set("Content-Type", "application/json")
	if redisStatus == "error" || postgresStatus == "error" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(struct {
		Postgres string `json:"postgres"`
		Redis    string `json:"redis"`
	}{postgresStatus, redisStatus})
}

// RegisterByEmail handles POST /register — email + password signup.
// Returns 201 with generic message, 400 for validation errors, 500 for server errors.
// Never reveals whether email already exists.
func (h *AuthHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	var registerInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registerInput); err != nil {
		logWarn(r, "failed to decode register input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	if msg := ValidateEmail(registerInput.Email); msg != "" {
		BadRequest(w, r, msg)
		return
	}

	if failures := h.Policy.Validate(registerInput.Password); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	if err := h.RL.Allow(r.Context(), "register:email:"+registerInput.Email, h.Policies.RegisterEmail); err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "register failed", "reason", "rate_limited", "email", registerInput.Email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	hashedPassword, err := HashPassword(registerInput.Password)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	userID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	err = h.PS.CreateUserByEmail(r.Context(), userID, registerInput.Email, hashedPassword)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Duplicate email -- return same 201 as real registration (no enumeration).
			// userID was generated above but never persisted; caller can't distinguish.
			logInfo(r, "register failed", "reason", "duplicate_email", "email", registerInput.Email)
			meta, _ := json.Marshal(struct {
				Email  string `json:"email"`
				Reason string `json:"reason"`
			}{registerInput.Email, "duplicate_email"})
			h.auditLog(r, nil, "user.register_failed", meta)
		} else {
			logError(r, "failed to create user", "error", err)
			InternalServerError(w, r, err)
			return
		}
	} else {
		logInfo(r, "user registered", "user_id", userID)
		h.auditLog(r, &userID, "user.registered", nil)

		// Send verification email when required. Non-fatal -- user can request resend later.
		if h.RequireEmailVerification {
			h.sendVerificationEmail(r, userID, registerInput.Email, "registration")
		}
	}

	Created(w, "if that email is available, your account has been created")
}

// LoginByEmail handles POST /login — email + password authentication.
// Returns 200 with user_id and CSRF token, 401 for bad credentials, 500 for server errors.
// Argon2id dummy-hash equalises timing when account doesn't exist.
func (h *AuthHandler) LoginByEmail(w http.ResponseWriter, r *http.Request) {
	var loginInput struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"remember_me"` // extends session to 30d instead of 24h
	}

	if err := json.NewDecoder(r.Body).Decode(&loginInput); err != nil {
		logWarn(r, "failed to decode login input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	email := strings.ToLower(loginInput.Email)

	// Validate before rate-limit -- keeps garbage strings out of Redis keys.
	// Both invalid email and missing password return generic 401 (no enumeration).
	if msg := ValidateEmail(email); msg != "" {
		Unauthorized(w, r, "invalid credentials")
		return
	}
	if loginInput.Password == "" {
		Unauthorized(w, r, "invalid credentials")
		return
	}

	if err := h.RL.Allow(r.Context(), "login:email:"+email, h.Policies.LoginEmail); err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "login failed", "reason", "rate_limited", "email", email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	user, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Always run dummy hash regardless of error type - equalises timing so neither
		// "user not found" nor "DB down" is distinguishable from a real login attempt.
		_, _ = VerifyPassword(loginInput.Password, dummyPasswordHash())
		if errors.Is(err, pgx.ErrNoRows) {
			logInfo(r, "login failed", "reason", "user_not_found", "email", email)
			meta, _ := json.Marshal(struct {
				Email  string `json:"email"`
				Reason string `json:"reason"`
			}{email, "user_not_found"})
			h.auditLog(r, nil, "user.login_failed", meta)
			Unauthorized(w, r, "invalid credentials")
		} else {
			logError(r, "failed to fetch user for login", "error", err)
			InternalServerError(w, r, err)
		}
		return
	}

	valid, err := VerifyPassword(loginInput.Password, user.PasswordHash)
	if err != nil {
		logError(r, "password verification failed", "error", err)
		InternalServerError(w, r, err)
		return
	}
	if !valid {
		logInfo(r, "login failed", "reason", "wrong_password", "user_id", user.ID)
		meta, _ := json.Marshal(struct {
			Reason string `json:"reason"`
		}{"wrong_password"})
		h.auditLog(r, &user.ID, "user.login_failed", meta)
		Unauthorized(w, r, "invalid credentials. If you need access, try resetting your password.")
		return
	}

	// Block login when email verification is required and not yet confirmed.
	if h.RequireEmailVerification && user.EmailConfirmedAt == nil {
		logInfo(r, "login failed", "reason", "email_not_verified", "user_id", user.ID)
		meta, _ := json.Marshal(struct {
			Reason string `json:"reason"`
		}{"email_not_verified"})
		h.auditLog(r, &user.ID, "user.login_failed", meta)
		Unauthorized(w, r, "email address not verified. Please check your inbox for a verification link.")
		return
	}

	token, tokenHash, err := GenerateToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	sessionDur := h.SessionTTL
	if loginInput.RememberMe {
		sessionDur = h.SessionRememberMe
	}
	expiresAt := time.Now().Add(sessionDur)
	ttl := int(sessionDur.Seconds())

	ipAddr := r.RemoteAddr
	userAgent := r.UserAgent()

	err = h.PS.CreateSession(r.Context(), sessionID, user.ID, tokenHash[:], csrfToken[:], expiresAt, &ipAddr, &userAgent)
	if err != nil {
		logError(r, "failed to create session in database", "error", err)
		InternalServerError(w, r, err)
		return
	}

	// Cache in Redis — non-fatal; Postgres is source of truth.
	err = h.RS.SetSession(r.Context(), base64.RawURLEncoding.EncodeToString(tokenHash[:]), store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		TokenHash: tokenHash[:],
		CSRFToken: csrfToken[:],
		ExpiresAt: expiresAt,
	}, ttl)
	if err != nil {
		logWarn(r, "failed to cache session in redis", "error", err)
	}

	SetSessionCookie(w, *token, expiresAt)
	meta, _ := json.Marshal(struct {
		RememberMe bool `json:"remember_me"`
	}{loginInput.RememberMe})
	h.auditLog(r, &user.ID, "user.login", meta)
	logInfo(r, "user logged in successfully", "user_id", user.ID, "remember_me", loginInput.RememberMe)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}{user.ID.String(), base64.RawURLEncoding.EncodeToString(csrfToken[:])})
}

// LogoutAll handles POST /logout-all — ends every session for the authenticated user.
// Deletes all sessions from Redis (non-fatal) then Postgres (fatal), clears cookie.
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		logError(r, "logout-all called without user_id in context")
		InternalServerError(w, r, errors.New("missing session context"))
		return
	}

	if err := h.RS.DeleteAllUserSessions(r.Context(), userID); err != nil {
		logWarn(r, "failed to delete all sessions from redis", "error", err)
	}

	if err := h.PS.DeleteAllUserSessions(r.Context(), userID); err != nil {
		logError(r, "failed to delete all sessions from database", "error", err)
		InternalServerError(w, r, err)
		return
	}

	ClearSessionCookie(w)
	h.auditLog(r, &userID, "user.logout_all", nil)
	logInfo(r, "user logged out of all devices", "user_id", userID)
	OK(w, "logged out of all devices")
}

// Logout handles POST /logout — ends authenticated session.
// Deletes from Redis (non-fatal) then Postgres (fatal), clears cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		logError(r, "logout called without user_id in context")
		InternalServerError(w, r, errors.New("missing session context"))
		return
	}

	tokenHash, ok := TokenHashFromContext(r.Context())
	if !ok {
		InternalServerError(w, r, errors.New("missing session context"))
		return
	}

	redisKey := base64.RawURLEncoding.EncodeToString(tokenHash)

	if err := h.RS.DeleteSession(r.Context(), redisKey, userID); err != nil {
		logWarn(r, "failed to delete session from redis", "error", err)
	}

	if err := h.PS.DeleteSession(r.Context(), tokenHash); err != nil {
		logError(r, "failed to delete session from database", "error", err)
		InternalServerError(w, r, err)
		return
	}

	ClearSessionCookie(w)
	h.auditLog(r, &userID, "user.logout", nil)
	logInfo(r, "user logged out", "user_id", userID)
	OK(w, "logged out")
}

// PasswordChange handles POST /password/change...updates the authenticated user's password.
// Verifies current password, re-hashes the new one, then invalidates all sessions.
// Returns 200 on success, 400 for invalid input, 401 for wrong current password, 500 for server errors.
func (h *AuthHandler) PasswordChange(w http.ResponseWriter, r *http.Request) {
	// Decode request body, expect current_password and new_password
	var pwdChangeInput struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdChangeInput); err != nil {
		logWarn(r, "failed to decode password change input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	if pwdChangeInput.CurrentPassword == "" {
		BadRequest(w, r, "current_password required")
		return
	}

	// Validate new pwd
	if failures := h.Policy.Validate(pwdChangeInput.NewPassword); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	// Pull user_id from context
	id, ok := UserIDFromContext(r.Context())
	if !ok {
		InternalServerError(w, r, errors.New("missing session context"))
		return
	}

	// Fetch stored hash for current password verification.
	passwordHash, err := h.PS.GetPwdHashByUserID(r.Context(), id)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Verify current_password against the stored hash.
	pwdMatch, err := VerifyPassword(pwdChangeInput.CurrentPassword, passwordHash)
	if err != nil {
		InternalServerError(w, r, err)
		return
	} else if !pwdMatch {
		logWarn(r, "password change failed: wrong current password", "user_id", id)
		h.auditLog(r, &id, "user.password_change_failed", nil)
		Unauthorized(w, r, "invalid credentials")
		return
	}

	// Hash new_password with HashPassword.
	newPassword, err := HashPassword(pwdChangeInput.NewPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Update the hash in Postgres with UpdateUserPassword.
	err = h.PS.UpdateUserPassword(r.Context(), id, newPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Delete all sessions from Redis (non-fatal, log warn on error).
	err = h.RS.DeleteAllUserSessions(r.Context(), id)
	if err != nil {
		logWarn(r, "failed to delete all sessions from redis", "error", err)
	}

	// Delete all sessions from Postgres (fatal, return 500 on error).
	err = h.PS.DeleteAllUserSessions(r.Context(), id)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Clear the session cookie; current session is now invalid.
	ClearSessionCookie(w)
	h.auditLog(r, &id, "user.password_changed", nil)
	logInfo(r, "user changed password", "user_id", id)
	OK(w, "password updated")
}

// PasswordReset handles POST /auth/password/reset -- initiates the reset flow for a given email.
func (h *AuthHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	// Get email from req
	var pwdResetInput struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdResetInput); err != nil {
		BadRequest(w, r, "invalid request")
		return
	}

	email := strings.ToLower(pwdResetInput.Email)

	// Validate before rate-limit -- keeps garbage strings out of Redis keys.
	if msg := ValidateEmail(email); msg != "" {
		BadRequest(w, r, msg)
		return
	}

	err := h.RL.Allow(r.Context(), "reset:email:"+email, h.Policies.PasswordReset)
	if err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "password reset failed", "reason", "rate_limited", "email", email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	const resetMsg = "if that email exists, a reset link has been sent"

	// Get user
	user, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Generic 200 -- no enumeration (caller cannot learn whether email exists)
		logInfo(r, "password reset failed", "reason", "user_not_found", "email", email)
		OK(w, resetMsg)
		return
	}

	// Gen token
	token, tokenHash, err := GenerateToken()
	if err != nil {
		logError(r, "failed to generate password reset token", "error", err)
		OK(w, resetMsg)
		return
	}

	// Create id for token
	tokenID, err := uuid.NewV7()
	if err != nil {
		logError(r, "failed to generate token id", "error", err)
		OK(w, resetMsg)
		return
	}

	// Add token to pg db, expires in 1 hour
	err = h.PS.CreateToken(r.Context(), tokenID, user.ID, "password_reset", tokenHash[:], time.Now().Add(1*time.Hour))
	if err != nil {
		logError(r, "failed to persist password reset token", "error", err, "user_id", user.ID)
		OK(w, resetMsg)
		return
	}

	// Build vars from available user fields; omit nil pointers.
	vars := map[string]string{}
	if user.FirstName != nil {
		vars["firstName"] = *user.FirstName
	}
	if user.LastName != nil {
		vars["lastName"] = *user.LastName
	}

	// Send pwd reset
	err = h.ML.SendPasswordReset(r.Context(), *user.Email, base64.RawURLEncoding.EncodeToString(token[:]), 1*time.Hour, vars)
	if err != nil {
		logError(r, "failed to send password reset email", "error", err, "user_id", user.ID)
		OK(w, resetMsg)
		return
	}

	h.auditLog(r, &user.ID, "user.password_reset_requested", nil)
	logInfo(r, "password reset email sent", "user_id", user.ID)
	OK(w, resetMsg)
}

// PasswordConfirm handles POST /auth/password/confirm -- completes the reset using the token from the email link.
func (h *AuthHandler) PasswordConfirm(w http.ResponseWriter, r *http.Request) {
	// Decode request body, expect token and new_password
	var pwdConfirmInput struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdConfirmInput); err != nil {
		logWarn(r, "failed to decode reset password confirm input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	// Validate new pwd
	if failures := h.Policy.Validate(pwdConfirmInput.NewPassword); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	// Decode and hash token
	tokenStr, err := base64.RawURLEncoding.DecodeString(pwdConfirmInput.Token)
	if err != nil {
		BadRequest(w, r, "invalid reset token")
		return
	}
	tokenHash := sha256.Sum256(tokenStr)

	// Use hashed token to consume token in db
	userID, err := h.PS.ConsumeToken(r.Context(), tokenHash[:], "password_reset")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "password reset failed: invalid or expired token")
			h.auditLog(r, nil, "user.password_reset_failed", nil)
			BadRequest(w, r, "invalid or expired reset token")
			return
		}
		logError(r, "failed to consume reset token", "error", err)
		InternalServerError(w, r, err)
		return
	}

	// Hash new_password with HashPassword.
	newPassword, err := HashPassword(pwdConfirmInput.NewPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Update the hash in Postgres with UpdateUserPassword.
	err = h.PS.UpdateUserPassword(r.Context(), userID, newPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Delete all sessions from Redis (non-fatal, log warn on error).
	err = h.RS.DeleteAllUserSessions(r.Context(), userID)
	if err != nil {
		logWarn(r, "failed to delete all sessions from redis", "error", err)
	}

	// Delete all sessions from Postgres (fatal, return 500 on error).
	err = h.PS.DeleteAllUserSessions(r.Context(), userID)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Set email confirmed. reset proves ownership so non-fatal if fails
	if err = h.PS.SetEmailConfirmedAt(r.Context(), userID); err != nil {
		logWarn(r, "failed to set email_confirmed_at after password reset", "error", err, "user_id", userID)
	}

	// No ClearSessionCookie -- reset flow is unauthenticated; caller has no session cookie.
	// Sessions already purged above. Any stale cookie from a prior login will 401 on next use.
	h.auditLog(r, &userID, "user.password_reset_completed", nil)
	logInfo(r, "user reset password", "user_id", userID)
	OK(w, "password updated")
}

// sendVerificationEmail generates a token, stores it, and mails the verification link.
// trigger identifies the source: "registration" or "resend". Non-fatal: errors are logged but never fail the enclosing request.
func (h *AuthHandler) sendVerificationEmail(r *http.Request, userID uuid.UUID, email, trigger string) {
	verifyToken, verifyTokenHash, err := GenerateToken()
	if err != nil {
		logWarn(r, "failed to generate verification token", "error", err)
		return
	}

	tokenID, err := uuid.NewV7()
	if err != nil {
		logWarn(r, "failed to generate verification token id", "error", err)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if err = h.PS.CreateToken(r.Context(), tokenID, userID, "email_verification", verifyTokenHash[:], expiresAt); err != nil {
		logWarn(r, "failed to store verification token", "error", err)
		return
	}

	tokenStr := base64.RawURLEncoding.EncodeToString(verifyToken[:])
	if err = h.ML.SendEmailVerification(r.Context(), email, tokenStr, 24*time.Hour, map[string]string{}); err != nil {
		logWarn(r, "failed to send verification email", "error", err)
		return
	}
	meta, _ := json.Marshal(struct {
		Trigger string `json:"trigger"`
	}{trigger})
	h.auditLog(r, &userID, "user.email_verification_requested", meta)
}

// ResendVerificationEmail handles POST /resend/verification-email -- re-sends the verification link.
// Rate-limited per email. Returns generic 200 regardless of whether the email exists
// or is already confirmed (no enumeration).
func (h *AuthHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logWarn(r, "failed to decode resend verification email input", "error", err)
		BadRequest(w, r, "invalid request")
		return
	}

	email := strings.ToLower(input.Email)

	if errMsg := ValidateEmail(email); errMsg != "" {
		BadRequest(w, r, errMsg)
		return
	}

	const resendMsg = "if that email is registered and unverified, a verification link has been sent"

	if err := h.RL.Allow(r.Context(), "resend:email:"+email, h.Policies.ResendVerification); err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "resend verification failed", "reason", "rate_limited", "email", email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	user, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Generic response for both not-found and DB errors -- no enumeration.
		if !errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "failed to fetch user for resend verification", "error", err)
		} else {
			logInfo(r, "resend verification failed", "reason", "user_not_found", "email", email)
		}
		OK(w, resendMsg)
		return
	}

	if user.EmailConfirmedAt != nil {
		logInfo(r, "resend verification failed", "reason", "already_confirmed", "user_id", user.ID)
		OK(w, resendMsg)
		return
	}

	// sendVerificationEmail handles its own logging and audit.
	h.sendVerificationEmail(r, user.ID, *user.Email, "resend")
	OK(w, resendMsg)
}

// VerifyEmail handles POST /verify/email -- consumes a single-use token from
// the verification link and sets email_confirmed_at for the associated user.
// Returns 200 on success, 400 for an invalid/expired token, 500 for DB errors.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logWarn(r, "failed to decode verify email input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}
	if input.Token == "" {
		BadRequest(w, r, "token is required")
		return
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil {
		logWarn(r, "failed to decode verification token", "error", err)
		BadRequest(w, r, "invalid token")
		return
	}

	tokenHash := sha256.Sum256(rawToken)
	userID, err := h.PS.ConsumeToken(r.Context(), tokenHash[:], "email_verification")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "invalid or expired verification token")
			BadRequest(w, r, "invalid or expired token")
			return
		}
		logError(r, "failed to consume verification token", "error", err)
		InternalServerError(w, r, err)
		return
	}

	if err = h.PS.SetEmailConfirmedAt(r.Context(), userID); err != nil {
		logError(r, "failed to set email_confirmed_at", "error", err, "user_id", userID)
		InternalServerError(w, r, err)
		return
	}

	h.auditLog(r, &userID, "user.email_verified", nil)
	logInfo(r, "email verified", "user_id", userID)
	OK(w, "email verified")
}
