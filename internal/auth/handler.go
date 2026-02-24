// handler.go -- HTTP handlers for all /auth/* endpoints.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
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
}

// RateLimiter checks and records rate limit state for a given key and policy.
// Satisfied by *store.RedisRateLimiter -- defined here per Go convention.
type RateLimiter interface {
	// Allow checks whether the action is within policy, records the attempt.
	// Returns nil if allowed; non-nil error if locked out or threshold exceeded.
	Allow(ctx context.Context, key string, policy store.RateLimit) error
}

// dummyPasswordHash is a precomputed Argon2id hash for timing attack mitigation.
// When a user doesn't exist, verify against this so both paths take equal time (~100ms).
const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$kC6C6jqLzC0JLlJgXhHbKMhLLpVvLJLLQw/IqT9ZYPU"

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS Store
	RS SessionCache
	RL RateLimiter
	ML mail.Mailer
}

// RegisterByEmail handles POST /register — email + password signup.
// Returns 201 with user_id, 400 for validation errors, 500 for server errors.
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

	if invalidMsg := ValidatePassword(registerInput.Password); invalidMsg != "" {
		BadRequest(w, r, invalidMsg)
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
			logInfo(r, "registration attempted with existing email")
		} else {
			logError(r, "failed to create user", "error", err)
			InternalServerError(w, r, err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp, _ := json.Marshal(map[string]string{"user_id": userID.String()})
	w.Write(resp)
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

	// Invalid email or missing password -- both return generic 401 (no enumeration).
	if msg := ValidateEmail(loginInput.Email); msg != "" {
		Unauthorized(w, r, "invalid credentials")
		return
	}
	if loginInput.Password == "" {
		Unauthorized(w, r, "invalid credentials")
		return
	}

	user, err := h.PS.GetUserByEmail(r.Context(), loginInput.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Run dummy hash to equalise timing with found-user path.
			VerifyPassword(loginInput.Password, dummyPasswordHash)
			logInfo(r, "login attempted with non-existent email")
		} else {
			logError(r, "failed to fetch user for login", "error", err)
		}
		Unauthorized(w, r, "invalid credentials")
		return
	}

	valid, err := VerifyPassword(loginInput.Password, user.PasswordHash)
	if err != nil {
		logError(r, "password verification failed", "error", err)
		InternalServerError(w, r, err)
		return
	}
	if !valid {
		logInfo(r, "login attempted with incorrect password", "user_id", user.ID)
		Unauthorized(w, r, "invalid credentials")
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

	// 24h default, 30d if remember_me.
	var expiresAt time.Time
	var ttl int
	if loginInput.RememberMe {
		ttl = 30 * 24 * 60 * 60
		expiresAt = time.Now().Add(30 * 24 * time.Hour)
	} else {
		ttl = 24 * 60 * 60
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	// RemoteAddr includes port — INET column expects bare IP.
	ipAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipAddr = r.RemoteAddr
	}
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
	logInfo(r, "user logged in successfully", "user_id", user.ID, "remember_me", loginInput.RememberMe)

	csrfTokenEncoded := base64.RawURLEncoding.EncodeToString(csrfToken[:])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"user_id":"` + user.ID.String() + `","csrf_token":"` + csrfTokenEncoded + `"}`))
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
	logInfo(r, "user logged out", "user_id", userID)
	OK(w, "logged out")
}

// LoginEmailPolicy is the rate limit applied per email address on login attempts.
// Applied in LoginByEmail before any DB work -- rejected requests never reach Argon2id.
var LoginEmailPolicy = store.RateLimit{
	MaxAttempts: 10,
	Window:      10 * time.Minute,
	LockoutTTL:  15 * time.Minute,
}

// PasswordResetPolicy is the rate limit applied per email address on password reset requests.
// Keyed on "reset:email:<email>" before user lookup -- intentionally pre-lookup to prevent
// timing-based enumeration (post-lookup keying would reveal whether an email exists).
var PasswordResetPolicy = store.RateLimit{
	MaxAttempts: 3,
	Window:      1 * time.Hour,
	LockoutTTL:  1 * time.Hour,
}

// TODO: LoginByEmail -- add h.RL.Allow(ctx, "login:email:"+email, LoginEmailPolicy) after input
// decode and before GetUserByEmail. Return 429 on ErrRateLimitExceeded.

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
	if invalidMsg := ValidatePassword(pwdChangeInput.NewPassword); invalidMsg != "" {
		BadRequest(w, r, invalidMsg)
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

	if msg := ValidateEmail(email); msg != "" {
		BadRequest(w, r, msg)
		return
	}

	// Check if email rate-limited, if so, err != nil, return
	err := h.RL.Allow(r.Context(), fmt.Sprintf("reset:email:%s", email), PasswordResetPolicy)
	if err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "password reset rate limited", "email", email)
			w.WriteHeader(http.StatusTooManyRequests)
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
		logInfo(r, "password reset requested for unknown email")
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

	// Send pwd reset
	err = h.ML.SendPasswordReset(r.Context(), *user.Email, base64.RawURLEncoding.EncodeToString(token[:]))
	if err != nil {
		logError(r, "failed to send password reset email", "error", err, "user_id", user.ID)
		OK(w, resetMsg)
		return
	}

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
	if invalidMsg := ValidatePassword(pwdConfirmInput.NewPassword); invalidMsg != "" {
		BadRequest(w, r, invalidMsg)
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
	logInfo(r, "user reset password", "user_id", userID)
	OK(w, "password updated")
}
