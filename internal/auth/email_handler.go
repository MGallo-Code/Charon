// email_handler.go -- HTTP handlers for email-based auth: register, login, logout, logout-all.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// dummyPasswordHash generates a live Argon2id hash at startup for timing attack mitigation.
// When a user doesn't exist, verify against this so both paths take equal time (~100ms).
// Generated from live constants so it tracks any future parameter changes in password.go.
var dummyPasswordHash = sync.OnceValue(func() string {
	h, _ := HashPassword("dummy")
	return h
})

// RegisterByEmail handles POST /register — email + password signup.
// Returns 201 with generic message, 400 for validation errors, 500 for server errors.
// Never reveals whether email already exists.
func (h *AuthHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	var registerInput struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		CaptchaToken string `json:"captcha_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registerInput); err != nil {
		logWarn(r, "failed to decode register input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	email := strings.ToLower(registerInput.Email)

	if msg := ValidateEmail(email); msg != "" {
		BadRequest(w, r, msg)
		return
	}

	if failures := h.Policy.Validate(registerInput.Password); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	if !h.checkCaptcha(w, r, registerInput.CaptchaToken, h.CaptchaCP.Register) {
		return
	}

	if err := h.RL.Allow(r.Context(), "register:email:"+email, h.Policies.RegisterEmail); err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "register failed", "reason", "rate_limited", "email", email)
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

	err = h.PS.CreateUserByEmail(r.Context(), userID, email, hashedPassword)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Duplicate email -- return same 201 as real registration (no enumeration).
			// userID was generated above but never persisted; caller can't distinguish.
			logInfo(r, "register failed", "reason", "duplicate_email", "email", email)
			h.auditLog(r, nil, "user.register_failed", marshalMeta(struct {
				Email  string `json:"email"`
				Reason string `json:"reason"`
			}{email, "duplicate_email"}))
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
			h.sendVerificationEmail(r, userID, email, "registration")
		}
	}

	Created(w, "if that email is available, your account has been created")
}

// LoginByEmail handles POST /login — email + password authentication.
// Returns 200 with user_id and CSRF token, 401 for bad credentials, 500 for server errors.
// Argon2id dummy-hash equalises timing when account doesn't exist.
func (h *AuthHandler) LoginByEmail(w http.ResponseWriter, r *http.Request) {
	var loginInput struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		RememberMe   bool   `json:"remember_me"` // extends session to 30d instead of 24h
		CaptchaToken string `json:"captcha_token"`
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

	if !h.checkCaptcha(w, r, loginInput.CaptchaToken, h.CaptchaCP.Login) {
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
			h.auditLog(r, nil, "user.login_failed", marshalMeta(struct {
				Email  string `json:"email"`
				Reason string `json:"reason"`
			}{email, "user_not_found"}))
			Unauthorized(w, r, "invalid credentials")
		} else {
			logError(r, "failed to fetch user for login", "error", err)
			InternalServerError(w, r, err)
		}
		return
	}

	if user.PasswordHash == nil {
		// OAuth-only user -- equalize timing then reject.
		_, _ = VerifyPassword(loginInput.Password, dummyPasswordHash())
		Unauthorized(w, r, "invalid credentials. If you need access, try resetting your password.")
		return
	}
	valid, err := VerifyPassword(loginInput.Password, *user.PasswordHash)
	if err != nil {
		logError(r, "password verification failed", "error", err)
		InternalServerError(w, r, err)
		return
	}
	if !valid {
		logInfo(r, "login failed", "reason", "wrong_password", "user_id", user.ID)
		h.auditLog(r, &user.ID, "user.login_failed", marshalMeta(struct {
			Reason string `json:"reason"`
		}{"wrong_password"}))
		Unauthorized(w, r, "invalid credentials. If you need access, try resetting your password.")
		return
	}

	// Block login when email verification is required and not yet confirmed.
	if h.RequireEmailVerification && user.EmailConfirmedAt == nil {
		logInfo(r, "login failed", "reason", "email_not_verified", "user_id", user.ID)
		h.auditLog(r, &user.ID, "user.login_failed", marshalMeta(struct {
			Reason string `json:"reason"`
		}{"email_not_verified"}))
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
	h.auditLog(r, &user.ID, "user.login", marshalMeta(struct {
		RememberMe bool `json:"remember_me"`
	}{loginInput.RememberMe}))
	logInfo(r, "user logged in successfully", "user_id", user.ID, "remember_me", loginInput.RememberMe)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}{user.ID.String(), base64.RawURLEncoding.EncodeToString(csrfToken[:])})
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
