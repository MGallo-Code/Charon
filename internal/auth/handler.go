// handler.go -- HTTP handlers for all /auth/* endpoints.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"time"

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

	// GetUserByID fetches user by UUID. Used when user_id is in context but email is not.
	GetUserByID(ctx context.Context, id uuid.UUID) (*store.User, error)

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
}

// dummyPasswordHash is a precomputed Argon2id hash for timing attack mitigation.
// When a user doesn't exist, verify against this so both paths take equal time (~100ms).
const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$kC6C6jqLzC0JLlJgXhHbKMhLLpVvLJLLQw/IqT9ZYPU"

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS Store
	RS SessionCache
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

	// Validate email — RFC 5321: min ~5 chars, max 254.
	if registerInput.Email == "" {
		BadRequest(w, r, "No email provided")
		return
	}
	emailLen := len(registerInput.Email)
	if emailLen < 5 {
		BadRequest(w, r, "Email too short!")
		return
	}
	if emailLen > 254 {
		BadRequest(w, r, "Email too long!")
		return
	}
	if _, err := mail.ParseAddress(registerInput.Email); err != nil {
		BadRequest(w, r, "Invalid email format")
		return
	}

	// Validate password — min 6, max 128 to prevent DoS via Argon2id.
	if registerInput.Password == "" {
		BadRequest(w, r, "No password provided!")
		return
	}
	pwdLen := len(registerInput.Password)
	if pwdLen < 6 {
		BadRequest(w, r, "Password too short!")
		return
	}
	if pwdLen > 128 {
		BadRequest(w, r, "Password too long!")
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
			// Duplicate email — expected behavior, not a server fault.
			logInfo(r, "registration attempted with existing email")
		} else {
			logError(r, "failed to create user", "error", err)
		}
		// Generic response — don't reveal whether email exists.
		InternalServerError(w, r, err)
		return
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

	if loginInput.Email == "" || loginInput.Password == "" {
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
	resp, _ := json.Marshal(map[string]string{
		"user_id":    user.ID.String(),
		"csrf_token": csrfTokenEncoded,
	})
	w.Write(resp)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"logged out of all devices"}`))
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
		logError(r, "logout called without token_hash in context")
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"logged out"}`))
}
