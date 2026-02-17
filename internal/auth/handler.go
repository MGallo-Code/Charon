// Package auth contains HTTP handlers and core authentication logic.
//
// handler.go -- HTTP handlers for all /auth/* endpoints.
// Registers routes on a chi router, returns JSON responses.
// Delegates to session, password, and csrf packages for logic.
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
	// GetSession retrieves a cached session by its token hash.
	// Returns nil if session not found or if Redis unavailable.
	GetSession(ctx context.Context, tokenHash string) (*store.CachedSession, error)

	// SetSession caches a session in Redis with the given TTL (in seconds).
	SetSession(ctx context.Context, tokenHash string, sessionData store.Session, ttl int) error
}

// Store defines database operations needed by auth handlers.
// Satisfied by *store.PostgresStore — defined here (at consumer) per Go convention.
type Store interface {
	// CreateUserByEmail inserts a new user with email and hashed password.
	CreateUserByEmail(ctx context.Context, uuid uuid.UUID, email, passwordHash string) error

	// GetUserByEmail fetches a user by their email address for login verification.
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)

	// CreateSession inserts a new session row with token hash and CSRF token.
	CreateSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error

	// GetSessionByTokenHash fetches a valid (non-expired) session by its token hash.
	// Returns pgx.ErrNoRows if not found or expired.
	GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*store.Session, error)
}

// dummyPasswordHash is a precomputed Argon2id hash used for timing attack mitigation.
// When a user doesn't exist, we verify against this dummy hash to ensure the same
// computation time as verifying a real user's password (~100ms). This prevents attackers
// from enumerating valid emails by measuring response times.
//
// Hash of the string "dummy-password-for-timing-attack-mitigation" with random salt.
// Format: $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$kC6C6jqLzC0JLlJgXhHbKMhLLpVvLJLLQw/IqT9ZYPU"

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
// Inject PostgresStore and RedisStore at initialization, then share across all handlers.
type AuthHandler struct {
	PS Store
	RS SessionCache
}

// RegisterByEmail handles POST /auth/register for email + password signup.
// Validates input, hashes password with Argon2id, and creates user in database.
// Returns 201 with user_id on success, 400 for validation errors, 500 for server errors.
// Does not reveal whether email already exists (returns generic 500 to prevent enumeration).
func (h *AuthHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	// Define expected JSON input structure
	var registerInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Parse and validate JSON request body
	err := json.NewDecoder(r.Body).Decode(&registerInput)
	if err != nil {
		logWarn(r, "failed to decode register input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	// Validate email presence and length (RFC 5321: local@domain, min ~5, max 254)
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

	// Validate email format using stdlib mail parser
	if _, err := mail.ParseAddress(registerInput.Email); err != nil {
		BadRequest(w, r, "Invalid email format")
		return
	}

	// Validate password presence and length (min 6, max 128 to prevent DoS via Argon2id)
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

	// Hash password with Argon2id (GPU-resistant, OWASP recommended)
	hashedPassword, err := HashPassword(registerInput.Password)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Attempt to generate user ID
	userID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Attempt to insert user w/ pg store
	err = h.PS.CreateUserByEmail(r.Context(), userID, registerInput.Email, hashedPassword)
	if err != nil {
		// Check if error triggered Postgres unique constraint violation (duplicate email)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Duplicate email — log as info, not error (expected user behavior)
			logInfo(r, "registration attempted with existing email")
		} else {
			// Real database failure — log as error for alerting
			logError(r, "failed to create user", "error", err)
		}
		// Return generic error (DONT REVEAL IF EMAIL EXISTS OR NOT)
		InternalServerError(w, r, err)
		return
	}

	// Success! Return 201 with new user ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp, _ := json.Marshal(map[string]string{"user_id": userID.String()})
	w.Write(resp)
}

// LoginByEmail handles POST /auth/login for email + password authentication.
// Validates credentials, creates session in Postgres + Redis, sets secure cookie.
// Returns 200 with user_id and CSRF token on success, 401 for invalid credentials, 500 for server errors.
// Uses generic error messages to prevent user enumeration (timing attacks mitigated by Argon2id).
func (h *AuthHandler) LoginByEmail(w http.ResponseWriter, r *http.Request) {
	// Define expected JSON input structure
	var loginInput struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"remember_me"` // Optional: extends session to 30 days instead of 24 hours
	}

	// Parse and validate JSON request body
	err := json.NewDecoder(r.Body).Decode(&loginInput)
	if err != nil {
		logWarn(r, "failed to decode login input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	// Validate email and password presence (format validation unnecessary for login)
	if loginInput.Email == "" || loginInput.Password == "" {
		Unauthorized(w, r, "invalid credentials")
		return
	}

	// Fetch user from database by email
	user, err := h.PS.GetUserByEmail(r.Context(), loginInput.Email)
	if err != nil {
		// User not found or database error — return generic "invalid credentials"
		if errors.Is(err, pgx.ErrNoRows) {
			// User doesn't exist — run dummy hash verification to prevent timing attacks
			// This ensures both paths (user exists vs doesn't exist) take equal time (~100ms)
			VerifyPassword(loginInput.Password, dummyPasswordHash)
			logInfo(r, "login attempted with non-existent email")
		} else {
			// Real database error — log as error for alerting
			logError(r, "failed to fetch user for login", "error", err)
		}
		// Always return same generic message (no user enumeration)
		Unauthorized(w, r, "invalid credentials")
		return
	}

	// Verify password using constant-time comparison (mitigates timing attacks)
	valid, err := VerifyPassword(loginInput.Password, user.PasswordHash)
	if err != nil {
		// Hash format error or other verification failure
		logError(r, "password verification failed", "error", err)
		InternalServerError(w, r, err)
		return
	}
	if !valid {
		// Wrong password — log as info (expected behavior)
		logInfo(r, "login attempted with incorrect password", "user_id", user.ID)
		Unauthorized(w, r, "invalid credentials")
		return
	}

	// Authentication successful! Create session.

	// Generate cryptographically random session token + SHA-256 hash
	token, tokenHash, err := GenerateToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Generate cryptographically random CSRF token for state-changing requests
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Generate UUID v7 for session ID
	sessionID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Calculate session expiry (24h default, 30d if remember_me)
	var expiresAt time.Time
	var ttl int // TTL in seconds for Redis and cookie MaxAge
	if loginInput.RememberMe {
		ttl = 30 * 24 * 60 * 60 // 30 days
		expiresAt = time.Now().Add(30 * 24 * time.Hour)
	} else {
		ttl = 24 * 60 * 60 // 24 hours
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	// Extract IP address and user agent for audit logging
	// RemoteAddr includes port (e.g., "192.168.65.1:46294"), but INET column expects just IP
	ipAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If no port, use RemoteAddr as-is (shouldn't happen but be defensive)
		ipAddr = r.RemoteAddr
	}
	userAgent := r.UserAgent()

	// Store session in PostgreSQL (durable, source of truth)
	// Convert array pointers to slices for storage
	err = h.PS.CreateSession(r.Context(), sessionID, user.ID, tokenHash[:], csrfToken[:], expiresAt, &ipAddr, &userAgent)
	if err != nil {
		logError(r, "failed to create session in database", "error", err)
		InternalServerError(w, r, err)
		return
	}

	// Cache session in Redis (fast path for validation, ~0.1ms vs ~1-5ms for Postgres)
	// Convert token hash to string (Redis key) and session data struct
	err = h.RS.SetSession(r.Context(), base64.RawURLEncoding.EncodeToString(tokenHash[:]), store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		TokenHash: tokenHash[:],
		CSRFToken: csrfToken[:],
		ExpiresAt: expiresAt,
	}, ttl)
	if err != nil {
		// Redis cache failure is non-fatal (Postgres is source of truth)
		// Log as warning but continue — session validation will fall back to Postgres
		logWarn(r, "failed to cache session in redis", "error", err)
	}

	// Set secure session cookie (HttpOnly, Secure, SameSite=Lax, __Host- prefix)
	// Dereference token pointer to get array value, pass expiresAt time
	SetSessionCookie(w, *token, expiresAt)

	// Log successful login for audit trail
	logInfo(r, "user logged in successfully", "user_id", user.ID, "remember_me", loginInput.RememberMe)

	// Return success with user ID and CSRF token (base64-encoded for client to send back in headers)
	csrfTokenEncoded := base64.RawURLEncoding.EncodeToString(csrfToken[:])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, _ := json.Marshal(map[string]string{
		"user_id":    user.ID.String(),
		"csrf_token": csrfTokenEncoded,
	})
	w.Write(resp)
}
