// email_handler_test.go -- unit tests for RegisterByEmail, LoginByEmail, Logout, and LogoutAll.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// assertClearedSessionCookie checks __Host-session cookie has MaxAge=-1 and empty value.
func assertClearedSessionCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "__Host-session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge: expected -1 (cleared), got %d", c.MaxAge)
			}
			if c.Value != "" {
				t.Errorf("cookie Value: expected empty, got %q", c.Value)
			}
			return
		}
	}
	t.Error("__Host-session cookie not found in response")
}

// --- RegisterByEmail ---

func TestRegisterByEmail(t *testing.T) {
	// -- Input validation (400s) --

	t.Run("empty request body returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// Body w// no request
		r := httptest.NewRequest(http.MethodPost, "/auth/register", nil)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// Body w// invalid JSON
		body := strings.NewReader(`{not valid json}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("missing email returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// Body w// pwd, no email
		body := strings.NewReader(`{"password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "No email provided")
	})

	t.Run("email too short returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// Body w// email too short (< 5 chars)
		body := strings.NewReader(`{"email":"a@b","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Email too short!")
	})

	t.Run("email too long returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// Body w// email too long (> 254 chars)
		longEmail := strings.Repeat("a", 250) + "@test.com" // 259 chars
		body := strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"validpassword123"}`, longEmail))
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Email too long!")
	})

	t.Run("invalid email format returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &testutil.MockStore{}}

		// No @ sign — fails format check
		body := strings.NewReader(`{"email":"notanemail","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Invalid email format")
	})

	// -- Happy path (201) --

	t.Run("valid email and password returns Created", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RL: &testutil.MockRateLimiter{},
		}

		// Body w// valid email and password
		body := strings.NewReader(`{"email":"valid@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertCreated(t, w)
	})

	// -- Rate limiting (429) --

	t.Run("rate limited registration returns TooManyRequests", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RL: &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded},
		}

		body := strings.NewReader(`{"email":"valid@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertTooManyRequests(t, w)
	})

	// -- CAPTCHA (400) --

	t.Run("captcha required, token rejected returns 400", func(t *testing.T) {
		h := AuthHandler{
			PS:        &testutil.MockStore{},
			CV:        &testutil.MockCaptchaVerifier{VerifyErr: errors.New("bad token")},
			CaptchaCP: CaptchaPolicies{Register: true},
		}
		body := strings.NewReader(`{"email":"test@example.com","password":"validpassword123","captcha_token":"bad"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertBadRequest(t, w, "captcha verification failed")
	})

	t.Run("captcha required, token valid proceeds past captcha check", func(t *testing.T) {
		h := AuthHandler{
			PS:        &testutil.MockStore{},
			RL:        &testutil.MockRateLimiter{},
			ML:        &testutil.MockMailer{},
			CV:        &testutil.MockCaptchaVerifier{},
			CaptchaCP: CaptchaPolicies{Register: true},
		}
		body := strings.NewReader(`{"email":"test@example.com","password":"validpassword123","captcha_token":"good"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertCreated(t, w)
	})

	// -- Database errors (500) --

	t.Run("duplicate email returns Created (no enumeration)", func(t *testing.T) {
		// Duplicate key error (23505) must return the same 201 as a real registration.
		// Returning 500 would let an attacker distinguish taken vs. available emails.
		pgErr := &pgconn.PgError{Code: "23505"}
		h := AuthHandler{
			PS: &testutil.MockStore{CreateUserErr: fmt.Errorf("creating user by email: %w", pgErr)},
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"existing@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertCreated(t, w)
	})

	t.Run("generic database error returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{CreateUserErr: errors.New("database connection failed")},
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		h.RegisterByEmail(w, r)

		assertInternalServerError(t, w)
	})
}

// --- LoginByEmail ---

func TestLoginByEmail(t *testing.T) {
	// Shared test user with known password for auth path tests.
	testPassword := "password123"
	testHash, _ := HashPassword(testPassword)
	testEmail := "test@example.com"
	testUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: &testHash,
	}

	// -- Input validation (400s) --

	t.Run("empty request body returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// Invalid JSON body
		body := strings.NewReader(`{not valid json}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("missing email returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), RL: &testutil.MockRateLimiter{}}

		body := strings.NewReader(`{"password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	t.Run("missing password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), RL: &testutil.MockRateLimiter{}}

		body := strings.NewReader(`{"email":"test@example.com"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Rate limiting (429, 500) --

	t.Run("rate limited returns 429", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("status: expected 429, got %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type: expected application/json, got %q", ct)
		}
		// No session cookie on rate-limited request.
		for _, c := range w.Result().Cookies() {
			if c.Name == "__Host-session" {
				t.Error("session cookie should not be set on rate-limited request")
			}
		}
	})

	t.Run("rate limiter error returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{AllowErr: errors.New("redis unavailable")},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertInternalServerError(t, w)
	})

	// -- CAPTCHA (400) --

	t.Run("captcha required, token rejected returns 400", func(t *testing.T) {
		h := AuthHandler{
			PS:        &testutil.MockStore{},
			RS:        testutil.NewMockCache(),
			CV:        &testutil.MockCaptchaVerifier{VerifyErr: errors.New("bad token")},
			CaptchaCP: CaptchaPolicies{Login: true},
		}
		body := strings.NewReader(`{"email":"test@example.com","password":"password123","captcha_token":"bad"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertBadRequest(t, w, "captcha verification failed")
	})

	t.Run("captcha required, token valid proceeds past captcha check", func(t *testing.T) {
		// Empty store -- user not found returns 401, confirming captcha didn't block.
		h := AuthHandler{
			PS:        &testutil.MockStore{},
			RS:        testutil.NewMockCache(),
			RL:        &testutil.MockRateLimiter{},
			CV:        &testutil.MockCaptchaVerifier{},
			CaptchaCP: CaptchaPolicies{Login: true},
		}
		body := strings.NewReader(`{"email":"test@example.com","password":"password123","captcha_token":"good"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Authentication failures (401s) --

	t.Run("non-existent user returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{GetUserByEmailErr: pgx.ErrNoRows},
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"nonexistent@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	t.Run("wrong password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(testUser),
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"wrongpassword"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials. If you need access, try resetting your password.")
	})

	// -- Database/system errors (500s) --

	t.Run("database error when fetching user returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{GetUserByEmailErr: errors.New("database connection failed")},
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		// Non-ErrNoRows DB errors return 500
		assertInternalServerError(t, w)
	})

	t.Run("malformed password hash returns InternalServerError", func(t *testing.T) {
		badHash := "not-a-valid-argon2id-hash"
		badUser := &store.User{
			ID:           testUser.ID,
			Email:        testUser.Email,
			PasswordHash: &badHash,
		}
		h := AuthHandler{
			PS: testutil.NewMockStore(badUser),
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("session creation failure returns InternalServerError", func(t *testing.T) {
		ps := testutil.NewMockStore(testUser)
		ps.CreateSessionErr = errors.New("database write failed")
		h := AuthHandler{
			PS: ps,
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertInternalServerError(t, w)
	})

	// -- Happy path (200) --

	t.Run("valid credentials returns OK with user_id and csrf_token", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(testUser),
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertOK(t, w)
		assertSessionCookie(t, w)
	})

	t.Run("valid credentials with remember_me sets extended TTL", func(t *testing.T) {
		h := AuthHandler{
			PS:                testutil.NewMockStore(testUser),
			RS:                testutil.NewMockCache(),
			RL:                &testutil.MockRateLimiter{},
			SessionTTL:        24 * time.Hour,
			SessionRememberMe: 720 * time.Hour,
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123","remember_me":true}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertOK(t, w)
		assertSessionCookie(t, w)

		// Check that MaxAge is longer (30 days = 2592000 seconds)
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "__Host-session" {
				sessionCookie = c
				break
			}
		}
		// MaxAge should be approximately 30 days (allowing for some variance)
		if sessionCookie.MaxAge < 2591000 || sessionCookie.MaxAge > 2593000 {
			t.Errorf("remember_me MaxAge: expected ~2592000 (30d), got %d", sessionCookie.MaxAge)
		}
	})

	t.Run("valid credentials without remember_me sets default TTL", func(t *testing.T) {
		h := AuthHandler{
			PS:                testutil.NewMockStore(testUser),
			RS:                testutil.NewMockCache(),
			RL:                &testutil.MockRateLimiter{},
			SessionTTL:        24 * time.Hour,
			SessionRememberMe: 720 * time.Hour,
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertOK(t, w)

		// Check that MaxAge is 24 hours (86400 seconds)
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "__Host-session" {
				sessionCookie = c
				break
			}
		}
		// MaxAge should be approximately 24 hours (allowing for some variance)
		if sessionCookie.MaxAge < 86300 || sessionCookie.MaxAge > 86500 {
			t.Errorf("default MaxAge: expected ~86400 (24h), got %d", sessionCookie.MaxAge)
		}
	})
}

// --- Logout ---

func TestLogout(t *testing.T) {
	testUserID := uuid.Must(uuid.NewV7())
	testTokenHash := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes

	// -- Missing context values (500s) --

	t.Run("missing userID in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// No context values — simulates Logout called without RequireAuth.
		r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("missing tokenHash in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// userID present but tokenHash missing
		r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		ctx := context.WithValue(r.Context(), userIDKey, testUserID)
		w := httptest.NewRecorder()

		h.Logout(w, r.WithContext(ctx))

		assertInternalServerError(t, w)
	})

	// -- Store errors (500s) --

	t.Run("Postgres delete failure returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{DeleteSessionErr: errors.New("database write failed")},
			RS: testutil.NewMockCache(),
		}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures --

	t.Run("Redis delete failure still returns OK", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RS: &testutil.MockCache{DeleteSessionErr: errors.New("redis unavailable")},
		}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path --

	t.Run("valid session returns OK and clears cookie", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		assertClearedSessionCookie(t, w)
	})
}

// --- LogoutAll ---

func TestLogoutAll(t *testing.T) {
	testUserID := uuid.Must(uuid.NewV7())
	testTokenHash := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes

	// -- Missing context values (500s) --

	t.Run("missing userID in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// No context values — simulates LogoutAll called without RequireAuth.
		r := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
		w := httptest.NewRecorder()

		h.LogoutAll(w, r)

		assertInternalServerError(t, w)
	})

	// -- Store errors (500s) --

	t.Run("Postgres delete failure returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{DeleteAllSessionsErr: errors.New("database write failed")},
			RS: testutil.NewMockCache(),
		}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.LogoutAll(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures --

	t.Run("Redis delete failure still returns OK", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{},
			RS: &testutil.MockCache{DeleteAllSessionsErr: errors.New("redis unavailable")},
		}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.LogoutAll(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path --

	t.Run("valid session returns OK and clears cookie", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.LogoutAll(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		assertClearedSessionCookie(t, w)
	})
}

func TestLoginByEmail_UnverifiedEmail(t *testing.T) {
	testPassword := "password123"
	testHash, _ := HashPassword(testPassword)
	testEmail := "unverified@example.com"
	// EmailConfirmedAt is nil (zero value *time.Time) -- email not verified.
	unverifiedUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: &testHash,
	}

	t.Run("unverified email blocks login when RequireEmailVerification is true", func(t *testing.T) {
		h := AuthHandler{
			PS:                       testutil.NewMockStore(unverifiedUser),
			RS:                       testutil.NewMockCache(),
			RL:                       &testutil.MockRateLimiter{},
			ML:                       &testutil.MockMailer{},
			RequireEmailVerification: true,
		}

		body := strings.NewReader(`{"email":"unverified@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "email address not verified. Please check your inbox for a verification link.")
	})

	t.Run("unverified email is allowed when RequireEmailVerification is false", func(t *testing.T) {
		h := AuthHandler{
			PS:                       testutil.NewMockStore(unverifiedUser),
			RS:                       testutil.NewMockCache(),
			RL:                       &testutil.MockRateLimiter{},
			RequireEmailVerification: false,
		}

		body := strings.NewReader(`{"email":"unverified@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})
}

// TestRegisterByEmail_PolicyViolation verifies that RegisterByEmail rejects a
// password that violates h.Policy and returns 400 with the failure message.
func TestRegisterByEmail_PolicyViolation(t *testing.T) {
	// Policy requires at least one digit; submitted password has none.
	h := AuthHandler{
		PS: &testutil.MockStore{},
		Policy: PasswordPolicy{
			MinLength:    8,
			RequireDigit: true,
		},
	}

	body := strings.NewReader(`{"email":"valid@example.com","password":"nodigitshere"}`)
	r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	w := httptest.NewRecorder()

	h.RegisterByEmail(w, r)

	assertPolicyViolation(t, w, "password must contain at least one digit")
}
