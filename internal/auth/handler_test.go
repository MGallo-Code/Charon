// handler_test.go

// unit tests for RegisterByEmail, LoginByEmail, Logout, LogoutAll, PasswordChange, PasswordReset, PasswordConfirm, VerifyEmail, and ResendVerificationEmail handlers.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

// --- Helper Functions ---

// assertBadRequest checks response is 400 JSON with expected message.
func assertBadRequest(t *testing.T, w *httptest.ResponseRecorder, expectedMsg string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: expected 400, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := strings.TrimSuffix(string(bodyBytes), "\n")
	expected := fmt.Sprintf(`{"error":"%s"}`, expectedMsg)
	if body != expected {
		t.Errorf("body: expected %q, got %q", expected, body)
	}
}

// assertInternalServerError checks response is 500 JSON with generic error.
func assertInternalServerError(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: expected 500, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := strings.TrimSuffix(string(bodyBytes), "\n")
	if body != `{"error":"internal server error"}` {
		t.Errorf("body: expected internal server error message, got %q", body)
	}
}

// assertUnauthorized checks response is 401 JSON with expected message.
func assertUnauthorized(t *testing.T, w *httptest.ResponseRecorder, expectedMsg string) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: expected 401, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := strings.TrimSuffix(string(bodyBytes), "\n")
	expected := fmt.Sprintf(`{"error":"%s"}`, expectedMsg)
	if body != expected {
		t.Errorf("body: expected %q, got %q", expected, body)
	}
}

// assertOK checks response is 200 JSON with user_id and csrf_token fields.
func assertOK(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Errorf("status: expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `"user_id"`) {
		t.Errorf("body: expected user_id field, got %q", string(body))
	}
	if !strings.Contains(string(body), `"csrf_token"`) {
		t.Errorf("body: expected csrf_token field, got %q", string(body))
	}
}

// assertSessionCookie checks __Host-session cookie has correct security attributes.
func assertSessionCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "__Host-session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("__Host-session cookie not found")
	}
	if !sessionCookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("cookie should be Secure")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite: expected Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Path != "/" {
		t.Errorf("cookie Path: expected /, got %s", sessionCookie.Path)
	}
	if sessionCookie.Value == "" {
		t.Error("cookie value should not be empty")
	}
}

// assertTooManyRequests checks response is 429 JSON with "too many requests" error.
func assertTooManyRequests(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status: expected 429, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := strings.TrimSuffix(string(bodyBytes), "\n")
	if body != `{"error":"too many requests"}` {
		t.Errorf("body: expected too many requests message, got %q", body)
	}
}

// assertCreated checks response is 201 JSON with message field.
func assertCreated(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusCreated {
		t.Errorf("status: expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `"message"`) {
		t.Errorf("body: expected message field, got %q", string(body))
	}
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
		PasswordHash: testHash,
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
		badUser := &store.User{
			ID:           testUser.ID,
			Email:        testUser.Email,
			PasswordHash: "not-a-valid-argon2id-hash",
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

// requestWithSession builds request with userID and tokenHash pre-loaded into context,
// simulates a request that has already passed through RequireAuth middleware.
func requestWithSession(userID uuid.UUID, tokenHash []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	ctx := context.WithValue(r.Context(), userIDKey, userID)
	ctx = context.WithValue(ctx, tokenHashKey, tokenHash)
	return r.WithContext(ctx)
}

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

// --- PasswordChange ---

// pwdChangeReq builds a POST /password/change request with userID injected in context.
func pwdChangeReq(userID uuid.UUID, currentPwd, newPwd string) *http.Request {
	body := strings.NewReader(fmt.Sprintf(
		`{"current_password":%q,"new_password":%q}`, currentPwd, newPwd,
	))
	r := httptest.NewRequest(http.MethodPost, "/password/change", body)
	ctx := context.WithValue(r.Context(), userIDKey, userID)
	return r.WithContext(ctx)
}

func TestPasswordChange(t *testing.T) {
	testPassword := "oldpassword1"
	testHash, _ := HashPassword(testPassword)
	testEmail := "pwchange@example.com"
	testUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: testHash,
	}

	// freshUser returns a new User with a freshly hashed testPassword.
	// MockStore stores users by pointer, and UpdateUserPassword mutates PasswordHash
	// in place; tests that reach UpdateUserPassword need their own copy.
	freshUser := func() *store.User {
		h, _ := HashPassword(testPassword)
		return &store.User{ID: testUser.ID, Email: testUser.Email, PasswordHash: h}
	}

	// -- Input validation (400s) --

	t.Run("empty body returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/password/change", nil)
		ctx := context.WithValue(r.Context(), userIDKey, testUser.ID)
		w := httptest.NewRecorder()

		h.PasswordChange(w, r.WithContext(ctx))

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		body := strings.NewReader(`{not valid json}`)
		r := httptest.NewRequest(http.MethodPost, "/password/change", body)
		ctx := context.WithValue(r.Context(), userIDKey, testUser.ID)
		w := httptest.NewRecorder()

		h.PasswordChange(w, r.WithContext(ctx))

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("missing current_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, "", "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertBadRequest(t, w, "current_password required")
	})

	t.Run("invalid new_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdChangeReq(testUser.ID, testPassword, "short")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	// -- Missing context (500) --

	t.Run("missing userID in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// No context, simulates handler called without RequireAuth.
		r := httptest.NewRequest(http.MethodPost, "/password/change",
			strings.NewReader(`{"current_password":"oldpassword1","new_password":"validnewpassword"}`))
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	// -- Auth failures (401s) --

	t.Run("wrong current_password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: testutil.NewMockStore(testUser), RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, "wrongpassword", "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Store errors (500s) --

	t.Run("GetPwdHashByUserID failure returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{GetPwdHashByUserIDErr: errors.New("database connection failed")},
			RS: testutil.NewMockCache(),
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("UpdateUserPassword failure returns InternalServerError", func(t *testing.T) {
		// UpdateUserPasswordErr causes early return before mutation; testUser is safe.
		ps := testutil.NewMockStore(testUser)
		ps.UpdateUserPasswordErr = errors.New("database write failed")
		h := AuthHandler{PS: ps, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("Postgres DeleteAllUserSessions failure returns InternalServerError", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		ps := testutil.NewMockStore(freshUser())
		ps.DeleteAllSessionsErr = errors.New("database write failed")
		h := AuthHandler{PS: ps, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures --

	t.Run("Redis DeleteAllUserSessions failure still returns OK", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		h := AuthHandler{
			PS: testutil.NewMockStore(freshUser()),
			RS: &testutil.MockCache{DeleteAllSessionsErr: errors.New("redis unavailable")},
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path (200) --

	t.Run("valid request returns OK and clears cookie", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		h := AuthHandler{
			PS: testutil.NewMockStore(freshUser()),
			RS: testutil.NewMockCache(),
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		assertClearedSessionCookie(t, w)
	})
}

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

// --- PasswordReset ---

// assertGenericResetResponse checks the handler returned the no-enumeration 200 response.
func assertGenericResetResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Errorf("status: expected 200, got %d", w.Code)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := strings.TrimSuffix(string(bodyBytes), "\n")
	if body != `{"message":"if that email exists, a reset link has been sent"}` {
		t.Errorf("body: expected generic reset message, got %q", body)
	}
}

func TestPasswordReset(t *testing.T) {
	email := "user@example.com"
	userID, _ := uuid.NewV7()
	existingUser := &store.User{ID: userID, Email: &email}

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader("not-json"))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertBadRequest(t, w, "invalid request")
	})

	t.Run("unknown email returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(), // no users seeded
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"nobody@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("rate limited returns 429", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("status: expected 429, got %d", w.Code)
		}
	})

	t.Run("CreateToken failure returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{
				Users:          map[string]*store.User{email: existingUser},
				CreateTokenErr: errors.New("db error"),
			},
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("email send failure returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{SendPasswordResetErr: errors.New("smtp unavailable")},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("happy path returns generic 200 and sends email", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: mailer,
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
		if mailer.LastResetTo != email {
			t.Errorf("email sent to: expected %q, got %q", email, mailer.LastResetTo)
		}
		if mailer.LastResetToken == "" {
			t.Error("expected a token to be sent, got empty string")
		}
	})

	t.Run("email is normalised to lowercase before lookup", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser), // seeded with lowercase email
			RL: &testutil.MockRateLimiter{},
			ML: mailer,
		}
		// Submit with mixed case -- should still find the user
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"User@Example.COM"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
		if mailer.LastResetTo != email {
			t.Errorf("email sent to: expected normalised %q, got %q", email, mailer.LastResetTo)
		}
	})
}

// --- PasswordConfirm ---

// seedConfirmToken plants a password_reset token in ms; returns base64 token for requests.
// Generates raw bytes, stores SHA-256 hash in MockStore (mirrors GenerateToken + CreateToken).
func seedConfirmToken(ms *testutil.MockStore, userID uuid.UUID) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("seedConfirmToken: rand.Read: " + err.Error())
	}
	hash := sha256.Sum256(raw)
	if ms.Tokens == nil {
		ms.Tokens = make(map[string]*store.Token)
	}
	ms.Tokens[string(hash[:])] = &store.Token{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    userID,
		TokenType: "password_reset",
		TokenHash: hash[:],
		ExpiresAt: time.Now().Add(time.Hour),
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// pwdConfirmReq builds a POST /auth/password/confirm request with given token and password.
func pwdConfirmReq(token, newPwd string) *http.Request {
	body := strings.NewReader(fmt.Sprintf(`{"token":%q,"new_password":%q}`, token, newPwd))
	return httptest.NewRequest(http.MethodPost, "/auth/password/confirm", body)
}

func TestPasswordConfirm(t *testing.T) {
	validPassword := "newpwd12*"
	testEmail := "confirm@example.com"
	testUserID := uuid.Must(uuid.NewV7())
	testUser := &store.User{
		ID:    testUserID,
		Email: &testEmail,
	}

	// freshStore seeds testUser + one valid reset token; returns store and base64 token string.
	freshStore := func() (*testutil.MockStore, string) {
		ms := testutil.NewMockStore(testUser)
		tok := seedConfirmToken(ms, testUserID)
		return ms, tok
	}

	// -- Input validation (400s) --

	t.Run("empty body returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/auth/password/confirm", nil)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/auth/password/confirm", strings.NewReader(`{not json}`))
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("empty new_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		// Password validation runs before token decode -- token field irrelevant here.
		r := pwdConfirmReq("sometoken", "")
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	t.Run("password too short returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdConfirmReq("sometoken", "abc")
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	t.Run("password too long returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdConfirmReq("sometoken", strings.Repeat("a", 129))
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at most 128 characters")
	})

	t.Run("malformed base64 token returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := pwdConfirmReq("!!!not-base64!!!", validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "invalid reset token")
	})

	// -- Token validation (400s) --

	t.Run("unknown token returns BadRequest", func(t *testing.T) {
		// No token seeded -- ConsumeToken returns pgx.ErrNoRows for unknown hash.
		h := AuthHandler{
			PS: testutil.NewMockStore(testUser),
			RS: testutil.NewMockCache(),
		}

		unknownRaw := make([]byte, 32) // zero bytes, valid base64, no matching token in store
		r := pwdConfirmReq(base64.RawURLEncoding.EncodeToString(unknownRaw), validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "invalid or expired reset token")
	})

	t.Run("ConsumeToken store error returns InternalServerError", func(t *testing.T) {
		ms := testutil.NewMockStore(testUser)
		ms.ConsumeTokenErr = errors.New("database error")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		// ConsumeTokenErr fires before lookup -- any valid base64 triggers it.
		unknownRaw := make([]byte, 32)
		r := pwdConfirmReq(base64.RawURLEncoding.EncodeToString(unknownRaw), validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	// -- Store errors after token consumed (500s) --

	t.Run("UpdateUserPassword failure returns InternalServerError", func(t *testing.T) {
		ms, tok := freshStore()
		ms.UpdateUserPasswordErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("Postgres DeleteAllUserSessions failure returns InternalServerError", func(t *testing.T) {
		ms, tok := freshStore()
		ms.DeleteAllSessionsErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures (200) --

	t.Run("Redis DeleteAllUserSessions failure still returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		h := AuthHandler{
			PS: ms,
			RS: &testutil.MockCache{DeleteAllSessionsErr: errors.New("redis unavailable")},
		}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("SetEmailConfirmedAt failure still returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		ms.SetEmailConfirmedAtErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path (200) --

	t.Run("valid token and password returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		bodyBytes, _ := io.ReadAll(w.Body)
		body := strings.TrimSuffix(string(bodyBytes), "\n")
		if body != `{"message":"password updated"}` {
			t.Errorf("body: expected password updated message, got %q", body)
		}
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
		PasswordHash: testHash,
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

func TestVerifyEmail(t *testing.T) {
	// Helper: builds a raw token, stores it in MockStore, returns encoded token string.
	makeToken := func(t *testing.T, ms *testutil.MockStore, userID uuid.UUID) string {
		t.Helper()
		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			t.Fatalf("generating token: %v", err)
		}
		hash := sha256.Sum256(rawToken)
		tokenID := uuid.Must(uuid.NewV7())
		_ = ms.CreateToken(context.Background(), tokenID, userID, "email_verification", hash[:], nowPlusHour())
		return base64.RawURLEncoding.EncodeToString(rawToken)
	}

	testUserID := uuid.Must(uuid.NewV7())

	t.Run("valid token verifies email and returns 200", func(t *testing.T) {
		ms := testutil.NewMockStore()
		tokenStr := makeToken(t, ms, testUserID)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		bodyBytes, _ := io.ReadAll(w.Body)
		body2 := strings.TrimSuffix(string(bodyBytes), "\n")
		if body2 != `{"message":"email verified"}` {
			t.Errorf("body: got %q, want email verified message", body2)
		}
	})

	t.Run("invalid token returns 400", func(t *testing.T) {
		ms := testutil.NewMockStore()
		// Encode a random token that was never stored.
		raw := make([]byte, 32)
		rand.Read(raw)
		tokenStr := base64.RawURLEncoding.EncodeToString(raw)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "invalid or expired token")
	})

	t.Run("bad base64 returns 400", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"!!!not-base64!!!"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "invalid token")
	})

	t.Run("empty token returns 400", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":""}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "token is required")
	})

	t.Run("replayed token returns 400", func(t *testing.T) {
		ms := testutil.NewMockStore()
		tokenStr := makeToken(t, ms, testUserID)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		// First use -- succeeds.
		r1 := httptest.NewRequest(http.MethodPost, "/verify/email", strings.NewReader(`{"token":"`+tokenStr+`"}`))
		h.VerifyEmail(httptest.NewRecorder(), r1)

		// Replay -- ConsumeToken returns ErrNoRows (used_at already set).
		r2 := httptest.NewRequest(http.MethodPost, "/verify/email", strings.NewReader(`{"token":"`+tokenStr+`"}`))
		w2 := httptest.NewRecorder()
		h.VerifyEmail(w2, r2)

		assertBadRequest(t, w2, "invalid or expired token")
	})
}

// nowPlusHour is a test helper for token expiry in VerifyEmail tests.
func nowPlusHour() time.Time {
	return time.Now().Add(time.Hour)
}

// genericResendMsg is the no-enumeration response ResendVerificationEmail always returns on 200.
const genericResendMsg = `{"message":"if that email is registered and unverified, a verification link has been sent"}`

// assertGenericResendResponse checks handler returned 200 with the no-enumeration message.
func assertGenericResendResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Errorf("status: expected 200, got %d", w.Code)
	}
	body := strings.TrimSuffix(w.Body.String(), "\n")
	if body != genericResendMsg {
		t.Errorf("body: expected generic resend message, got %q", body)
	}
}

func TestResendVerificationEmail(t *testing.T) {
	email := "user@example.com"
	userID := uuid.Must(uuid.NewV7())

	// unverifiedUser has no EmailConfirmedAt -- eligible for resend.
	unverifiedUser := &store.User{ID: userID, Email: &email}

	// confirmedAt holds a timestamp for seeding an already-verified user.
	confirmedAt := time.Now().Add(-24 * time.Hour)
	verifiedUser := &store.User{ID: userID, Email: &email, EmailConfirmedAt: &confirmedAt}

	// resendReq builds a POST /resend/verification-email request with the given body.
	resendReq := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/resend/verification-email", strings.NewReader(body))
	}

	// baseHandler returns a handler wired with a no-error rate limiter and mailer.
	// Swap PS / RL / ML fields per sub-test as needed.
	baseHandler := func(ps Store) AuthHandler {
		return AuthHandler{
			PS: ps,
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
			Policies: RateLimitPolicies{
				ResendVerification: store.RateLimit{MaxAttempts: 3, Window: time.Hour, LockoutTTL: time.Hour},
			},
		}
	}

	t.Run("bad JSON returns 400", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore())
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq("not-json"))
		assertBadRequest(t, w, "invalid request")
	})

	t.Run("invalid email returns 400", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore())
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"notanemail"}`))
		if w.Code != http.StatusBadRequest {
			t.Errorf("status: expected 400, got %d", w.Code)
		}
	})

	t.Run("rate limited returns 429", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore(unverifiedUser))
		h.RL = &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded}
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("status: expected 429, got %d", w.Code)
		}
	})

	t.Run("happy path: unverified user gets email, returns generic 200", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(unverifiedUser))
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != email {
			t.Errorf("verification sent to: expected %q, got %q", email, mailer.LastVerifTo)
		}
		if mailer.LastVerifToken == "" {
			t.Error("expected a verification token to be sent, got empty string")
		}
	})

	t.Run("user not found returns generic 200 (no enumeration)", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore()) // no users seeded
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"nobody@example.com"}`))
		assertGenericResendResponse(t, w)
	})

	t.Run("already confirmed user returns generic 200 (no enumeration)", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(verifiedUser))
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != "" {
			t.Errorf("no email expected for confirmed user, but got LastVerifTo=%q", mailer.LastVerifTo)
		}
	})

	t.Run("DB error on GetUserByEmail returns generic 200 (no enumeration)", func(t *testing.T) {
		ms := &testutil.MockStore{
			GetUserByEmailErr: errors.New("connection refused"),
		}
		h := baseHandler(ms)
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
	})

	t.Run("email is lowercased before lookup", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(unverifiedUser)) // seeded with lowercase email
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"User@Example.COM"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != email {
			t.Errorf("expected normalised email %q, got %q", email, mailer.LastVerifTo)
		}
	})
}

// --- PasswordPolicy handler integration ---

// assertPolicyViolation checks response is 400 and body contains the failure message.
// Uses substring match because handlers join multiple failures with "; " and we test
// one violation at a time -- the exact joined string is an implementation detail.
func assertPolicyViolation(t *testing.T, w *httptest.ResponseRecorder, wantFragment string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: expected 400, got %d", w.Code)
	}
	bodyBytes, _ := io.ReadAll(w.Body)
	body := string(bodyBytes)
	if !strings.Contains(body, wantFragment) {
		t.Errorf("body: expected to contain %q, got %q", wantFragment, body)
	}
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

// TestPasswordChange_PolicyViolation verifies that PasswordChange rejects a
// new_password that violates h.Policy and returns 400 with the failure message.
func TestPasswordChange_PolicyViolation(t *testing.T) {
	currentPwd := "OldPassword1!"
	currentHash, _ := HashPassword(currentPwd)
	testEmail := "pwchange-policy@example.com"
	testUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: currentHash,
	}

	// Policy requires uppercase; new password is all lowercase.
	h := AuthHandler{
		PS: testutil.NewMockStore(testUser),
		RS: testutil.NewMockCache(),
		Policy: PasswordPolicy{
			MinLength:        8,
			RequireUppercase: true,
		},
	}

	r := pwdChangeReq(testUser.ID, currentPwd, "alllowercase")
	w := httptest.NewRecorder()

	h.PasswordChange(w, r)

	assertPolicyViolation(t, w, "password must contain at least one uppercase letter")
}

// TestPasswordConfirm_PolicyViolation verifies that PasswordConfirm rejects a
// new_password that violates h.Policy and returns 400 with the failure message.
func TestPasswordConfirm_PolicyViolation(t *testing.T) {
	testEmail := "confirm-policy@example.com"
	testUserID := uuid.Must(uuid.NewV7())
	testUser := &store.User{ID: testUserID, Email: &testEmail}

	ms := testutil.NewMockStore(testUser)
	tok := seedConfirmToken(ms, testUserID)

	// Policy requires a special character; submitted password has none.
	h := AuthHandler{
		PS: ms,
		RS: testutil.NewMockCache(),
		Policy: PasswordPolicy{
			MinLength:      8,
			RequireSpecial: true,
		},
	}

	r := pwdConfirmReq(tok, "NoSpecialChars1A")
	w := httptest.NewRecorder()

	h.PasswordConfirm(w, r)

	assertPolicyViolation(t, w, "password must contain at least one special character")
}
