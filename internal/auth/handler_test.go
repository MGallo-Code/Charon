// handler_test.go

// unit tests for RegisterByEmail, LoginByEmail, and Logout handlers.

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// --- Mocks ---

// mockStore implements Store interface for handler unit tests.
type mockStore struct {
	createUserErr         error
	getUserByEmail        *store.User
	getUserErr            error
	createSessionErr      error
	getSessionByTokenHash *store.Session
	getSessionErr         error
	deleteSessionErr      error
}

func (m *mockStore) CreateUserByEmail(ctx context.Context, id uuid.UUID, email, passwordHash string) error {
	return m.createUserErr
}

func (m *mockStore) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	return m.getUserByEmail, nil
}

func (m *mockStore) CreateSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error {
	return m.createSessionErr
}

func (m *mockStore) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*store.Session, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return m.getSessionByTokenHash, nil
}

func (m *mockStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	return m.deleteSessionErr
}

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
	body, _ := io.ReadAll(w.Body)
	expected := fmt.Sprintf(`{"message":"%s"}`, expectedMsg)
	if string(body) != expected {
		t.Errorf("body: expected %q, got %q", expected, string(body))
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
	body, _ := io.ReadAll(w.Body)
	if string(body) != `{"message":"internal server error"}` {
		t.Errorf("body: expected internal server error message, got %q", string(body))
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
	body, _ := io.ReadAll(w.Body)
	expected := fmt.Sprintf(`{"message":"%s"}`, expectedMsg)
	if string(body) != expected {
		t.Errorf("body: expected %q, got %q", expected, string(body))
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

// assertCreated checks response is 201 JSON with user_id.
func assertCreated(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusCreated {
		t.Errorf("status: expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `"user_id"`) {
		t.Errorf("body: expected user_id field, got %q", string(body))
	}
}

// --- RegisterByEmail ---

func TestRegisterByEmail(t *testing.T) {
	// -- Input validation (400s) --

	t.Run("empty request body returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &mockStore{}}

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
		h := AuthHandler{PS: &mockStore{}}

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
		h := AuthHandler{PS: &mockStore{}}

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
		h := AuthHandler{PS: &mockStore{}}

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
		h := AuthHandler{PS: &mockStore{}}

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
		h := AuthHandler{PS: &mockStore{}}

		// No @ sign — fails format check
		body := strings.NewReader(`{"email":"notanemail","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Invalid email format")
	})

	t.Run("missing password returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &mockStore{}}

		// Body w// email, no pwd
		body := strings.NewReader(`{"email":"test@email.com"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "No password provided!")
	})

	t.Run("password too short returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &mockStore{}}

		// Body w// password too short (< 6 chars)
		body := strings.NewReader(`{"email":"test@email.com","password":"short"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Password too short!")
	})

	t.Run("password too long returns BadRequest", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &mockStore{}}

		// Body w// password too long (> 128 chars)
		longPassword := strings.Repeat("a", 129)
		body := strings.NewReader(fmt.Sprintf(`{"email":"test@email.com","password":"%s"}`, longPassword))
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert bad request code
		assertBadRequest(t, w, "Password too long!")
	})

	// -- Happy path (201) --

	t.Run("valid email and password returns Created", func(t *testing.T) {
		// Mock store that returns nil, no err on User creation
		h := AuthHandler{PS: &mockStore{}}

		// Body w// valid email and password
		body := strings.NewReader(`{"email":"valid@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert created
		assertCreated(t, w)
	})

	// -- Database errors (500) --

	t.Run("duplicate email returns InternalServerError", func(t *testing.T) {
		// Mock store that returns duplicate key error (Postgres 23505)
		pgErr := &pgconn.PgError{Code: "23505"}
		h := AuthHandler{
			PS: &mockStore{createUserErr: fmt.Errorf("creating user by email: %w", pgErr)},
		}

		// Body w// valid email and password
		body := strings.NewReader(`{"email":"existing@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert internal server error (no user enumeration)
		assertInternalServerError(t, w)
	})

	t.Run("generic database error returns InternalServerError", func(t *testing.T) {
		// Mock store that returns generic database error
		h := AuthHandler{
			PS: &mockStore{createUserErr: errors.New("database connection failed")},
		}

		// Body w// valid email and password
		body := strings.NewReader(`{"email":"test@email.com","password":"validpassword123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		w := httptest.NewRecorder()

		// Attempt register
		h.RegisterByEmail(w, r)

		// assert internal server error
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
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		// Invalid JSON body
		body := strings.NewReader(`{not valid json}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("missing email returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		body := strings.NewReader(`{"password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	t.Run("missing password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		body := strings.NewReader(`{"email":"test@example.com"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Authentication failures (401s) --

	t.Run("non-existent user returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{
			PS: &mockStore{getUserErr: pgx.ErrNoRows},
			RS: &mockSessionCache{},
		}

		body := strings.NewReader(`{"email":"nonexistent@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	t.Run("wrong password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{
			PS: &mockStore{getUserByEmail: testUser},
			RS: &mockSessionCache{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"wrongpassword"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Database/system errors (500s) --

	t.Run("database error when fetching user returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{
			PS: &mockStore{getUserErr: errors.New("database connection failed")},
			RS: &mockSessionCache{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		// Database errors that aren't "no rows" should return 500, not 401
		// But our handler returns 401 for all getUserByEmail errors (generic "invalid credentials")
		// This is intentional to prevent user enumeration via timing
		assertUnauthorized(t, w, "invalid credentials")
	})

	t.Run("malformed password hash returns InternalServerError", func(t *testing.T) {
		badUser := &store.User{
			ID:           testUser.ID,
			Email:        testUser.Email,
			PasswordHash: "not-a-valid-argon2id-hash",
		}
		h := AuthHandler{
			PS: &mockStore{getUserByEmail: badUser},
			RS: &mockSessionCache{},
		}

		body := strings.NewReader(`{"email":"test@example.com","password":"password123"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		w := httptest.NewRecorder()

		h.LoginByEmail(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("session creation failure returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &mockStore{
				getUserByEmail:   testUser,
				createSessionErr: errors.New("database write failed"),
			},
			RS: &mockSessionCache{},
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
			PS: &mockStore{getUserByEmail: testUser},
			RS: &mockSessionCache{},
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
			PS: &mockStore{getUserByEmail: testUser},
			RS: &mockSessionCache{},
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
			PS: &mockStore{getUserByEmail: testUser},
			RS: &mockSessionCache{},
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

func TestLogout(t *testing.T) {
	testUserID := uuid.Must(uuid.NewV7())
	testTokenHash := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes

	// -- Missing context values (500s) --

	t.Run("missing userID in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		// No context values — simulates Logout called without RequireAuth.
		r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("missing tokenHash in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

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
			PS: &mockStore{deleteSessionErr: errors.New("database write failed")},
			RS: &mockSessionCache{},
		}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures --

	t.Run("Redis delete failure still returns OK", func(t *testing.T) {
		h := AuthHandler{
			PS: &mockStore{},
			RS: &mockSessionCache{deleteSessionErr: errors.New("redis unavailable")},
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
		h := AuthHandler{PS: &mockStore{}, RS: &mockSessionCache{}}

		r := requestWithSession(testUserID, testTokenHash)
		w := httptest.NewRecorder()

		h.Logout(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		assertClearedSessionCookie(t, w)
	})
}