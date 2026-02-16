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
	"github.com/jackc/pgx/v5/pgconn"
)

// --- Mocks ---

// mockStore implements Store interface for handler unit tests.
type mockStore struct {
	createUserErr   error
	getUserByEmail  *store.User
	getUserErr      error
	createSessionErr error
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

		// Body w// invalid email format
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
