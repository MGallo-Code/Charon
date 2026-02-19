// main_test.go
//
// Level 3 smoke tests
// chi wiring via httptest.NewServer with in-memory mock stores.
// Catches middleware ordering, route grouping, and real HTTP cookie/header behavior
// that httptest.NewRecorder cannot exercise.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/auth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// --- Smoke mocks ---

// smokeStore is a minimal, stateful mock of auth.Store.
// Stores sessions in memory so login -> logout round-trips work without a real DB.
type smokeStore struct {
	mu       sync.Mutex
	user     *store.User
	sessions map[string]*store.Session // keyed by string(tokenHash)
}

func (m *smokeStore) CreateUserByEmail(_ context.Context, id uuid.UUID, email, passwordHash string) error {
	return nil
}

func (m *smokeStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	if m.user != nil && m.user.Email != nil && *m.user.Email == email {
		return m.user, nil
	}
	return nil, errors.New("user not found")
}

func (m *smokeStore) CreateSession(_ context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[string(tokenHash)] = &store.Session{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
	}
	return nil
}

func (m *smokeStore) GetSessionByTokenHash(_ context.Context, tokenHash []byte) (*store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[string(tokenHash)]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (m *smokeStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, string(tokenHash))
	return nil
}

// smokeCache is a minimal, stateful mock of auth.SessionCache.
// Acts as an in-memory Redis replacement for smoke tests.
type smokeCache struct {
	mu       sync.Mutex
	sessions map[string]*store.CachedSession // keyed by base64 token hash
}

func (m *smokeCache) GetSession(_ context.Context, tokenHash string) (*store.CachedSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, errors.New("cache miss")
	}
	return s, nil
}

func (m *smokeCache) SetSession(_ context.Context, tokenHash string, sessionData store.Session, ttl int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[tokenHash] = &store.CachedSession{
		UserID:    sessionData.UserID,
		CSRFToken: sessionData.CSRFToken,
		ExpiresAt: sessionData.ExpiresAt,
	}
	return nil
}

func (m *smokeCache) DeleteSession(_ context.Context, tokenHash string, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

// --- Helpers ---

const smokeEmail = "smoke@example.com"
const smokePassword = "smokepassword1"

// newSmokeHandler returns an AuthHandler backed by in-memory stores, seeded with one test user.
func newSmokeHandler(t *testing.T) *auth.AuthHandler {
	t.Helper()
	hash, err := auth.HashPassword(smokePassword)
	if err != nil {
		t.Fatalf("hashing test password: %v", err)
	}
	email := smokeEmail
	ms := &smokeStore{
		user: &store.User{
			ID:           uuid.Must(uuid.NewV7()),
			Email:        &email,
			PasswordHash: hash,
		},
		sessions: make(map[string]*store.Session),
	}
	mc := &smokeCache{
		sessions: make(map[string]*store.CachedSession),
	}
	return &auth.AuthHandler{PS: ms, RS: mc}
}

// doSmokeLogin logs in with smokeEmail/smokePassword and returns the response.
// Caller must close resp.Body.
func doSmokeLogin(t *testing.T, serverURL string) *http.Response {
	t.Helper()
	payload := `{"email":"` + smokeEmail + `","password":"` + smokePassword + `"}`
	resp, err := http.Post(serverURL+"/loginEmail", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /loginEmail: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}
	return resp
}

// --- Smoke tests ---

// TestSmoke_Health verifies /health is mounted and returns expected JSON.
func TestSmoke_Health(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: expected 200, got %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf(`body.status: expected "ok", got %q`, body.Status)
	}
}

// TestSmoke_Login_ValidCredentials verifies login sets session cookie and returns CSRF token.
func TestSmoke_Login_ValidCredentials(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	resp := doSmokeLogin(t, srv.URL)
	defer resp.Body.Close()

	// Session cookie must be set
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("__Host-session cookie not set")
	}
	if sessionCookie.Value == "" {
		t.Error("session cookie value is empty")
	}

	// Body must contain user_id and csrf_token
	var body struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	if body.UserID == "" {
		t.Error("user_id missing from response body")
	}
	if body.CSRFToken == "" {
		t.Error("csrf_token missing from response body")
	}
}

// TestSmoke_Logout_WithoutSession verifies /logout rejects unauthenticated requests
// (RequireAuth is wired to the protected route group).
func TestSmoke_Logout_WithoutSession(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	// No session cookie -- RequireAuth must reject this
	resp, err := http.Post(srv.URL+"/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: expected 401, got %d", resp.StatusCode)
	}
}

// TestSmoke_Logout_WithSessionButNoCSRF verifies CSRFMiddleware is wired to the protected group.
// A valid session without the X-CSRF-Token header must be rejected with 403.
func TestSmoke_Logout_WithSessionButNoCSRF(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	// Login -- get a valid session cookie
	loginResp := doSmokeLogin(t, srv.URL)
	var cookieValue string
	for _, c := range loginResp.Cookies() {
		if c.Name == "__Host-session" {
			cookieValue = c.Value
			break
		}
	}
	loginResp.Body.Close()
	if cookieValue == "" {
		t.Fatal("no session cookie from login")
	}

	// Logout -- valid session, but no CSRF header
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("building logout request: %v", err)
	}
	req.Header.Set("Cookie", "__Host-session="+cookieValue)
	// Intentionally omitting X-CSRF-Token

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: expected 403, got %d", resp.StatusCode)
	}
}

// TestSmoke_FullRoundTrip verifies login -> logout over real HTTP.
// Exercises cookie passing, CSRF header, and middleware ordering end-to-end.
func TestSmoke_FullRoundTrip(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	// Step 1: Login -- capture session cookie and CSRF token
	loginResp := doSmokeLogin(t, srv.URL)

	var cookieValue string
	for _, c := range loginResp.Cookies() {
		if c.Name == "__Host-session" {
			cookieValue = c.Value
			break
		}
	}
	if cookieValue == "" {
		loginResp.Body.Close()
		t.Fatal("no session cookie from login")
	}

	var loginBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginBody); err != nil {
		loginResp.Body.Close()
		t.Fatalf("decoding login response: %v", err)
	}
	loginResp.Body.Close()
	if loginBody.CSRFToken == "" {
		t.Fatal("no csrf_token from login")
	}

	// Step 2: Logout -- pass session cookie and CSRF token
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("building logout request: %v", err)
	}
	req.Header.Set("Cookie", "__Host-session="+cookieValue)
	req.Header.Set("X-CSRF-Token", loginBody.CSRFToken)

	logoutResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	defer logoutResp.Body.Close()

	if logoutResp.StatusCode != http.StatusOK {
		t.Errorf("logout: expected 200, got %d", logoutResp.StatusCode)
	}

	// Step 3: Session cookie must be cleared in logout response
	for _, c := range logoutResp.Cookies() {
		if c.Name == "__Host-session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge: expected -1 (cleared), got %d", c.MaxAge)
			}
			return
		}
	}
	t.Error("__Host-session not found in logout response")
}