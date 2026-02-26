// main_test.go
//
// Level 3 smoke tests
// chi wiring via httptest.NewServer with in-memory mock stores.
// Catches middleware ordering, route grouping, and real HTTP cookie/header behavior
// that httptest.NewRecorder cannot exercise.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MGallo-Code/charon/internal/auth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
)

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
	user := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &email,
		PasswordHash: hash,
	}
	return &auth.AuthHandler{PS: testutil.NewMockStore(user), RS: testutil.NewMockCache(), RL: &testutil.MockRateLimiter{}}
}

// doSmokeLogin logs in with smokeEmail/smokePassword and returns the response.
// Caller must close resp.Body.
func doSmokeLogin(t *testing.T, serverURL string) *http.Response {
	t.Helper()
	payload := `{"email":"` + smokeEmail + `","password":"` + smokePassword + `"}`
	resp, err := http.Post(serverURL+"/login/email", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /login/email: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}
	return resp
}

// --- Smoke tests ---

// TestSmoke_Health verifies /health is mounted and returns per-dependency status.
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
		Postgres string `json:"postgres"`
		Redis    string `json:"redis"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Postgres != "ok" {
		t.Errorf(`body.postgres: expected "ok", got %q`, body.Postgres)
	}
	if body.Redis != "ok" {
		t.Errorf(`body.redis: expected "ok", got %q`, body.Redis)
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

// TestSmoke_LogoutAll_WithoutSession verifies /logout-all rejects unauthenticated requests.
func TestSmoke_LogoutAll_WithoutSession(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/logout-all", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /logout-all: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: expected 401, got %d", resp.StatusCode)
	}
}

// TestSmoke_LogoutAll_WithSessionButNoCSRF verifies CSRFMiddleware is wired to /logout-all.
func TestSmoke_LogoutAll_WithSessionButNoCSRF(t *testing.T) {
	srv := httptest.NewServer(buildRouter(newSmokeHandler(t)))
	defer srv.Close()

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

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/logout-all", nil)
	if err != nil {
		t.Fatalf("building logout-all request: %v", err)
	}
	req.Header.Set("Cookie", "__Host-session="+cookieValue)
	// Intentionally omitting X-CSRF-Token

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /logout-all: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: expected 403, got %d", resp.StatusCode)
	}
}

// TestSmoke_FullRoundTrip_LogoutAll verifies login -> logout-all over real HTTP.
func TestSmoke_FullRoundTrip_LogoutAll(t *testing.T) {
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

	// Step 2: LogoutAll -- pass session cookie and CSRF token
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/logout-all", nil)
	if err != nil {
		t.Fatalf("building logout-all request: %v", err)
	}
	req.Header.Set("Cookie", "__Host-session="+cookieValue)
	req.Header.Set("X-CSRF-Token", loginBody.CSRFToken)

	logoutAllResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /logout-all: %v", err)
	}
	defer logoutAllResp.Body.Close()

	if logoutAllResp.StatusCode != http.StatusOK {
		t.Errorf("logout-all: expected 200, got %d", logoutAllResp.StatusCode)
	}

	// Step 3: Session cookie must be cleared in response
	for _, c := range logoutAllResp.Cookies() {
		if c.Name == "__Host-session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge: expected -1 (cleared), got %d", c.MaxAge)
			}
			return
		}
	}
	t.Error("__Host-session not found in logout-all response")
}

// TestSmoke_PasswordReset_UnknownEmail verifies POST /send/reset/password returns 200
// even when no account exists for the given email (enumeration-safe).
func TestSmoke_PasswordReset_UnknownEmail(t *testing.T) {
	hash, err := auth.HashPassword(smokePassword)
	if err != nil {
		t.Fatalf("hashing test password: %v", err)
	}
	email := smokeEmail
	user := &store.User{ID: uuid.Must(uuid.NewV7()), Email: &email, PasswordHash: hash}
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	mailer := &testutil.MockMailer{}
	h := &auth.AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: mailer}
	srv := httptest.NewServer(buildRouter(h))
	defer srv.Close()

	payload := `{"email":"unknown@example.com"}`
	resp, err := http.Post(srv.URL+"/send/reset/password", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /send/reset/password: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: expected 200, got %d", resp.StatusCode)
	}
}

// TestSmoke_PasswordConfirm_InvalidToken verifies POST /password/confirm returns 400
// when the token is not found in the store.
func TestSmoke_PasswordConfirm_InvalidToken(t *testing.T) {
	hash, err := auth.HashPassword(smokePassword)
	if err != nil {
		t.Fatalf("hashing test password: %v", err)
	}
	email := smokeEmail
	user := &store.User{ID: uuid.Must(uuid.NewV7()), Email: &email, PasswordHash: hash}
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	mailer := &testutil.MockMailer{}
	h := &auth.AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: mailer}
	srv := httptest.NewServer(buildRouter(h))
	defer srv.Close()

	payload := `{"token":"notavalidtoken","new_password":"newpassword1"}`
	resp, err := http.Post(srv.URL+"/password/confirm", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /password/confirm: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: expected 400, got %d", resp.StatusCode)
	}
}

// TestSmoke_PasswordReset_FullRoundTrip verifies the complete password reset flow over real HTTP:
// reset request -> confirm with captured token -> old password rejected -> new password accepted.
func TestSmoke_PasswordReset_FullRoundTrip(t *testing.T) {
	hash, err := auth.HashPassword(smokePassword)
	if err != nil {
		t.Fatalf("hashing test password: %v", err)
	}
	email := smokeEmail
	user := &store.User{ID: uuid.Must(uuid.NewV7()), Email: &email, PasswordHash: hash}
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	mailer := &testutil.MockMailer{}
	h := &auth.AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: mailer}
	srv := httptest.NewServer(buildRouter(h))
	defer srv.Close()

	// Step 1: Request password reset -- expect 200, mailer captures the token.
	resetPayload := `{"email":"` + smokeEmail + `"}`
	resetResp, err := http.Post(srv.URL+"/send/reset/password", "application/json", strings.NewReader(resetPayload))
	if err != nil {
		t.Fatalf("POST /send/reset/password: %v", err)
	}
	resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("reset: expected 200, got %d", resetResp.StatusCode)
	}
	token := mailer.LastResetToken
	if token == "" {
		t.Fatal("mailer.LastResetToken is empty after reset request")
	}

	// Step 2: Confirm with captured token and new password -- expect 200.
	confirmPayload := `{"token":"` + token + `","new_password":"newpassword1"}`
	confirmResp, err := http.Post(srv.URL+"/password/confirm", "application/json", strings.NewReader(confirmPayload))
	if err != nil {
		t.Fatalf("POST /password/confirm: %v", err)
	}
	confirmResp.Body.Close()
	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: expected 200, got %d", confirmResp.StatusCode)
	}

	// Step 3: Old password must be rejected -- expect 401.
	oldPayload := `{"email":"` + smokeEmail + `","password":"` + smokePassword + `"}`
	oldResp, err := http.Post(srv.URL+"/login/email", "application/json", strings.NewReader(oldPayload))
	if err != nil {
		t.Fatalf("POST /login/email (old password): %v", err)
	}
	oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password: expected 401, got %d", oldResp.StatusCode)
	}

	// Step 4: New password must be accepted -- expect 200.
	newPayload := `{"email":"` + smokeEmail + `","password":"newpassword1"}`
	newResp, err := http.Post(srv.URL+"/login/email", "application/json", strings.NewReader(newPayload))
	if err != nil {
		t.Fatalf("POST /login/email (new password): %v", err)
	}
	newResp.Body.Close()
	if newResp.StatusCode != http.StatusOK {
		t.Errorf("new password: expected 200, got %d", newResp.StatusCode)
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