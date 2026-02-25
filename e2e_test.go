// e2e_test.go
//
// Level 3 integration tests: exercises run() end-to-end with real Postgres and Redis.
// Requires compose.test.yml to be running.
//
//	docker compose -f compose.test.yml up -d
//	go test ./...
//	docker compose -f compose.test.yml down
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/config"
	"github.com/MGallo-Code/charon/internal/testutil"
)

// e2eServerURL is the base URL of the running test server.
// Empty if the compose stack is not up; e2e tests skip in that case.
var e2eServerURL string

// e2eMailer captures outbound password reset emails so e2e tests can extract the token.
var e2eMailer = &testutil.MockMailer{}

func TestMain(m *testing.M) {
	cfg := &config.Config{
		DatabaseURL: envOrDefault("TEST_DATABASE_URL", "postgres://test_user:test_pass@localhost:5433/charon_test"),
		RedisURL:    envOrDefault("TEST_REDIS_URL", "redis://localhost:6380"),
		Port:        "0", // OS picks a free port
		LogLevel:    slog.LevelWarn,
		// Rate limit defaults -- must be non-zero or the Lua script gets invalid TTLs.
		RateLoginEmailMax:     10,
		RateLoginEmailWindow:  10 * time.Minute,
		RateLoginEmailLockout: 15 * time.Minute,
		RateResetMax:          3,
		RateResetWindow:       time.Hour,
		RateResetLockout:      time.Hour,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	runErr := make(chan error, 1)

	go func() {
		runErr <- run(ctx, cfg, ready, e2eMailer)
	}()

	// Wait for server ready or startup failure (compose stack not running).
	select {
	case addr := <-ready:
		e2eServerURL = addr
	case err := <-runErr:
		fmt.Fprintf(os.Stderr, "e2e: server failed to start (%v) — e2e tests will be skipped\n", err)
	}

	code := m.Run()

	cancel()
	if e2eServerURL != "" {
		// Wait for run() to finish so deferred closes (ps, rs) complete before os.Exit.
		<-runErr
	}

	os.Exit(code)
}

// envOrDefault returns the env var value or fallback if unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// skipIfNoE2E skips the test if the e2e server did not start.
func skipIfNoE2E(t *testing.T) {
	t.Helper()
	if e2eServerURL == "" {
		t.Skip("e2e: compose stack not running (docker compose -f compose.test.yml up -d)")
	}
}

// --- E2E helpers ---

// e2eRegister registers a new user. Fatals on error or non-201.
func e2eRegister(t *testing.T, email, password string) {
	t.Helper()
	resp, err := http.Post(e2eServerURL+"/register/email", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /register/email: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
}

// e2eLogin logs in and returns the session cookie value and CSRF token. Fatals on error or non-200.
func e2eLogin(t *testing.T, email, password string) (cookieValue, csrfToken string) {
	t.Helper()
	resp, err := http.Post(e2eServerURL+"/login/email", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /login/email: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" {
			cookieValue = c.Value
			break
		}
	}
	if cookieValue == "" {
		t.Fatal("e2eLogin: no session cookie in response")
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("e2eLogin: decoding response: %v", err)
	}
	if body.CSRFToken == "" {
		t.Fatal("e2eLogin: no csrf_token in response")
	}
	return cookieValue, body.CSRFToken
}

// e2eAuthPost makes an authenticated POST with session cookie and X-CSRF-Token.
// Caller must close the returned response body.
func e2eAuthPost(t *testing.T, path, cookieValue, csrfToken, jsonBody string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e2eServerURL+path, strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("building %s request: %v", path, err)
	}
	req.Header.Set("Cookie", "__Host-session="+cookieValue)
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// --- E2E tests ---

// TestE2E_Health verifies /health returns per-dependency status against the real server.
func TestE2E_Health(t *testing.T) {
	skipIfNoE2E(t)

	resp, err := http.Get(e2eServerURL + "/health")
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

// TestE2E_Register verifies a new user can be created against real Postgres.
func TestE2E_Register(t *testing.T) {
	skipIfNoE2E(t)
	e2eRegister(t, fmt.Sprintf("e2e-reg-%d@example.com", time.Now().UnixNano()), "e2epassword1")
}

// TestE2E_Register_And_Login verifies the register -> login flow against real Postgres + Redis.
func TestE2E_Register_And_Login(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())
	password := "e2epassword1"

	e2eRegister(t, email, password)
	e2eLogin(t, email, password)
}

// TestE2E_FullRoundTrip_LogoutAll verifies register -> login -> logout-all against real Postgres + Redis.
func TestE2E_FullRoundTrip_LogoutAll(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-loa-%d@example.com", time.Now().UnixNano())
	password := "logoutalldebug1"

	// Step 1: Register + login
	e2eRegister(t, email, password)
	cookieValue, csrfToken := e2eLogin(t, email, password)

	// Step 2: LogoutAll
	resp := e2eAuthPost(t, "/logout-all", cookieValue, csrfToken, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("logout-all: expected 200, got %d", resp.StatusCode)
	}

	// Session cookie must be cleared
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge: expected -1 (cleared), got %d", c.MaxAge)
			}
			return
		}
	}
	t.Error("__Host-session not found in logout-all response")
}

// TestE2E_FullRoundTrip verifies register -> login -> logout against real Postgres + Redis.
func TestE2E_FullRoundTrip(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-rt-%d@example.com", time.Now().UnixNano())
	password := "roundtrippass1"

	// Step 1: Register + login
	e2eRegister(t, email, password)
	cookieValue, csrfToken := e2eLogin(t, email, password)

	// Step 2: Logout
	resp := e2eAuthPost(t, "/logout", cookieValue, csrfToken, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("logout: expected 200, got %d", resp.StatusCode)
	}

	// Session cookie must be cleared
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge: expected -1 (cleared), got %d", c.MaxAge)
			}
			return
		}
	}
	t.Error("__Host-session not found in logout response")
}

// TestE2E_FullRoundTrip_PasswordChange verifies register -> login -> password change ->
// old password rejected -> new password works against real Postgres + Redis.
func TestE2E_FullRoundTrip_PasswordChange(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-pwdch-%d@example.com", time.Now().UnixNano())
	oldPassword := "oldpassword1"
	newPassword := "newpassword1"

	// Step 1: Register
	e2eRegister(t, email, oldPassword)

	// Step 2: Login
	cookieValue, csrfToken := e2eLogin(t, email, oldPassword)

	// Step 3: Change password
	pwdResp := e2eAuthPost(t, "/password/change", cookieValue, csrfToken,
		fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, oldPassword, newPassword))
	defer pwdResp.Body.Close()
	if pwdResp.StatusCode != http.StatusOK {
		t.Fatalf("password change: expected 200, got %d", pwdResp.StatusCode)
	}

	// Session cookie must be cleared in response
	var cookieCleared bool
	for _, c := range pwdResp.Cookies() {
		if c.Name == "__Host-session" {
			cookieCleared = c.MaxAge == -1
			break
		}
	}
	if !cookieCleared {
		t.Error("expected session cookie to be cleared after password change")
	}

	// Step 4: Old password must be rejected
	resp, err := http.Post(e2eServerURL+"/login/email", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, oldPassword)))
	if err != nil {
		t.Fatalf("POST /login/email: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login with old password: expected 401, got %d", resp.StatusCode)
	}

	// Step 5: New password must work
	_, _ = e2eLogin(t, email, newPassword)
}

// TestE2E_PasswordReset_GenericResponse verifies that POST /password/reset returns 200
// for both existing and non-existent emails -- caller cannot distinguish the two.
func TestE2E_PasswordReset_GenericResponse(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-pwdreset-%d@example.com", time.Now().UnixNano())
	e2eRegister(t, email, "resetpassword1")

	// Non-existent email must return 200.
	resp, err := http.Post(e2eServerURL+"/password/reset", "application/json",
		strings.NewReader(`{"email":"doesnotexist-e2e@example.com"}`))
	if err != nil {
		t.Fatalf("POST /password/reset (unknown): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unknown email: expected 200, got %d", resp.StatusCode)
	}

	// Registered email must also return 200.
	resp, err = http.Post(e2eServerURL+"/password/reset", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	if err != nil {
		t.Fatalf("POST /password/reset (registered): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("registered email: expected 200, got %d", resp.StatusCode)
	}
}

// TestE2E_PasswordConfirm_InvalidToken verifies that POST /password/confirm rejects
// a bogus token with 400 -- the route is mounted and token validation runs.
func TestE2E_PasswordConfirm_InvalidToken(t *testing.T) {
	skipIfNoE2E(t)

	resp, err := http.Post(e2eServerURL+"/password/confirm", "application/json",
		strings.NewReader(`{"token":"totallybogustoken","new_password":"newpassword1"}`))
	if err != nil {
		t.Fatalf("POST /password/confirm: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bogus token: expected 400, got %d", resp.StatusCode)
	}
}

// TestE2E_PasswordReset_RouteIsAccessible verifies both password reset routes are mounted
// and reachable -- no 404 or 405 -- and that basic validation runs end-to-end.
func TestE2E_PasswordReset_RouteIsAccessible(t *testing.T) {
	skipIfNoE2E(t)

	// /password/reset returns 200 for any email (enumeration-safe).
	resp, err := http.Post(e2eServerURL+"/password/reset", "application/json",
		strings.NewReader(`{"email":"doesnotexist@example.com"}`))
	if err != nil {
		t.Fatalf("POST /password/reset: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/password/reset: expected 200, got %d", resp.StatusCode)
	}

	// /password/confirm returns 400 for a bad token (route mounted, validation runs).
	resp, err = http.Post(e2eServerURL+"/password/confirm", "application/json",
		strings.NewReader(`{"token":"bogustoken","new_password":"newpassword1"}`))
	if err != nil {
		t.Fatalf("POST /password/confirm: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("/password/confirm: expected 400, got %d", resp.StatusCode)
	}
}

// TestE2E_PasswordChange_DoesNotAffectOtherUser verifies that User A's password change
// does not affect User B's credentials or session against real Postgres + Redis.
func TestE2E_PasswordChange_DoesNotAffectOtherUser(t *testing.T) {
	skipIfNoE2E(t)

	ts := time.Now().UnixNano()
	emailA := fmt.Sprintf("e2e-pwdiso-a-%d@example.com", ts)
	emailB := fmt.Sprintf("e2e-pwdiso-b-%d@example.com", ts)
	passwordA := "passwordA1"
	passwordB := "passwordB1"

	// Register both users
	e2eRegister(t, emailA, passwordA)
	e2eRegister(t, emailB, passwordB)

	// Both log in
	cookieA, csrfA := e2eLogin(t, emailA, passwordA)
	_, _ = e2eLogin(t, emailB, passwordB)

	// User A changes their password
	pwdResp := e2eAuthPost(t, "/password/change", cookieA, csrfA,
		fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, passwordA, "newPasswordA1"))
	pwdResp.Body.Close()
	if pwdResp.StatusCode != http.StatusOK {
		t.Fatalf("password change: expected 200, got %d", pwdResp.StatusCode)
	}

	// User B must still be able to log in with their original password
	_, _ = e2eLogin(t, emailB, passwordB)
}

// e2eRequestPasswordReset calls POST /password/reset and returns the reset token
// captured by e2eMailer. Fatals if the request fails or no token is captured.
func e2eRequestPasswordReset(t *testing.T, email string) string {
	t.Helper()
	e2eMailer.LastResetToken = "" // clear previous capture
	resp, err := http.Post(e2eServerURL+"/password/reset", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	if err != nil {
		t.Fatalf("POST /password/reset: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password/reset: expected 200, got %d", resp.StatusCode)
	}
	if e2eMailer.LastResetToken == "" {
		t.Fatal("password/reset: no token captured by mock mailer")
	}
	return e2eMailer.LastResetToken
}

// e2ePasswordConfirm calls POST /password/confirm with token and new password.
// Returns the response; caller must close the body.
func e2ePasswordConfirm(t *testing.T, token, newPassword string) *http.Response {
	t.Helper()
	resp, err := http.Post(e2eServerURL+"/password/confirm", "application/json",
		strings.NewReader(fmt.Sprintf(`{"token":%q,"new_password":%q}`, token, newPassword)))
	if err != nil {
		t.Fatalf("POST /password/confirm: %v", err)
	}
	return resp
}

// TestE2E_PasswordReset_FullFlow verifies the full password reset flow against
// real Postgres + Redis: request reset email, confirm with token, old sessions cleared,
// old password rejected, new password works, and token replay rejected.
func TestE2E_PasswordReset_FullFlow(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-pwdreset-full-%d@example.com", time.Now().UnixNano())
	oldPassword := "oldresetpass1"
	newPassword := "newresetpass1"

	// Step 1: Register + create two sessions
	e2eRegister(t, email, oldPassword)
	cookie1, csrf1 := e2eLogin(t, email, oldPassword)
	_, _ = e2eLogin(t, email, oldPassword) // second session

	// Step 2: Request password reset — capture token via mock mailer
	token := e2eRequestPasswordReset(t, email)

	// Step 3: Confirm with the token
	confirmResp := e2ePasswordConfirm(t, token, newPassword)
	defer confirmResp.Body.Close()
	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("password/confirm: expected 200, got %d", confirmResp.StatusCode)
	}

	// Step 4: Old sessions must be cleared — authenticated request must return 401
	stalResp := e2eAuthPost(t, "/logout", cookie1, csrf1, "")
	stalResp.Body.Close()
	if stalResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("stale session after reset: expected 401, got %d", stalResp.StatusCode)
	}

	// Step 5: Old password must be rejected
	resp, err := http.Post(e2eServerURL+"/login/email", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, oldPassword)))
	if err != nil {
		t.Fatalf("POST /login/email (old password): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login with old password: expected 401, got %d", resp.StatusCode)
	}

	// Step 6: New password must work
	_, _ = e2eLogin(t, email, newPassword)

	// Step 7: Token replay must be rejected
	replayResp := e2ePasswordConfirm(t, token, "anotherpassword1")
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Errorf("token replay: expected 400, got %d", replayResp.StatusCode)
	}
}
