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
)

// e2eServerURL is the base URL of the running test server.
// Empty if the compose stack is not up; e2e tests skip in that case.
var e2eServerURL string

func TestMain(m *testing.M) {
	cfg := &config.Config{
		DatabaseURL: envOrDefault("TEST_DATABASE_URL", "postgres://test_user:test_pass@localhost:5433/charon_test"),
		RedisURL:    envOrDefault("TEST_REDIS_URL", "redis://localhost:6380"),
		Port:        "0", // OS picks a free port
		LogLevel:    slog.LevelWarn,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	runErr := make(chan error, 1)

	go func() {
		runErr <- run(ctx, cfg, ready)
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

// --- E2E tests ---

// TestE2E_Health verifies /health returns {"status":"ok"} against the real server.
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
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf(`body.status: expected "ok", got %q`, body.Status)
	}
}

// TestE2E_Register verifies a new user can be created against real Postgres.
func TestE2E_Register(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-reg-%d@example.com", time.Now().UnixNano())
	password := "e2epassword1"

	resp, err := http.Post(e2eServerURL+"/registerEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /registerEmail: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status: expected 201, got %d", resp.StatusCode)
	}
}

// TestE2E_Register_And_Login verifies the register -> login flow against real Postgres + Redis.
func TestE2E_Register_And_Login(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())
	password := "e2epassword1"

	// Register
	regResp, err := http.Post(e2eServerURL+"/registerEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /registerEmail: %v", err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", regResp.StatusCode)
	}

	// Login
	loginResp, err := http.Post(e2eServerURL+"/loginEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /loginEmail: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", loginResp.StatusCode)
	}

	// Session cookie must be set
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "__Host-session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("__Host-session cookie not set after login")
	}

	// Body must have user_id and csrf_token
	var body struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding login response: %v", err)
	}
	if body.UserID == "" {
		t.Error("user_id missing from login response")
	}
	if body.CSRFToken == "" {
		t.Error("csrf_token missing from login response")
	}
}

// TestE2E_FullRoundTrip_LogoutAll verifies register -> login -> logout-all against real Postgres + Redis.
func TestE2E_FullRoundTrip_LogoutAll(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-loa-%d@example.com", time.Now().UnixNano())
	password := "logoutalldebug1"

	// Step 1: Register
	regResp, err := http.Post(e2eServerURL+"/registerEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /registerEmail: %v", err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", regResp.StatusCode)
	}

	// Step 2: Login -- capture session cookie and CSRF token
	loginResp, err := http.Post(e2eServerURL+"/loginEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /loginEmail: %v", err)
	}
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

	// Step 3: LogoutAll -- pass session cookie and CSRF token
	req, err := http.NewRequest(http.MethodPost, e2eServerURL+"/logout-all", nil)
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

	// Session cookie must be cleared
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

// TestE2E_FullRoundTrip verifies register -> login -> logout against real Postgres + Redis.
func TestE2E_FullRoundTrip(t *testing.T) {
	skipIfNoE2E(t)

	email := fmt.Sprintf("e2e-rt-%d@example.com", time.Now().UnixNano())
	password := "roundtrippass1"

	// Step 1: Register
	regResp, err := http.Post(e2eServerURL+"/registerEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /registerEmail: %v", err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", regResp.StatusCode)
	}

	// Step 2: Login -- capture session cookie and CSRF token
	loginResp, err := http.Post(e2eServerURL+"/loginEmail", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
	if err != nil {
		t.Fatalf("POST /loginEmail: %v", err)
	}
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

	// Step 3: Logout -- pass session cookie and CSRF token
	req, err := http.NewRequest(http.MethodPost, e2eServerURL+"/logout", nil)
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

	// Session cookie must be cleared in logout response
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
