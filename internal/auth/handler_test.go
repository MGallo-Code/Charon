// handler_test.go

// Shared test helpers and TestCheckCaptcha for the auth package.
// Handler-specific tests live in their own _handler_test.go files.
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
)

// --- Shared assert helpers ---

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

// --- Shared request helpers ---

// requestWithSession builds request with userID and tokenHash pre-loaded into context,
// simulates a request that has already passed through RequireAuth middleware.
func requestWithSession(userID uuid.UUID, tokenHash []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	ctx := context.WithValue(r.Context(), userIDKey, userID)
	ctx = context.WithValue(ctx, tokenHashKey, tokenHash)
	return r.WithContext(ctx)
}

// pwdChangeReq builds a POST /password/change request with userID injected in context.
func pwdChangeReq(userID uuid.UUID, currentPwd, newPwd string) *http.Request {
	body := strings.NewReader(fmt.Sprintf(
		`{"current_password":%q,"new_password":%q}`, currentPwd, newPwd,
	))
	r := httptest.NewRequest(http.MethodPost, "/password/change", body)
	ctx := context.WithValue(r.Context(), userIDKey, userID)
	return r.WithContext(ctx)
}

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

// --- checkCaptcha ---

func TestCheckCaptcha(t *testing.T) {
	makeReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/", nil)
	}

	t.Run("CV nil required false returns true (skip)", func(t *testing.T) {
		h := AuthHandler{}
		w := httptest.NewRecorder()
		if !h.checkCaptcha(w, makeReq(), "token", false) {
			t.Error("expected true (skip), got false")
		}
	})

	t.Run("CV nil required true returns true (skip)", func(t *testing.T) {
		h := AuthHandler{}
		w := httptest.NewRecorder()
		if !h.checkCaptcha(w, makeReq(), "token", true) {
			t.Error("expected true (skip), got false")
		}
	})

	t.Run("CV set required false returns true (skip)", func(t *testing.T) {
		h := AuthHandler{CV: &testutil.MockCaptchaVerifier{VerifyErr: errors.New("would fail")}}
		w := httptest.NewRecorder()
		if !h.checkCaptcha(w, makeReq(), "token", false) {
			t.Error("expected true (skip), got false")
		}
	})

	t.Run("CV set required true verify ok returns true", func(t *testing.T) {
		h := AuthHandler{CV: &testutil.MockCaptchaVerifier{}}
		w := httptest.NewRecorder()
		if !h.checkCaptcha(w, makeReq(), "token", true) {
			t.Error("expected true, got false")
		}
	})

	t.Run("CV set required true verify fails returns false and 400", func(t *testing.T) {
		h := AuthHandler{CV: &testutil.MockCaptchaVerifier{VerifyErr: errors.New("rejected")}}
		w := httptest.NewRecorder()
		if h.checkCaptcha(w, makeReq(), "token", true) {
			t.Error("expected false, got true")
		}
		assertBadRequest(t, w, "captcha verification failed")
	})
}
