package auth

// wiring_test.go
//
// Catches bugs where middleware components hand data to each other incorrectly.
//
// Shares the same mock store and cache through both handler and middleware to verify
// the encoding contracts between them:
//
//   - Cookie:      LoginByEmail (set cookie) -> RequireAuth (validate cookie)
//   - CSRF:        LoginByEmail (set CSRF token) -> X-CSRF-Token -> CSRFMiddleware
//   - Context:     RequireAuth (inject context) -> Logout (read context)
//   - Password:    LoginByEmail -> RequireAuth -> PasswordChange (session + store update)
//   - Isolation:   PasswordChange only affects the authenticated user's sessions
//

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
)

// --- Seam test helpers ---

// newUserWithPassword creates a test user with a real Argon2id hash for the given password.
// Both *store.User and its email string are returned.
func newUserWithPassword(t *testing.T, password string) (*store.User, string) {
	t.Helper()
	return newUser(t, "seam@example.com", password)
}

// newUser creates a test user with the given email and a real Argon2id hash for the given password.
// Used when multiple distinct users are needed in one test.
func newUser(t *testing.T, email, password string) (*store.User, string) {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("newUser: hashing password: %v", err)
	}
	e := email
	return &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &e,
		PasswordHash: hash,
	}, email
}

// doLogin calls LoginByEmail with the provided credentials and returns the recorder.
func doLogin(t *testing.T, h *AuthHandler, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	// Concat user registration input, send to login as body of json
	body := strings.NewReader(`{"email":"` + email + `","password":"` + password + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/loginEmail", body)
	w := httptest.NewRecorder()
	// Attempt login, report errors
	h.LoginByEmail(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("doLogin: expected 200, got %d", w.Code)
	}
	return w
}

// getSessionCookie finds the __Host-session cookie from a login response.
func getSessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	// Get "__Host-session" cookie and return it
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-session" {
			return c
		}
	}
	// ERR if cookie not found
	t.Fatal("getSessionCookie: __Host-session not found in response")
	return nil
}

// getCSRFToken decodes the csrf_token string from a login JSON response body.
func getCSRFToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	// Decode CSRF token from body using resp struct
	var resp struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("getCSRFToken: decoding login response: %v", err)
	}
	// Make sure token received
	if resp.CSRFToken == "" {
		t.Fatal("getCSRFToken: csrf_token missing from login response")
	}
	return resp.CSRFToken
}

// --- Seam tests ---

// TestWiring_LoginCookieWorksWithRequireAuth verifies cookie encoding contract.

func TestWiring_LoginCookieWorksWithRequireAuth(t *testing.T) {
	// Create new user
	user, email := newUserWithPassword(t, "password123")
	// Insert into store
	ms := testutil.NewMockStore(user)
	// Create cache
	mc := testutil.NewMockCache()
	// Create handler
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Attempt login
	loginW := doLogin(t, h, email, "password123")
	// Attempt to get cookie
	cookie := getSessionCookie(t, loginW)

	// Create context
	cap := &contextCapture{}
	// Create request, add cookie
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	// Call auth middleware
	h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

	// Log results
	if w.Code != http.StatusOK {
		t.Errorf("RequireAuth: expected 200, got %d (cookie encoding mismatch?)", w.Code)
	}
	if !cap.called {
		t.Fatal("next handler not called — RequireAuth rejected the session cookie set by LoginByEmail")
	}
	if !cap.userIDOK || cap.userID != user.ID {
		t.Errorf("userID: expected %v, got %v (ok=%v)", user.ID, cap.userID, cap.userIDOK)
	}
}

// TestWiring_LoginCSRFTokenWorksWithCSRFMiddleware verifies the CSRF encoding contract.
func TestWiring_LoginCSRFTokenWorksWithCSRFMiddleware(t *testing.T) {
	// Create new user
	user, email := newUserWithPassword(t, "password123")
	// Insert into store
	ms := testutil.NewMockStore(user)
	// Create cache
	mc := testutil.NewMockCache()
	// Create hander
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Attempt login
	loginW := doLogin(t, h, email, "password123")
	// Get cookie
	cookie := getSessionCookie(t, loginW)
	// Get CSRF token
	csrfToken := getCSRFToken(t, loginW)

	// Create new request, add cookie
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(cookie)
	// Set CSRF token in header
	r.Header.Set("X-CSRF-Token", csrfToken)
	w := httptest.NewRecorder()
	// Call Auth handler and CSRF middleware
	h.RequireAuth(h.CSRFMiddleware(passHandler)).ServeHTTP(w, r)

	// Check code
	if w.Code != http.StatusOK {
		t.Errorf("full auth stack: expected 200, got %d (CSRF encoding mismatch?)", w.Code)
	}
}

// TestWiring_WrongCSRFTokenIsRejected verifies the negative case of the CSRF contract.

// A CSRF token from a different session should not pass validation for this session.
// Uses two logins to produce two distinct sessions, then submits cookie from session 1
// with the CSRF token from session 2.
func TestWiring_WrongCSRFTokenIsRejected(t *testing.T) {
	// Create new usesr
	user, email := newUserWithPassword(t, "password123")
	// Create store, add user to it
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	// Create handler
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Login, get session1 cookie session token
	loginW1 := doLogin(t, h, email, "password123")
	cookie1 := getSessionCookie(t, loginW1)

	// Login get session2 CSRF token
	loginW2 := doLogin(t, h, email, "password123")
	csrfToken2 := getCSRFToken(t, loginW2)

	// Cookie from session 1, CSRF token from session 2
	// HAS TO REJECT
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(cookie1)
	r.Header.Set("X-CSRF-Token", csrfToken2)
	w := httptest.NewRecorder()
	h.RequireAuth(h.CSRFMiddleware(passHandler)).ServeHTTP(w, r)

	// Check code
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-session CSRF token, got %d", w.Code)
	}
}

// TestWiring_RequireAuthContextWorksWithLogoutAll verifies logout-all clears all sessions via context.
// Two logins produce two sessions; logout-all via either session must wipe both.
func TestWiring_RequireAuthContextWorksWithLogoutAll(t *testing.T) {
	user, email := newUserWithPassword(t, "password123")
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Two logins — two sessions for the same user.
	doLogin(t, h, email, "password123")
	loginW := doLogin(t, h, email, "password123")
	cookie := getSessionCookie(t, loginW)

	if len(mc.Sessions) != 2 {
		t.Fatalf("expected 2 sessions in cache after two logins, got %d", len(mc.Sessions))
	}

	// LogoutAll using the second session's cookie.
	r := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.RequireAuth(http.HandlerFunc(h.LogoutAll)).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("logout-all: expected 200, got %d", w.Code)
	}

	// All sessions must be gone.
	if len(mc.Sessions) != 0 {
		t.Errorf("expected 0 sessions after logout-all, got %d remaining", len(mc.Sessions))
	}
}

// TestWiring_RequireAuthContextWorksWithLogout verifies the context injection contract.

func TestWiring_RequireAuthContextWorksWithLogout(t *testing.T) {
	// Create new user
	user, email := newUserWithPassword(t, "password123")
	// Add user to new mock store
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	// Create handler
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Login user, get session cookie
	loginW := doLogin(t, h, email, "password123")
	cookie := getSessionCookie(t, loginW)

	// Ensure 1 session stored
	if len(mc.Sessions) != 1 {
		t.Fatalf("expected 1 session in cache after login, got %d", len(mc.Sessions))
	}

	// Logout
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.RequireAuth(http.HandlerFunc(h.Logout)).ServeHTTP(w, r)

	// Ensure logout code OK
	if w.Code != http.StatusOK {
		t.Errorf("logout: expected 200, got %d", w.Code)
	}

	// Session must be gone from the cache, proves Logout computed the same Redis key as Login.
	if len(mc.Sessions) != 0 {
		t.Errorf("session still in cache after logout (token hash encoding mismatch between Login and Logout?): %d remaining", len(mc.Sessions))
	}
}

// --- PasswordChange wiring tests ---

// doPasswordChange calls PasswordChange via RequireAuth with the given session cookie.
func doPasswordChange(t *testing.T, h *AuthHandler, cookie *http.Cookie, currentPassword, newPassword string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"current_password":"` + currentPassword + `","new_password":"` + newPassword + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/password/change", body)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.RequireAuth(http.HandlerFunc(h.PasswordChange)).ServeHTTP(w, r)
	return w
}

// TestWiring_PasswordChange_WorksWithRequireAuth verifies the session cookie from LoginByEmail
// works through RequireAuth into PasswordChange, and that all sessions are cleared on success.
func TestWiring_PasswordChange_WorksWithRequireAuth(t *testing.T) {
	user, email := newUserWithPassword(t, "oldpassword1")
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	loginW := doLogin(t, h, email, "oldpassword1")
	cookie := getSessionCookie(t, loginW)

	if len(mc.Sessions) != 1 {
		t.Fatalf("expected 1 session after login, got %d", len(mc.Sessions))
	}

	w := doPasswordChange(t, h, cookie, "oldpassword1", "newpassword1")

	if w.Code != http.StatusOK {
		t.Errorf("password change: expected 200, got %d", w.Code)
	}
	if len(mc.Sessions) != 0 {
		t.Errorf("expected 0 sessions after password change, got %d", len(mc.Sessions))
	}
}

// TestWiring_PasswordChange_OldPasswordRejectedAfterChange verifies the store update is real:
// the old password must no longer work for login after a successful change.
func TestWiring_PasswordChange_OldPasswordRejectedAfterChange(t *testing.T) {
	user, email := newUserWithPassword(t, "oldpassword1")
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Change password
	loginW := doLogin(t, h, email, "oldpassword1")
	cookie := getSessionCookie(t, loginW)
	if w := doPasswordChange(t, h, cookie, "oldpassword1", "newpassword1"); w.Code != http.StatusOK {
		t.Fatalf("password change: expected 200, got %d", w.Code)
	}

	// Old password must be rejected
	body := strings.NewReader(`{"email":"` + email + `","password":"oldpassword1"}`)
	r := httptest.NewRequest(http.MethodPost, "/login/email", body)
	w := httptest.NewRecorder()
	h.LoginByEmail(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("login with old password after change: expected 401, got %d", w.Code)
	}
}

// --- Cross-user isolation tests ---
//
// Verifies that authenticated operations are strictly scoped to the session owner.
// User A must never be able to affect User B's account or sessions.

// TestWiring_PasswordChange_DoesNotAffectOtherUser verifies User A's password change
// only clears User A's sessions and does not alter User B's password or sessions.
func TestWiring_PasswordChange_DoesNotAffectOtherUser(t *testing.T) {
	userA, emailA := newUser(t, "a@example.com", "passwordA1")
	userB, emailB := newUser(t, "b@example.com", "passwordB1")
	ms := testutil.NewMockStore(userA, userB)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Both users log in
	doLogin(t, h, emailB, "passwordB1")
	loginW := doLogin(t, h, emailA, "passwordA1")
	cookie := getSessionCookie(t, loginW)

	if len(mc.Sessions) != 2 {
		t.Fatalf("expected 2 sessions before password change, got %d", len(mc.Sessions))
	}

	// User A changes their password
	if w := doPasswordChange(t, h, cookie, "passwordA1", "newPasswordA1"); w.Code != http.StatusOK {
		t.Fatalf("password change: expected 200, got %d", w.Code)
	}

	// User B's session must still be in the cache
	if len(mc.Sessions) != 1 {
		t.Errorf("expected 1 session remaining (User B's) after User A's password change, got %d", len(mc.Sessions))
	}

	// User B must still be able to log in with their original password
	body := strings.NewReader(`{"email":"` + emailB + `","password":"passwordB1"}`)
	r := httptest.NewRequest(http.MethodPost, "/login/email", body)
	w := httptest.NewRecorder()
	h.LoginByEmail(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("user B login after user A password change: expected 200, got %d", w.Code)
	}
}

// TestWiring_LogoutAll_DoesNotAffectOtherUser verifies User A's logout-all
// only clears User A's sessions, leaving User B's sessions intact.
func TestWiring_LogoutAll_DoesNotAffectOtherUser(t *testing.T) {
	userA, emailA := newUser(t, "a@example.com", "passwordA1")
	userB, _ := newUser(t, "b@example.com", "passwordB1")
	ms := testutil.NewMockStore(userA, userB)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Both users log in
	doLogin(t, h, "b@example.com", "passwordB1")
	loginW := doLogin(t, h, emailA, "passwordA1")
	cookie := getSessionCookie(t, loginW)

	if len(mc.Sessions) != 2 {
		t.Fatalf("expected 2 sessions before logout-all, got %d", len(mc.Sessions))
	}

	// User A logs out of all devices
	r := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.RequireAuth(http.HandlerFunc(h.LogoutAll)).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("logout-all: expected 200, got %d", w.Code)
	}

	// User B's session must still be in the cache
	if len(mc.Sessions) != 1 {
		t.Errorf("expected 1 session remaining (User B's) after User A's logout-all, got %d", len(mc.Sessions))
	}
}

// --- PasswordReset wiring tests ---

// doPasswordReset calls PasswordReset with the given email; fatals if response is not 200.
func doPasswordReset(t *testing.T, h *AuthHandler, email string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"email":"` + email + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
	w := httptest.NewRecorder()
	h.PasswordReset(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("doPasswordReset: expected 200, got %d", w.Code)
	}
	return w
}

// doPasswordConfirm calls PasswordConfirm with the given token and new password.
func doPasswordConfirm(t *testing.T, h *AuthHandler, token, newPassword string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"token":"` + token + `","new_password":"` + newPassword + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/auth/password/confirm", body)
	w := httptest.NewRecorder()
	h.PasswordConfirm(w, r)
	return w
}

// TestWiring_PasswordReset_TokenRoundTrip verifies the token encoding contract between
// PasswordReset and PasswordConfirm. Both share one MockStore and one MockMailer.
// If either side encodes differently, ConsumeToken misses and PasswordConfirm returns 400.
func TestWiring_PasswordReset_TokenRoundTrip(t *testing.T) {
	user, email := newUserWithPassword(t, "oldpassword1")
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	mailer := &testutil.MockMailer{}
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: mailer}

	// PasswordReset: stores SHA-256 hash in ms.Tokens, sends base64 raw token to mailer.
	doPasswordReset(t, h, email)

	token := mailer.LastSentToken
	if token == "" {
		t.Fatal("PasswordReset: expected mailer to capture token, got empty string")
	}

	// PasswordConfirm: decodes base64 token, rehashes, calls ConsumeToken with same hash.
	// Any encoding mismatch causes ConsumeToken to miss (400 instead of 200).
	w := doPasswordConfirm(t, h, token, "newpassword1")

	if w.Code != http.StatusOK {
		t.Errorf("PasswordConfirm: expected 200, got %d (token encoding mismatch?)", w.Code)
	}
}

// TestWiring_PasswordConfirm_ClearsSessions verifies PasswordConfirm removes the user's
// sessions from both MockStore and MockCache after a successful confirm.
func TestWiring_PasswordConfirm_ClearsSessions(t *testing.T) {
	user, email := newUserWithPassword(t, "oldpassword1")
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	mailer := &testutil.MockMailer{}
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: mailer}

	// Two logins — two sessions for the same user.
	doLogin(t, h, email, "oldpassword1")
	doLogin(t, h, email, "oldpassword1")

	if len(mc.Sessions) != 2 {
		t.Fatalf("expected 2 sessions in cache after two logins, got %d", len(mc.Sessions))
	}

	// Initiate reset and capture token.
	doPasswordReset(t, h, email)
	token := mailer.LastSentToken

	// Confirm -- should clear all sessions for this user in both store and cache.
	w := doPasswordConfirm(t, h, token, "newpassword1")

	if w.Code != http.StatusOK {
		t.Fatalf("PasswordConfirm: expected 200, got %d", w.Code)
	}
	if len(mc.Sessions) != 0 {
		t.Errorf("expected 0 sessions in cache after password confirm, got %d", len(mc.Sessions))
	}
	if len(ms.Sessions) != 0 {
		t.Errorf("expected 0 sessions in store after password confirm, got %d", len(ms.Sessions))
	}
}

// TestWiring_Logout_DoesNotAffectOtherUser verifies User A's logout only removes
// User A's current session, leaving User B's sessions intact.
func TestWiring_Logout_DoesNotAffectOtherUser(t *testing.T) {
	userA, emailA := newUser(t, "a@example.com", "passwordA1")
	userB, _ := newUser(t, "b@example.com", "passwordB1")
	ms := testutil.NewMockStore(userA, userB)
	mc := testutil.NewMockCache()
	h := &AuthHandler{PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}}

	// Both users log in
	doLogin(t, h, "b@example.com", "passwordB1")
	loginW := doLogin(t, h, emailA, "passwordA1")
	cookie := getSessionCookie(t, loginW)

	if len(mc.Sessions) != 2 {
		t.Fatalf("expected 2 sessions before logout, got %d", len(mc.Sessions))
	}

	// User A logs out of current session
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.RequireAuth(http.HandlerFunc(h.Logout)).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("logout: expected 200, got %d", w.Code)
	}

	// User B's session must still be in the cache
	if len(mc.Sessions) != 1 {
		t.Errorf("expected 1 session remaining (User B's) after User A's logout, got %d", len(mc.Sessions))
	}
}
