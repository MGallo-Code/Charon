package auth

// wiring_test.go
//
// Catches bugs where middleware components hand data to each other incorrectly.
//
// Shares the same mock store and cache through both handler and middleware to verify
// the encoding contracts between them:
//
//   - Cookie:   LoginByEmail (set cookie) -> RequireAuth (validate cookie)
//   - CSRF:     LoginByEmail (set CSRF token) -> X-CSRF-Token -> CSRFMiddleware
//   - Context:  RequireAuth (inject context) -> Logout (read context)
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
	email := "seam@example.com"
	// Attempt to hash pwd
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("newUserWithPassword: hashing password: %v", err)
	}
	// Return user info in User object
	return &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &email,
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
	h := &AuthHandler{PS: ms, RS: mc}

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
	h := &AuthHandler{PS: ms, RS: mc}

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
	h := &AuthHandler{PS: ms, RS: mc}

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

// TestWiring_RequireAuthContextWorksWithLogout verifies the context injection contract.

func TestWiring_RequireAuthContextWorksWithLogout(t *testing.T) {
	// Create new user
	user, email := newUserWithPassword(t, "password123")
	// Add user to new mock store
	ms := testutil.NewMockStore(user)
	mc := testutil.NewMockCache()
	// Create handler
	h := &AuthHandler{PS: ms, RS: mc}

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
