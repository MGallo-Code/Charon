// middleware_test.go

// unit tests for RequireAuth middleware.
package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// contextCapture records context values injected by RequireAuth for downstream assertion.
type contextCapture struct {
	called      bool
	userID      uuid.UUID
	userIDOK    bool
	tokenHash   []byte
	tokenHashOK bool
	csrfToken   []byte
	csrfTokenOK bool
}

// capturingHandler records context values then responds 200.
func capturingHandler(cap *contextCapture) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.called = true
		cap.userID, cap.userIDOK = UserIDFromContext(r.Context())
		cap.tokenHash, cap.tokenHashOK = TokenHashFromContext(r.Context())
		cap.csrfToken, cap.csrfTokenOK = CSRFTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

// sessionFixture returns deterministic session material for RequireAuth tests.
//   - cookie: base64-encoded raw token (for the __Host-session cookie value)
//   - wantHash: SHA-256(token) as bytes (what should appear in context)
//   - redisKey: base64-encoded wantHash (Redis lookup key used by middleware)
func sessionFixture() (cookie string, wantHash []byte, redisKey string) {
	var token [32]byte
	for i := range token {
		token[i] = byte(i + 1)
	}
	h := sha256.Sum256(token[:])
	wantHash = h[:]
	redisKey = base64.RawURLEncoding.EncodeToString(wantHash)
	cookie = base64.RawURLEncoding.EncodeToString(token[:])
	return
}

// addSessionCookie adds __Host-session cookie to request.
func addSessionCookie(r *http.Request, value string) {
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: value})
}

// --- RequireAuth ---

func TestRequireAuth(t *testing.T) {
	t.Run("missing cookie returns Unauthorized", func(t *testing.T) {
		h := &AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
	})

	t.Run("empty cookie value returns Unauthorized", func(t *testing.T) {
		h := &AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, "")

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
	})

	t.Run("invalid base64 cookie returns Unauthorized", func(t *testing.T) {
		h := &AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, "not!!valid!!base64!!")

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
	})

	t.Run("Redis hit calls next with userID, tokenHash, and csrfToken in context", func(t *testing.T) {
		cookie, wantHash, redisKey := sessionFixture()
		wantUserID := uuid.Must(uuid.NewV4())
		wantCSRF := []byte("csrf-token-value")

		mc := &testutil.MockCache{
			Sessions: map[string]*store.CachedSession{
				redisKey: {
					UserID:    wantUserID,
					CSRFToken: wantCSRF,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
		}
		h := &AuthHandler{PS: &testutil.MockStore{}, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		if !cap.called {
			t.Fatal("next handler was not called")
		}
		if !cap.userIDOK || cap.userID != wantUserID {
			t.Errorf("userID: expected %v, got %v (ok=%v)", wantUserID, cap.userID, cap.userIDOK)
		}
		if !cap.tokenHashOK || !bytes.Equal(cap.tokenHash, wantHash) {
			t.Errorf("tokenHash: expected %x, got %x (ok=%v)", wantHash, cap.tokenHash, cap.tokenHashOK)
		}
		if !cap.csrfTokenOK || !bytes.Equal(cap.csrfToken, wantCSRF) {
			t.Errorf("csrfToken: expected %x, got %x (ok=%v)", wantCSRF, cap.csrfToken, cap.csrfTokenOK)
		}
	})

	t.Run("Redis miss Postgres hit calls next and repopulates Redis", func(t *testing.T) {
		cookie, wantHash, redisKey := sessionFixture()
		wantUserID := uuid.Must(uuid.NewV4())
		wantCSRF := []byte("csrf-token-value")

		mc := testutil.NewMockCache() // empty — forces Redis miss
		ms := &testutil.MockStore{
			Sessions: map[string]*store.Session{
				string(wantHash): {
					ID:        uuid.Must(uuid.NewV4()),
					UserID:    wantUserID,
					TokenHash: wantHash,
					CSRFToken: wantCSRF,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
		}
		h := &AuthHandler{PS: ms, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		if !cap.called {
			t.Fatal("next handler was not called")
		}
		if !cap.userIDOK || cap.userID != wantUserID {
			t.Errorf("userID: expected %v, got %v (ok=%v)", wantUserID, cap.userID, cap.userIDOK)
		}
		if !cap.tokenHashOK || !bytes.Equal(cap.tokenHash, wantHash) {
			t.Errorf("tokenHash: expected %x, got %x (ok=%v)", wantHash, cap.tokenHash, cap.tokenHashOK)
		}
		if !cap.csrfTokenOK || !bytes.Equal(cap.csrfToken, wantCSRF) {
			t.Errorf("csrfToken: expected %x, got %x (ok=%v)", wantCSRF, cap.csrfToken, cap.csrfTokenOK)
		}
		// Middleware should have repopulated Redis after falling back to Postgres.
		if _, ok := mc.Sessions[redisKey]; !ok {
			t.Error("expected Redis to be repopulated after Postgres fallback")
		}
	})

	t.Run("Redis miss Postgres ErrNoRows returns Unauthorized", func(t *testing.T) {
		cookie, _, _ := sessionFixture()

		mc := testutil.NewMockCache() // empty — forces Redis miss
		ms := &testutil.MockStore{GetSessionErr: pgx.ErrNoRows}
		h := &AuthHandler{PS: ms, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
	})

	t.Run("Redis miss Postgres error returns Unauthorized", func(t *testing.T) {
		cookie, _, _ := sessionFixture()

		mc := testutil.NewMockCache() // empty — forces Redis miss
		ms := &testutil.MockStore{GetSessionErr: errors.New("database connection failed")}
		h := &AuthHandler{PS: ms, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
	})

	t.Run("Redis repopulate failure is non-fatal", func(t *testing.T) {
		cookie, wantHash, _ := sessionFixture()
		wantUserID := uuid.Must(uuid.NewV4())
		wantCSRF := []byte("csrf-token-value")

		// Redis miss + SetSession fails, but Postgres succeeds — request should still pass.
		mc := &testutil.MockCache{SetSessionErr: errors.New("redis unavailable")}
		ms := &testutil.MockStore{
			Sessions: map[string]*store.Session{
				string(wantHash): {
					ID:        uuid.Must(uuid.NewV4()),
					UserID:    wantUserID,
					TokenHash: wantHash,
					CSRFToken: wantCSRF,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
		}
		h := &AuthHandler{PS: ms, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		if !cap.called {
			t.Fatal("next handler was not called")
		}
		if !cap.userIDOK || cap.userID != wantUserID {
			t.Errorf("userID: expected %v, got %v (ok=%v)", wantUserID, cap.userID, cap.userIDOK)
		}
		if !cap.tokenHashOK || !bytes.Equal(cap.tokenHash, wantHash) {
			t.Errorf("tokenHash: expected %x, got %x (ok=%v)", wantHash, cap.tokenHash, cap.tokenHashOK)
		}
		if !cap.csrfTokenOK || !bytes.Equal(cap.csrfToken, wantCSRF) {
			t.Errorf("csrfToken: expected %x, got %x (ok=%v)", wantCSRF, cap.csrfToken, cap.csrfTokenOK)
		}
	})

	t.Run("tombstoned session returns Unauthorized without Postgres fallback", func(t *testing.T) {
		cookie, _, redisKey := sessionFixture()

		// Mark key as tombstoned in cache.
		mc := testutil.NewMockCache()
		mc.Tombstones[redisKey] = true

		// Postgres has a valid session -- it must never be reached.
		ms := &testutil.MockStore{
			Sessions: map[string]*store.Session{
				"any": {ExpiresAt: time.Now().Add(time.Hour)},
			},
		}
		h := &AuthHandler{PS: ms, RS: mc}
		cap := &contextCapture{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		addSessionCookie(r, cookie)

		h.RequireAuth(capturingHandler(cap)).ServeHTTP(w, r)

		assertUnauthorized(t, w, "unauthorized")
		if cap.called {
			t.Error("next handler should not have been called")
		}
		// Postgres must not have been queried -- GetSessionErr being nil with no session
		// hit means the fallback was skipped entirely.
		if ms.GetSessionErr != nil {
			t.Error("expected no Postgres lookup for tombstoned session")
		}
	})
}
