package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"context"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// mockSessionCache implements SessionCache for handler unit tests.
type mockSessionCache struct {
	sessions map[string]*store.CachedSession
}

// Mock function to "GetSession" using tokenHash, gets session stored in mockSessionCache
func (m *mockSessionCache) GetSession(_ context.Context, tokenHash string) (*store.CachedSession, error) {
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return s, nil
}

// passHandler returns 200 when reached — proves middleware let request through.
var passHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// csrfTestSetup holds all pieces needed for a valid CSRF request.
type csrfTestSetup struct {
	handler      http.Handler
	sessionToken [32]byte // raw session token
	csrfToken    [32]byte // raw CSRF token
	cookieValue  string   // base64-encoded session token
	headerValue  string   // base64-encoded CSRF token
}

// newCSRFTestSetup creates handler wired to mock cache with matching session + CSRF.
// Uses deterministic tokens so tests are reproducible.
func newCSRFTestSetup() csrfTestSetup {
	// Deterministic tokens for testing
	var sessionToken, csrfToken [32]byte
	for i := range sessionToken {
		sessionToken[i] = byte(i)
	}
	for i := range csrfToken {
		csrfToken[i] = byte(i + 100)
	}

	tokenHash := sha256.Sum256(sessionToken[:])
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	// Mock session cache
	mock := &mockSessionCache{
		sessions: map[string]*store.CachedSession{
			tokenHashHex: {
				UserID:    uuid.Must(uuid.NewV4()),
				CSRFToken: csrfToken[:],
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		},
	}

	// Create AuthHandler with mock redis store
	h := &AuthHandler{RS: mock}
	// Create test setup struct, add middleware that leads to status 200 on success, encode token vals
	return csrfTestSetup{
		handler:      h.CSRFMiddleware(passHandler),
		sessionToken: sessionToken,
		csrfToken:    csrfToken,
		cookieValue:  base64.RawURLEncoding.EncodeToString(sessionToken[:]),
		headerValue:  base64.RawURLEncoding.EncodeToString(csrfToken[:]),
	}
}

// assertForbidden checks response is 403 JSON with generic error body.
func assertForbidden(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: expected 403, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"error":"forbidden"}` {
		t.Errorf("body: expected {\"error\":\"forbidden\"}, got %q", string(body))
	}
}

// --- GenerateCSRFToken ---

func TestGenerateCSRFToken(t *testing.T) {
	//These are pretty straightforward at this point
	t.Run("returns 32-byte token without error", func(t *testing.T) {
		token, err := GenerateCSRFToken()
		if err != nil {
			t.Fatalf("GenerateCSRFToken returned error: %v", err)
		}
		if token == nil {
			t.Fatal("token should not be nil")
		}
	})

	t.Run("unique tokens per call", func(t *testing.T) {
		t1, err := GenerateCSRFToken()
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		t2, err := GenerateCSRFToken()
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if *t1 == *t2 {
			t.Error("two tokens should differ (unique random bytes)")
		}
	})
}

// --- ValidateCSRFToken ---

func TestValidateCSRFToken(t *testing.T) {
	t.Run("matching tokens return true", func(t *testing.T) {
		var token [32]byte
		for i := range token {
			token[i] = byte(i)
		}
		if !ValidateCSRFToken(token, token) {
			t.Error("identical tokens should match")
		}
	})

	t.Run("different tokens return false", func(t *testing.T) {
		var a, b [32]byte
		a[0] = 0xAA
		b[0] = 0xBB
		if ValidateCSRFToken(a, b) {
			t.Error("different tokens should not match")
		}
	})

	t.Run("off-by-one byte returns false", func(t *testing.T) {
		var a, b [32]byte
		for i := range a {
			a[i] = byte(i)
			b[i] = byte(i)
		}
		b[31] ^= 0x01 // flip one bit in last byte
		if ValidateCSRFToken(a, b) {
			t.Error("off-by-one tokens should not match")
		}
	})
}

// --- CSRFMiddleware ---

func TestCSRFMiddleware(t *testing.T) {
	// -- Safe methods pass through without CSRF check --

	t.Run("GET passes through", func(t *testing.T) {
		// Setup mock
		setup := newCSRFTestSetup()
		// GET req to generic route
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		// Test writer/recorder
		w := httptest.NewRecorder()

		// ServE!
		setup.handler.ServeHTTP(w, req)

		// Should be ok
		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("HEAD passes through", func(t *testing.T) {
		// Setup mock
		setup := newCSRFTestSetup()
		// HEAD req
		req := httptest.NewRequest(http.MethodHead, "/anything", nil)
		w := httptest.NewRecorder()

		// ServE!
		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("OPTIONS passes through", func(t *testing.T) {
		// Setup mock
		setup := newCSRFTestSetup()
		// OPTIONS req
		req := httptest.NewRequest(http.MethodOptions, "/anything", nil)
		w := httptest.NewRecorder()

		// ServE!
		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Rejection cases --

	t.Run("POST without CSRF header returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with invalid base64 CSRF header returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", "!!!not-valid-base64!!!")
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with wrong-length CSRF token returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		// 16 bytes instead of 32
		short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
		req.Header.Set("X-CSRF-Token", short)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST without session cookie returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with empty session cookie returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: ""})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with invalid cookie encoding returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: "!!!bad-base64!!!"})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with unknown session returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		// Valid base64 but not in mock cache
		unknown := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: unknown})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with CSRF token mismatch returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		// Wrong CSRF token (all zeros instead of real one)
		wrong := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		req.Header.Set("X-CSRF-Token", wrong)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with short stored CSRF token returns 403", func(t *testing.T) {
		// Session exists but server-side CSRF token is wrong length.
		// Needs custom mock, so can't use newCSRFTestSetup() handler directly.
		setup := newCSRFTestSetup()
		tokenHash := sha256.Sum256(setup.sessionToken[:])
		mock := &mockSessionCache{
			sessions: map[string]*store.CachedSession{
				hex.EncodeToString(tokenHash[:]): {
					UserID:    uuid.Must(uuid.NewV4()),
					CSRFToken: make([]byte, 16), // wrong length
					ExpiresAt: time.Now().Add(24 * time.Hour),
				},
			},
		}
		h := &AuthHandler{RS: mock}
		handler := h.CSRFMiddleware(passHandler)

		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	// -- Valid requests pass through --

	t.Run("POST with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("PUT with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPut, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("DELETE with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodDelete, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("PATCH with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPatch, "/action", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: setup.cookieValue})
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})
}
