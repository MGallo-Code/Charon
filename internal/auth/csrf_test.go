// csrf_test.go

// unit tests for GenerateCSRFToken, ValidateCSRFToken, and CSRFMiddleware.
package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// mockSessionCache implements SessionCache for unit tests.
type mockSessionCache struct {
	sessions         map[string]*store.CachedSession
	setSessionErr    error
	deleteSessionErr error
}

// GetSession retrieves session by token hash.
func (m *mockSessionCache) GetSession(_ context.Context, tokenHash string) (*store.CachedSession, error) {
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return s, nil
}

// SetSession stores session in mock cache. Stateful for round-trip tests.
func (m *mockSessionCache) SetSession(_ context.Context, tokenHash string, sessionData store.Session, ttl int) error {
	if m.setSessionErr != nil {
		return m.setSessionErr
	}
	if m.sessions == nil {
		m.sessions = make(map[string]*store.CachedSession)
	}
	m.sessions[tokenHash] = &store.CachedSession{
		UserID:    sessionData.UserID,
		CSRFToken: sessionData.CSRFToken,
		ExpiresAt: sessionData.ExpiresAt,
	}
	return nil
}

// DeleteSession removes session by token hash.
func (m *mockSessionCache) DeleteSession(_ context.Context, tokenHash string, userID uuid.UUID) error {
	if m.deleteSessionErr != nil {
		return m.deleteSessionErr
	}
	delete(m.sessions, tokenHash)
	return nil
}

// passHandler returns 200 when reached — proves middleware let request through.
var passHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// csrfTestSetup holds handler and CSRF token for CSRFMiddleware tests.
// CSRFMiddleware reads the stored token from context (injected by RequireAuth),
// so setup injects the CSRF token directly — no session cache needed.
type csrfTestSetup struct {
	handler     http.Handler
	csrfToken   [32]byte // raw CSRF token
	headerValue string   // base64-encoded for X-CSRF-Token header
}

// newCSRFTestSetup builds handler simulating RequireAuth -> CSRFMiddleware with injected CSRF token.
func newCSRFTestSetup() csrfTestSetup {
	var csrfToken [32]byte
	for i := range csrfToken {
		csrfToken[i] = byte(i + 100)
	}

	h := &AuthHandler{}

	// Inject CSRF token as RequireAuth would.
	injectCtx := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), csrfTokenKey, csrfToken[:])
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	return csrfTestSetup{
		handler:     injectCtx(h.CSRFMiddleware(passHandler)),
		csrfToken:   csrfToken,
		headerValue: base64.RawURLEncoding.EncodeToString(csrfToken[:]),
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
		req := httptest.NewRequest(http.MethodGet, "/", nil)
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
		req := httptest.NewRequest(http.MethodHead, "/", nil)
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
		req := httptest.NewRequest(http.MethodOptions, "/", nil)
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
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with invalid base64 CSRF header returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-CSRF-Token", "!!!not-valid-base64!!!")
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with wrong-length CSRF token returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		// 16 bytes instead of required 32
		short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
		req.Header.Set("X-CSRF-Token", short)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST without CSRF token in context returns 403", func(t *testing.T) {
		// Simulates RequireAuth not running, or context missing the CSRF token.
		h := &AuthHandler{}
		handler := h.CSRFMiddleware(passHandler)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-CSRF-Token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with CSRF token mismatch returns 403", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		// Wrong CSRF token (all zeros instead of real one)
		wrong := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		req.Header.Set("X-CSRF-Token", wrong)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	t.Run("POST with short stored CSRF token in context returns 403", func(t *testing.T) {
		// Server-side token wrong length (16 bytes instead of 32)
		// (guards against corrupt context)
		h := &AuthHandler{}
		injectShort := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), csrfTokenKey, make([]byte, 16))
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		handler := injectShort(h.CSRFMiddleware(passHandler))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-CSRF-Token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assertForbidden(t, w.Result())
	})

	// -- Valid requests pass through --

	t.Run("POST with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("PUT with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPut, "/", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("DELETE with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("PATCH with valid CSRF passes through", func(t *testing.T) {
		setup := newCSRFTestSetup()
		req := httptest.NewRequest(http.MethodPatch, "/", nil)
		req.Header.Set("X-CSRF-Token", setup.headerValue)
		w := httptest.NewRecorder()

		setup.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})
}
