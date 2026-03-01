// oauth_test.go -- unit tests for OAuthRedirect, OAuthCallback, and findOrCreateOAuthUser.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/oauth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// --- Shared helpers ---

// mockProvider implements oauth.Provider for tests.
type mockProvider struct {
	name        string
	authCodeURL string
	claims      *oauth.Claims
	exchangeErr error
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) AuthCodeURL(state, _ string) string {
	return m.authCodeURL + "?state=" + state
}
func (m *mockProvider) Exchange(_ context.Context, _, _ string) (*oauth.Claims, error) {
	return m.claims, m.exchangeErr
}

// makeStateCookie builds a valid __Host-oauth-state cookie value for use in callback tests.
func makeStateCookie(state, verifier string) string {
	payload, _ := json.Marshal(oauthStateCookie{State: state, Verifier: verifier})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// makeCallbackRequest builds a GET callback request with a chi route context,
// the given state cookie value, and ?state=<state>&code=<code> query params.
func makeCallbackRequest(cookieVal, state, code string) *http.Request {
	r := httptest.NewRequest("GET", "/oauth/google/callback?state="+state+"&code="+code, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-oauth-state", Value: cookieVal})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// baseCallbackHandler returns an AuthHandler wired with the given store, cache,
// and provider claims for the "google" provider.
func baseCallbackHandler(ms *testutil.MockStore, mc *testutil.MockCache, claims *oauth.Claims) AuthHandler {
	return AuthHandler{
		PS:         ms,
		RS:         mc,
		RL:         &testutil.MockRateLimiter{},
		ML:         &testutil.MockMailer{},
		SessionTTL: 24 * time.Hour,
		OAuthProviders: map[string]oauth.Provider{
			"google": &mockProvider{name: "google", claims: claims},
		},
	}
}

// --- OAuthRedirect ---

// TestOAuthRedirect_UnknownProvider expects 404 when provider is not registered.
func TestOAuthRedirect_UnknownProvider(t *testing.T) {
	h := AuthHandler{
		PS:             testutil.NewMockStore(),
		RS:             testutil.NewMockCache(),
		RL:             &testutil.MockRateLimiter{},
		ML:             &testutil.MockMailer{},
		SessionTTL:     24 * time.Hour,
		OAuthProviders: map[string]oauth.Provider{},
	}

	r := httptest.NewRequest(http.MethodGet, "/oauth/google", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.OAuthRedirect(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: expected 404, got %d", w.Code)
	}
}

// TestOAuthRedirect_ValidProvider expects 302 redirect with state cookie set.
func TestOAuthRedirect_ValidProvider(t *testing.T) {
	h := AuthHandler{
		PS:         testutil.NewMockStore(),
		RS:         testutil.NewMockCache(),
		RL:         &testutil.MockRateLimiter{},
		ML:         &testutil.MockMailer{},
		SessionTTL: 24 * time.Hour,
		OAuthProviders: map[string]oauth.Provider{
			"google": &mockProvider{name: "google", authCodeURL: "https://mock.provider.test/auth"},
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/oauth/google", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.OAuthRedirect(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status: expected 302, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "https://mock.provider.test/auth") {
		t.Errorf("Location: expected to contain provider URL, got %q", loc)
	}

	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-oauth-state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("__Host-oauth-state cookie not set")
	}
	if !stateCookie.HttpOnly {
		t.Error("cookie: expected HttpOnly=true")
	}
	if !stateCookie.Secure {
		t.Error("cookie: expected Secure=true")
	}
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie: expected SameSite=Lax, got %v", stateCookie.SameSite)
	}
	if stateCookie.MaxAge != 600 {
		t.Errorf("cookie: expected MaxAge=600, got %d", stateCookie.MaxAge)
	}
	if stateCookie.Path != "/" {
		t.Errorf("cookie: expected Path=/, got %q", stateCookie.Path)
	}

	// Decode and verify state + verifier are non-empty, and state matches redirect URL.
	rawJSON, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		t.Fatalf("cookie value: base64 decode failed: %v", err)
	}
	var sc oauthStateCookie
	if err := json.Unmarshal(rawJSON, &sc); err != nil {
		t.Fatalf("cookie value: json unmarshal failed: %v", err)
	}
	if sc.State == "" {
		t.Error("cookie state: expected non-empty")
	}
	if sc.Verifier == "" {
		t.Error("cookie verifier: expected non-empty")
	}
	if !strings.Contains(loc, "state="+sc.State) {
		t.Errorf("Location state mismatch: cookie state %q not found in %q", sc.State, loc)
	}
}

// --- OAuthCallback ---

// TestOAuthCallback_MissingStateCookie verifies that an absent state cookie returns 400.
func TestOAuthCallback_MissingStateCookie(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), nil)

	r := httptest.NewRequest("GET", "/oauth/google/callback?state=abc&code=code", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.OAuthCallback(w, r)

	assertBadRequest(t, w, "missing oauth state")
}

// TestOAuthCallback_BadBase64Cookie verifies that a cookie with invalid base64 returns 400.
func TestOAuthCallback_BadBase64Cookie(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), nil)

	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest("!!!", "abc", "code"))

	assertBadRequest(t, w, "invalid oauth state")
}

// TestOAuthCallback_BadJSONCookie verifies that a base64-valid but non-JSON cookie returns 400.
func TestOAuthCallback_BadJSONCookie(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), nil)
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))

	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(notJSON, "abc", "code"))

	assertBadRequest(t, w, "invalid oauth state")
}

// TestOAuthCallback_StateMismatch verifies that a state value that doesn't match the cookie returns 401.
func TestOAuthCallback_StateMismatch(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), nil)

	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie("abc", "verifier"), "xyz", "code"))

	assertUnauthorized(t, w, "invalid oauth state")
}

// TestOAuthCallback_ExchangeError verifies that a failed provider exchange returns 401.
func TestOAuthCallback_ExchangeError(t *testing.T) {
	h := AuthHandler{
		PS:         testutil.NewMockStore(),
		RS:         testutil.NewMockCache(),
		RL:         &testutil.MockRateLimiter{},
		ML:         &testutil.MockMailer{},
		SessionTTL: 24 * time.Hour,
		OAuthProviders: map[string]oauth.Provider{
			"google": &mockProvider{name: "google", exchangeErr: errors.New("token verification failed")},
		},
	}

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	assertUnauthorized(t, w, "oauth authentication failed")
}

// TestOAuthCallback_UnverifiedEmail verifies that claims with EmailVerified=false returns 401.
func TestOAuthCallback_UnverifiedEmail(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), &oauth.Claims{
		Sub: "sub-123", Email: "user@example.com", EmailVerified: false,
	})

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	assertUnauthorized(t, w, "oauth account email is not verified")
}

// TestOAuthCallback_CreateSessionError verifies that a session creation failure returns 500.
func TestOAuthCallback_CreateSessionError(t *testing.T) {
	email := "user@example.com"
	provider := "google"
	providerID := "sub-123"
	userID, _ := uuid.NewV7()

	ms := testutil.NewMockStore(&store.User{
		ID: userID, Email: &email, OAuthProvider: &provider, OAuthProviderID: &providerID,
	})
	ms.CreateSessionErr = errors.New("db error")

	h := baseCallbackHandler(ms, testutil.NewMockCache(), &oauth.Claims{
		Sub: providerID, Email: email, EmailVerified: true,
	})

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	assertInternalServerError(t, w)
}

// TestOAuthCallback_ExistingOAuthUser_HappyPath verifies a returning OAuth user gets a session.
func TestOAuthCallback_ExistingOAuthUser_HappyPath(t *testing.T) {
	email := "user@example.com"
	provider := "google"
	providerID := "sub-123"
	userID, _ := uuid.NewV7()

	ms := testutil.NewMockStore(&store.User{
		ID: userID, Email: &email, OAuthProvider: &provider, OAuthProviderID: &providerID,
	})
	h := baseCallbackHandler(ms, testutil.NewMockCache(), &oauth.Claims{
		Sub: providerID, Email: email, EmailVerified: true,
	})

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	assertOK(t, w)
	assertSessionCookie(t, w)
}

// TestOAuthCallback_NewUser_HappyPath verifies a brand-new OAuth user is created and gets a session.
func TestOAuthCallback_NewUser_HappyPath(t *testing.T) {
	h := baseCallbackHandler(testutil.NewMockStore(), testutil.NewMockCache(), &oauth.Claims{
		Sub: "new-sub-456", Email: "newuser@example.com", EmailVerified: true,
	})

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	assertOK(t, w)
	assertSessionCookie(t, w)
}

// --- findOrCreateOAuthUser ---

// TestFindOrCreateOAuthUser_ReturningUser expects the existing OAuth user returned unchanged.
func TestFindOrCreateOAuthUser_ReturningUser(t *testing.T) {
	email := "returning@example.com"
	provider := "google"
	providerID := "google-sub-returning"
	userID, _ := uuid.NewV7()
	now := time.Now()

	ms := testutil.NewMockStore(&store.User{
		ID: userID, Email: &email, OAuthProvider: &provider, OAuthProviderID: &providerID, EmailConfirmedAt: &now,
	})
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), provider, &oauth.Claims{Sub: providerID, Email: email})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if user.ID != userID {
		t.Errorf("user ID: expected %v, got %v", userID, user.ID)
	}
	if len(ms.Users) != 1 {
		t.Errorf("store mutation: expected 1 user, got %d", len(ms.Users))
	}
}

// TestFindOrCreateOAuthUser_NewUser creates a new OAuth user when neither lookup matches.
func TestFindOrCreateOAuthUser_NewUser(t *testing.T) {
	email := "newuser@example.com"
	ms := testutil.NewMockStore()
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{Sub: "google-sub-new-user", Email: email})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	created := ms.Users[email]
	if created == nil {
		t.Fatal("expected new user in store, got nil")
	}
	if created.ID != user.ID {
		t.Errorf("stored user ID %v does not match returned user ID %v", created.ID, user.ID)
	}
}

// TestFindOrCreateOAuthUser_OAuthLookupDBError propagates non-ErrNoRows errors from GetUserByOAuthProvider.
func TestFindOrCreateOAuthUser_OAuthLookupDBError(t *testing.T) {
	ms := testutil.NewMockStore()
	ms.GetUserByOAuthProviderErr = errors.New("db error")
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{Sub: "sub", Email: "a@example.com"})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if user != nil {
		t.Errorf("expected nil user, got %v", user)
	}
}

// TestFindOrCreateOAuthUser_EmailLookupDBError propagates non-ErrNoRows errors from GetUserByEmail.
func TestFindOrCreateOAuthUser_EmailLookupDBError(t *testing.T) {
	ms := testutil.NewMockStore()
	ms.GetUserByEmailErr = errors.New("db error")
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{Sub: "sub", Email: "a@example.com"})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if user != nil {
		t.Errorf("expected nil user, got %v", user)
	}
}

// TestFindOrCreateOAuthUser_CreateOAuthUserError propagates CreateOAuthUser errors.
func TestFindOrCreateOAuthUser_CreateOAuthUserError(t *testing.T) {
	ms := testutil.NewMockStore()
	ms.CreateOAuthUserErr = errors.New("db error")
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{Sub: "sub", Email: "a@example.com"})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if user != nil {
		t.Errorf("expected nil user, got %v", user)
	}
}

// TestFindOrCreateOAuthUser_NewUser_SetsProfile verifies profile fields are stored for new OAuth users.
func TestFindOrCreateOAuthUser_NewUser_SetsProfile(t *testing.T) {
	ms := testutil.NewMockStore()
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	_, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{
		Sub: "sub-profile", Email: "profile@example.com", EmailVerified: true,
		GivenName: "Jane", FamilyName: "Doe", Picture: "https://example.com/avatar.jpg",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	u := ms.Users["profile@example.com"]
	if u == nil {
		t.Fatal("expected user in store")
	}
	if u.FirstName == nil || *u.FirstName != "Jane" {
		t.Errorf("first_name: expected %q, got %v", "Jane", u.FirstName)
	}
	if u.LastName == nil || *u.LastName != "Doe" {
		t.Errorf("last_name: expected %q, got %v", "Doe", u.LastName)
	}
	if u.AvatarURL == nil || *u.AvatarURL != "https://example.com/avatar.jpg" {
		t.Errorf("avatar_url: expected %q, got %v", "https://example.com/avatar.jpg", u.AvatarURL)
	}
}

// --- SMTP-enabled confirmation flow ---

// TestFindOrCreateOAuthUser_ExistingEmail_SMTPEnabled verifies that when SMTP is enabled and an
// existing email-password account is found, ErrOAuthLinkRequired is returned and a pending link is stored.
func TestFindOrCreateOAuthUser_ExistingEmail_SMTPEnabled(t *testing.T) {
	email := "existing@example.com"
	userID, _ := uuid.NewV7()
	now := time.Now()
	ml := &testutil.MockMailer{}

	ms := testutil.NewMockStore(&store.User{ID: userID, Email: &email, EmailConfirmedAt: &now})
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: ml, SMTPEnabled: true}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{
		Sub: "google-sub-smtp", Email: email, EmailVerified: true,
	})

	if !errors.Is(err, ErrOAuthLinkRequired) {
		t.Fatalf("expected ErrOAuthLinkRequired, got %v", err)
	}
	if user != nil {
		t.Error("expected nil user when link confirmation required")
	}
	// Confirmation email must have been sent to the right address.
	if ml.LastOAuthLinkTo != email {
		t.Errorf("confirmation email to: expected %q, got %q", email, ml.LastOAuthLinkTo)
	}
	// A pending link must be stored in the mock.
	if len(ms.OAuthPendingLinks) != 1 {
		t.Errorf("expected 1 pending link, got %d", len(ms.OAuthPendingLinks))
	}
}

// TestFindOrCreateOAuthUser_ExistingEmail_SMTPDisabled verifies that when SMTP is disabled and an
// existing email-password account is found, ErrOAuthLinkUnavailable is returned and no link is stored.
func TestFindOrCreateOAuthUser_ExistingEmail_SMTPDisabled(t *testing.T) {
	email := "existing@example.com"
	userID, _ := uuid.NewV7()
	now := time.Now()
	ml := &testutil.MockMailer{}

	ms := testutil.NewMockStore(&store.User{ID: userID, Email: &email, EmailConfirmedAt: &now})
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: ml, SMTPEnabled: false}

	user, err := h.findOrCreateOAuthUser(httptest.NewRequest("GET", "/", nil), "google", &oauth.Claims{
		Sub: "google-sub-nosmtp", Email: email, EmailVerified: true,
	})

	if !errors.Is(err, ErrOAuthLinkUnavailable) {
		t.Fatalf("expected ErrOAuthLinkUnavailable, got %v", err)
	}
	if user != nil {
		t.Error("expected nil user when link unavailable")
	}
	// No confirmation email should be sent.
	if ml.LastOAuthLinkTo != "" {
		t.Errorf("expected no confirmation email, got one sent to %q", ml.LastOAuthLinkTo)
	}
	// No pending link should be stored.
	if len(ms.OAuthPendingLinks) != 0 {
		t.Errorf("expected 0 pending links, got %d", len(ms.OAuthPendingLinks))
	}
}

// TestOAuthCallback_LinkUnavailable verifies that OAuthCallback returns 409 when an existing
// account is found and SMTP is disabled -- no session is issued, no link is stored.
func TestOAuthCallback_LinkUnavailable(t *testing.T) {
	email := "existing@example.com"
	userID, _ := uuid.NewV7()
	now := time.Now()

	ms := testutil.NewMockStore(&store.User{ID: userID, Email: &email, EmailConfirmedAt: &now})
	ml := &testutil.MockMailer{}

	h := AuthHandler{
		PS:         ms,
		RS:         testutil.NewMockCache(),
		RL:         &testutil.MockRateLimiter{},
		ML:         ml,
		SessionTTL: 24 * time.Hour,
		SMTPEnabled: false,
		OAuthProviders: map[string]oauth.Provider{
			"google": &mockProvider{name: "google", claims: &oauth.Claims{
				Sub: "google-sub-nosmtp", Email: email, EmailVerified: true,
			}},
		},
	}

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	if w.Code != http.StatusConflict {
		t.Fatalf("status: expected 409, got %d", w.Code)
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected non-empty error message in response")
	}
	// No session cookie should be issued.
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-session" {
			t.Error("expected no session cookie to be set")
		}
	}
	// No pending link should be stored.
	if len(ms.OAuthPendingLinks) != 0 {
		t.Errorf("expected 0 pending links, got %d", len(ms.OAuthPendingLinks))
	}
}

// TestOAuthCallback_LinkRequired verifies that OAuthCallback returns
// {"action":"link_confirmation_sent"} when an existing account is found and SMTP is enabled.
func TestOAuthCallback_LinkRequired(t *testing.T) {
	email := "existing@example.com"
	userID, _ := uuid.NewV7()
	now := time.Now()

	ms := testutil.NewMockStore(&store.User{ID: userID, Email: &email, EmailConfirmedAt: &now})
	ml := &testutil.MockMailer{}

	h := AuthHandler{
		PS:         ms,
		RS:         testutil.NewMockCache(),
		RL:         &testutil.MockRateLimiter{},
		ML:         ml,
		SessionTTL: 24 * time.Hour,
		SMTPEnabled: true,
		OAuthProviders: map[string]oauth.Provider{
			"google": &mockProvider{name: "google", claims: &oauth.Claims{
				Sub: "google-sub-link", Email: email, EmailVerified: true,
			}},
		},
	}

	state := "matchingstate"
	w := httptest.NewRecorder()
	h.OAuthCallback(w, makeCallbackRequest(makeStateCookie(state, "verifier"), state, "code"))

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}
	var resp struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Message != "link_confirmation_sent" {
		t.Errorf("message: expected %q, got %q", "link_confirmation_sent", resp.Message)
	}
	// No session cookie should be issued.
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-session" {
			t.Error("expected no session cookie to be set")
		}
	}
}

// TestConfirmOAuthLink_Valid verifies that a valid pending-link token issues a session.
func TestConfirmOAuthLink_Valid(t *testing.T) {
	userID, _ := uuid.NewV7()
	email := "linkme@example.com"
	ms := testutil.NewMockStore(&store.User{ID: userID, Email: &email})
	mc := testutil.NewMockCache()

	// Pre-generate a token and store its hash as a pending link.
	rawToken, tokenHash, _ := GenerateToken()
	expiresAt := time.Now().Add(1 * time.Hour)
	_ = ms.CreateOAuthPendingLink(context.Background(), tokenHash[:], userID, "google", "google-sub-confirm",
		nil, nil, nil, expiresAt)

	h := &AuthHandler{
		PS: ms, RS: mc, RL: &testutil.MockRateLimiter{}, ML: &testutil.MockMailer{},
		SessionTTL: 24 * time.Hour,
	}

	tokenStr := base64.RawURLEncoding.EncodeToString(rawToken[:])
	body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/oauth/link/confirm", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ConfirmOAuthLink(w, r)

	assertOK(t, w)
	assertSessionCookie(t, w)

	// Pending link must be consumed (deleted).
	if len(ms.OAuthPendingLinks) != 0 {
		t.Errorf("expected pending link to be consumed, got %d remaining", len(ms.OAuthPendingLinks))
	}
}

// TestConfirmOAuthLink_InvalidToken verifies that an invalid or expired token returns 400.
func TestConfirmOAuthLink_InvalidToken(t *testing.T) {
	ms := testutil.NewMockStore()
	h := &AuthHandler{PS: ms, RS: testutil.NewMockCache(), ML: &testutil.MockMailer{}}

	// Token that was never stored -- ConsumeOAuthPendingLink returns ErrNoRows.
	_, bogusHash, _ := GenerateToken()
	tokenStr := base64.RawURLEncoding.EncodeToString(bogusHash[:])
	body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/oauth/link/confirm", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ConfirmOAuthLink(w, r)

	assertBadRequest(t, w, "invalid or expired token")
}

// TestConfirmOAuthLink_CaptchaRejected verifies that a failed captcha check returns 400
// before the token is ever examined.
func TestConfirmOAuthLink_CaptchaRejected(t *testing.T) {
	h := &AuthHandler{
		PS:        testutil.NewMockStore(),
		RS:        testutil.NewMockCache(),
		CV:        &testutil.MockCaptchaVerifier{VerifyErr: errors.New("bad token")},
		CaptchaCP: CaptchaPolicies{ConfirmOAuthLink: true},
	}
	body := strings.NewReader(`{"token":"sometoken","captcha_token":"bad"}`)
	r := httptest.NewRequest(http.MethodPost, "/oauth/link/confirm", body)
	w := httptest.NewRecorder()

	h.ConfirmOAuthLink(w, r)

	assertBadRequest(t, w, "captcha verification failed")
}

// TestConfirmOAuthLink_CaptchaValid verifies that a valid captcha proceeds past the captcha
// check and reaches token validation.
func TestConfirmOAuthLink_CaptchaValid(t *testing.T) {
	// Valid captcha, but bogus token -- expect token error, not captcha error.
	rawToken, bogusHash, _ := GenerateToken()
	tokenStr := base64.RawURLEncoding.EncodeToString(rawToken[:])
	_ = bogusHash
	h := &AuthHandler{
		PS:        testutil.NewMockStore(),
		RS:        testutil.NewMockCache(),
		CV:        &testutil.MockCaptchaVerifier{},
		CaptchaCP: CaptchaPolicies{ConfirmOAuthLink: true},
	}
	body := strings.NewReader(`{"token":"` + tokenStr + `","captcha_token":"good"}`)
	r := httptest.NewRequest(http.MethodPost, "/oauth/link/confirm", body)
	w := httptest.NewRecorder()

	h.ConfirmOAuthLink(w, r)

	assertBadRequest(t, w, "invalid or expired token")
}
