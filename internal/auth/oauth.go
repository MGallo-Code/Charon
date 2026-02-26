// oauth.go -- Generic OAuth2 redirect and callback handlers.
// Provider-specific logic lives in internal/oauth/*.go.
// Adding a new provider: implement oauth.Provider, register it in OAuthProviders in main.go.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MGallo-Code/charon/internal/oauth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// oauthStateCookie is the payload stored in __Host-oauth-state during the OAuth round-trip.
type oauthStateCookie struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
}

// OAuthRedirect handles GET /oauth/{provider} -- generates PKCE + state, stores them in a
// short-lived HttpOnly cookie, and redirects the browser to the provider's consent page.
func (h *AuthHandler) OAuthRedirect(w http.ResponseWriter, r *http.Request) {
	provider, ok := h.oauthProvider(r, w)
	if !ok {
		return
	}

	var stateBytes, verifierBytes [32]byte
	if _, err := rand.Read(stateBytes[:]); err != nil {
		InternalServerError(w, r, err)
		return
	}
	if _, err := rand.Read(verifierBytes[:]); err != nil {
		InternalServerError(w, r, err)
		return
	}

	state := base64.RawURLEncoding.EncodeToString(stateBytes[:])
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes[:])
	challenge := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])

	setOAuthStateCookie(w, state, codeVerifier)
	http.Redirect(w, r, provider.AuthCodeURL(state, codeChallenge), http.StatusFound)
}

// OAuthCallback handles GET /oauth/{provider}/callback -- verifies state, exchanges the
// authorization code for identity claims, then finds-or-creates a user and issues a session.
func (h *AuthHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider, ok := h.oauthProvider(r, w)
	if !ok {
		return
	}

	// Read and immediately clear the state cookie to prevent replay.
	stateCookie, err := r.Cookie("__Host-oauth-state")
	if err != nil {
		logWarn(r, "oauth callback: missing state cookie")
		BadRequest(w, r, "missing oauth state")
		return
	}
	clearOAuthStateCookie(w)

	rawJSON, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		logWarn(r, "oauth callback: bad state cookie encoding", "error", err)
		BadRequest(w, r, "invalid oauth state")
		return
	}
	var sc oauthStateCookie
	if err := json.Unmarshal(rawJSON, &sc); err != nil {
		logWarn(r, "oauth callback: bad state cookie json", "error", err)
		BadRequest(w, r, "invalid oauth state")
		return
	}

	// Constant-time comparison prevents timing oracle on state value.
	if subtle.ConstantTimeCompare([]byte(sc.State), []byte(r.URL.Query().Get("state"))) != 1 {
		logWarn(r, "oauth callback: state mismatch")
		Unauthorized(w, r, "invalid oauth state")
		return
	}

	claims, err := provider.Exchange(r.Context(), r.URL.Query().Get("code"), sc.Verifier)
	if err != nil {
		logWarn(r, "oauth callback: exchange failed", "error", err, "provider", provider.Name())
		Unauthorized(w, r, "oauth authentication failed")
		return
	}
	if !claims.EmailVerified {
		Unauthorized(w, r, "oauth account email is not verified")
		return
	}

	user, err := h.findOrCreateOAuthUser(r, provider.Name(), claims.Sub, claims.Email)
	if err != nil {
		logError(r, "oauth callback: find or create user failed", "error", err)
		InternalServerError(w, r, err)
		return
	}

	sessionToken, tokenHash, err := GenerateToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}
	sessionID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	expiresAt := time.Now().Add(h.SessionTTL)
	ttl := int(h.SessionTTL.Seconds())
	ipAddr := r.RemoteAddr
	userAgent := r.UserAgent()

	if err := h.PS.CreateSession(r.Context(), sessionID, user.ID, tokenHash[:], csrfToken[:], expiresAt, &ipAddr, &userAgent); err != nil {
		logError(r, "oauth callback: failed to create session", "error", err)
		InternalServerError(w, r, err)
		return
	}

	if err := h.RS.SetSession(r.Context(), base64.RawURLEncoding.EncodeToString(tokenHash[:]), store.Session{
		ID: sessionID, UserID: user.ID, TokenHash: tokenHash[:], CSRFToken: csrfToken[:], ExpiresAt: expiresAt,
	}, ttl); err != nil {
		logWarn(r, "oauth callback: failed to cache session in redis", "error", err)
	}

	SetSessionCookie(w, *sessionToken, expiresAt)
	meta, _ := json.Marshal(struct {
		Provider string `json:"provider"`
	}{provider.Name()})
	h.auditLog(r, &user.ID, "user.login", meta)
	logInfo(r, "oauth user logged in", "user_id", user.ID, "provider", provider.Name())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}{user.ID.String(), base64.RawURLEncoding.EncodeToString(csrfToken[:])})
}

// findOrCreateOAuthUser looks up a user by (provider, providerID).
// Falls back to email lookup if not found; links the OAuth identity to the existing account.
// Creates a new OAuth user if neither lookup finds a match.
func (h *AuthHandler) findOrCreateOAuthUser(r *http.Request, provider, providerID, email string) (*store.User, error) {
	// Returning user -- already has this OAuth identity.
	user, err := h.PS.GetUserByOAuthProvider(r.Context(), provider, providerID)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up oauth user: %w", err)
	}

	// Existing email account -- link this OAuth identity.
	existing, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up user by email for oauth link: %w", err)
	}
	if existing != nil {
		// Provider verified this email -- confirm it in our records if not already done.
		if existing.EmailConfirmedAt == nil {
			if confErr := h.PS.SetEmailConfirmedAt(r.Context(), existing.ID); confErr != nil {
				logWarn(r, "oauth: failed to confirm email on link", "error", confErr, "user_id", existing.ID)
			}
		}
		if linkErr := h.PS.LinkOAuthToUser(r.Context(), existing.ID, provider, providerID); linkErr != nil {
			// Non-fatal: user may already have a different provider linked.
			logWarn(r, "oauth: could not link identity to account", "error", linkErr, "user_id", existing.ID)
		} else {
			h.auditLog(r, &existing.ID, "user.oauth_linked", nil)
		}
		return existing, nil
	}

	// New user.
	userID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating user id: %w", err)
	}
	if err := h.PS.CreateOAuthUser(r.Context(), userID, email, provider, providerID); err != nil {
		return nil, fmt.Errorf("creating oauth user: %w", err)
	}
	h.auditLog(r, &userID, "user.registered", nil)
	logInfo(r, "oauth user created", "user_id", userID, "provider", provider)
	return &store.User{ID: userID}, nil
}

// oauthProvider reads the {provider} URL param and looks it up in OAuthProviders.
// Writes 404 and returns (nil, false) when the provider is not configured.
func (h *AuthHandler) oauthProvider(r *http.Request, w http.ResponseWriter) (oauth.Provider, bool) {
	name := chi.URLParam(r, "provider")
	p, ok := h.OAuthProviders[name]
	if !ok {
		NotFound(w)
		return nil, false
	}
	return p, true
}

// setOAuthStateCookie stores state + PKCE verifier in a short-lived HttpOnly cookie.
func setOAuthStateCookie(w http.ResponseWriter, state, verifier string) {
	payload, _ := json.Marshal(oauthStateCookie{State: state, Verifier: verifier})
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-oauth-state",
		Value:    base64.RawURLEncoding.EncodeToString(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
}

// clearOAuthStateCookie expires the OAuth state cookie immediately.
func clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-oauth-state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
