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
	"strings"
	"time"

	"github.com/MGallo-Code/charon/internal/oauth"
	"github.com/MGallo-Code/charon/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrOAuthLinkRequired is returned by findOrCreateOAuthUser when an existing
// password account shares the OAuth email. The caller should inform the user
// that a confirmation email was sent; no session is issued yet.
var ErrOAuthLinkRequired = errors.New("oauth link requires email confirmation")

// ErrOAuthLinkUnavailable is returned when an existing account matches the OAuth email
// but SMTP is not configured, making email-confirmed linking impossible.
// The user must log in with their password instead; no session is issued.
var ErrOAuthLinkUnavailable = errors.New("oauth account linking unavailable without SMTP")

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

	user, err := h.findOrCreateOAuthUser(r, provider.Name(), claims)
	if errors.Is(err, ErrOAuthLinkRequired) {
		logInfo(r, "oauth link confirmation sent", "provider", provider.Name())
		OK(w, "link_confirmation_sent")
		return
	}
	if errors.Is(err, ErrOAuthLinkUnavailable) {
		logWarn(r, "oauth callback: link rejected, smtp disabled", "provider", provider.Name())
		Conflict(w, "an account with this email already exists. Please log in with your password.")
		return
	}
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
	providerName := provider.Name()
	h.auditLog(r, &user.ID, "user.login", marshalMeta(struct {
		Provider string `json:"provider"`
	}{providerName}))
	logInfo(r, "oauth user logged in", "user_id", user.ID, "provider", providerName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}{user.ID.String(), base64.RawURLEncoding.EncodeToString(csrfToken[:])})
}

// findOrCreateOAuthUser looks up a user by (provider, claims.Sub).
// Falls back to email lookup if not found; links the OAuth identity to the existing account.
// Creates a new OAuth user if neither lookup finds a match.
func (h *AuthHandler) findOrCreateOAuthUser(r *http.Request, provider string, claims *oauth.Claims) (*store.User, error) {
	email := strings.ToLower(claims.Email)

	// Returning user -- already has this OAuth identity.
	user, err := h.PS.GetUserByOAuthProvider(r.Context(), provider, claims.Sub)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up oauth user: %w", err)
	}

	// Existing email account -- require confirmation before linking.
	existing, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up user by email for oauth link: %w", err)
	}
	if existing != nil {
		if !h.SMTPEnabled {
			// Without SMTP, email-confirmed linking is impossible. Reject rather than
			// auto-link -- auto-linking without consent is an account takeover vector.
			logWarn(r, "oauth: smtp disabled, rejecting link attempt", "user_id", existing.ID)
			return nil, ErrOAuthLinkUnavailable
		}
		// Send confirmation email; the account owner must click to approve linking.
		token, tokenHash, err := GenerateToken()
		if err != nil {
			return nil, fmt.Errorf("generating oauth link token: %w", err)
		}
		expiresAt := time.Now().Add(1 * time.Hour)
		if err := h.PS.CreateOAuthPendingLink(r.Context(), tokenHash[:], existing.ID, provider, claims.Sub,
			strOrNil(claims.GivenName), strOrNil(claims.FamilyName), strOrNil(claims.Picture), expiresAt,
		); err != nil {
			return nil, fmt.Errorf("storing oauth pending link: %w", err)
		}
		tokenStr := base64.RawURLEncoding.EncodeToString(token[:])
		if err := h.ML.SendOAuthLinkConfirmation(r.Context(), email, tokenStr, time.Until(expiresAt), nil); err != nil {
			logWarn(r, "oauth: failed to send link confirmation email", "error", err, "user_id", existing.ID)
		}
		return nil, ErrOAuthLinkRequired
	}

	// New user.
	userID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating user id: %w", err)
	}
	if err := h.PS.CreateOAuthUser(r.Context(), userID, email, provider, claims.Sub,
		strOrNil(claims.GivenName), strOrNil(claims.FamilyName), strOrNil(claims.Picture),
	); err != nil {
		return nil, fmt.Errorf("creating oauth user: %w", err)
	}
	h.auditLog(r, &userID, "user.registered", nil)
	logInfo(r, "oauth user created", "user_id", userID, "provider", provider)
	return &store.User{ID: userID}, nil
}

// ConfirmOAuthLink handles POST /oauth/link/confirm -- consumes the pending-link token
// emailed to the account owner and completes the OAuth identity link.
// Returns 200 with user_id and csrf_token on success; 400 for invalid/expired token.
func (h *AuthHandler) ConfirmOAuthLink(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logWarn(r, "confirm oauth link: failed to decode input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}
	if input.Token == "" {
		BadRequest(w, r, "token is required")
		return
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil {
		logWarn(r, "confirm oauth link: invalid token encoding", "error", err)
		BadRequest(w, r, "invalid token")
		return
	}
	tokenHash := sha256.Sum256(rawToken)

	link, err := h.PS.ConsumeOAuthPendingLink(r.Context(), tokenHash[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "confirm oauth link: invalid or expired token")
			BadRequest(w, r, "invalid or expired token")
			return
		}
		logError(r, "confirm oauth link: failed to consume token", "error", err)
		InternalServerError(w, r, err)
		return
	}

	// Link the OAuth identity. Non-fatal if already linked (idempotent).
	if linkErr := h.PS.LinkOAuthToUser(r.Context(), link.UserID, link.Provider, link.ProviderID); linkErr != nil {
		logWarn(r, "confirm oauth link: could not link identity", "error", linkErr, "user_id", link.UserID)
	} else {
		h.auditLog(r, &link.UserID, "user.oauth_linked", marshalMeta(struct {
			Provider string `json:"provider"`
		}{link.Provider}))
	}

	// Confirm email -- provider has verified it.
	if confErr := h.PS.SetEmailConfirmedAt(r.Context(), link.UserID); confErr != nil {
		logWarn(r, "confirm oauth link: failed to set email_confirmed_at", "error", confErr, "user_id", link.UserID)
	}

	// Update profile fields -- COALESCE-safe, only fills NULL columns.
	if profErr := h.PS.SetOAuthProfile(r.Context(), link.UserID, link.GivenName, link.FamilyName, link.Picture); profErr != nil {
		logWarn(r, "confirm oauth link: failed to set oauth profile", "error", profErr, "user_id", link.UserID)
	}

	sessionToken, tokenHash2, err := GenerateToken()
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

	if err := h.PS.CreateSession(r.Context(), sessionID, link.UserID, tokenHash2[:], csrfToken[:], expiresAt, &ipAddr, &userAgent); err != nil {
		logError(r, "confirm oauth link: failed to create session", "error", err)
		InternalServerError(w, r, err)
		return
	}
	if err := h.RS.SetSession(r.Context(), base64.RawURLEncoding.EncodeToString(tokenHash2[:]), store.Session{
		ID: sessionID, UserID: link.UserID, TokenHash: tokenHash2[:], CSRFToken: csrfToken[:], ExpiresAt: expiresAt,
	}, ttl); err != nil {
		logWarn(r, "confirm oauth link: failed to cache session in redis", "error", err)
	}

	SetSessionCookie(w, *sessionToken, expiresAt)
	h.auditLog(r, &link.UserID, "user.login", marshalMeta(struct {
		Provider string `json:"provider"`
	}{link.Provider}))
	logInfo(r, "oauth link confirmed, session issued", "user_id", link.UserID, "provider", link.Provider)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}{link.UserID.String(), base64.RawURLEncoding.EncodeToString(csrfToken[:])})
}

// strOrNil converts an empty string to nil; non-empty strings are returned as a pointer.
// Used to map optional OAuth profile fields to nullable DB columns.
func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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
