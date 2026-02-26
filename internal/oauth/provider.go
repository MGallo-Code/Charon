// provider.go -- OAuth provider interface and shared types.
package oauth

import "context"

// Claims holds the normalized identity claims returned by an OAuth provider.
// All fields are verified server-side; never trust client-supplied values.
// Profile fields (GivenName, FamilyName, Picture) are optional -- empty string means not provided.
// Picture is a provider-hosted URL from a verified token; safe to store, but consuming apps
// should use CSP or server-side proxying before rendering it as an image.
type Claims struct {
	Sub           string // provider-specific stable user ID (e.g. Google "sub")
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	Picture       string // avatar URL
}

// Provider is an OAuth2 identity provider.
// Implementations handle provider-specific auth URLs, code exchange, and token verification.
// PKCE (RFC 7636) is required: callers pass the code_challenge to AuthCodeURL and the
// matching code_verifier to Exchange.
type Provider interface {
	// Name returns the provider identifier used as the URL param and stored in the DB.
	Name() string

	// AuthCodeURL returns the redirect URL with state and PKCE code_challenge embedded.
	AuthCodeURL(state, codeChallenge string) string

	// Exchange exchanges the authorization code for verified identity claims.
	// The code_verifier must match the code_challenge passed to AuthCodeURL.
	Exchange(ctx context.Context, code, codeVerifier string) (*Claims, error)
}
