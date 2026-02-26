// google.go -- Google OAuth2 + OIDC provider implementation.
package oauth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleProvider implements Provider using Google's OIDC discovery + OAuth2 code flow.
// Uses PKCE (S256) for all authorization requests.
type GoogleProvider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewGoogleProvider creates a GoogleProvider by fetching Google's OIDC discovery document.
// Makes an outbound HTTP request to accounts.google.com at startup; returns an error if unreachable.
func NewGoogleProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*GoogleProvider, error) {
	p, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("google oidc discovery: %w", err)
	}
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// Name returns "google".
func (p *GoogleProvider) Name() string { return "google" }

// AuthCodeURL builds the Google consent page URL with state and PKCE S256 challenge embedded.
func (p *GoogleProvider) AuthCodeURL(state, codeChallenge string) string {
	return p.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange trades an authorization code for verified identity claims.
// Verifies the returned ID token signature against Google's JWKS, checks aud + exp.
func (p *GoogleProvider) Exchange(ctx context.Context, code, codeVerifier string) (*Claims, error) {
	token, err := p.config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id token: %w", err)
	}

	var c struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err := idToken.Claims(&c); err != nil {
		return nil, fmt.Errorf("extracting id token claims: %w", err)
	}

	return &Claims{
		Sub:           c.Sub,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
		GivenName:     c.GivenName,
		FamilyName:    c.FamilyName,
		Picture:       c.Picture,
	}, nil
}
