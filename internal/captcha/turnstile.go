// turnstile.go -- Cloudflare Turnstile CAPTCHA verifier.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const turnstileURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileVerifier verifies Cloudflare Turnstile tokens against the siteverify API.
type TurnstileVerifier struct {
	secret     string
	httpClient *http.Client
}

// NewTurnstileVerifier returns a TurnstileVerifier using the given secret key.
// Uses a 5s timeout on the outbound HTTP client.
func NewTurnstileVerifier(secret string) *TurnstileVerifier {
	return &TurnstileVerifier{
		secret:     secret,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Verify checks the token against Cloudflare's siteverify endpoint.
// Returns nil on success; non-nil if the token is rejected or any network/decode error occurs.
func (v *TurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	body := url.Values{
		"secret":   {v.secret},
		"response": {token},
		"remoteip": {remoteIP},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileURL, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile: request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("turnstile: decoding response: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("turnstile rejected token: %v", result.ErrorCodes)
	}
	return nil
}
