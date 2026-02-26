// turnstile_test.go -- unit tests for TurnstileVerifier.Verify.
package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTurnstileVerifier_Verify(t *testing.T) {
	t.Run("success response returns nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true}`))
		}))
		defer srv.Close()

		orig := turnstileURL
		turnstileURL = srv.URL
		defer func() { turnstileURL = orig }()

		v := NewTurnstileVerifier("test-secret")
		if err := v.Verify(context.Background(), "token", "127.0.0.1"); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("rejected token returns error containing error code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		}))
		defer srv.Close()

		orig := turnstileURL
		turnstileURL = srv.URL
		defer func() { turnstileURL = orig }()

		v := NewTurnstileVerifier("test-secret")
		err := v.Verify(context.Background(), "bad-token", "127.0.0.1")
		if err == nil {
			t.Fatal("expected non-nil error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid-input-response") {
			t.Errorf("expected error to mention error code, got %q", err.Error())
		}
	})

	t.Run("network error returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // closed before request is sent

		orig := turnstileURL
		turnstileURL = srv.URL
		defer func() { turnstileURL = orig }()

		v := NewTurnstileVerifier("test-secret")
		if err := v.Verify(context.Background(), "token", "127.0.0.1"); err == nil {
			t.Error("expected non-nil error for closed server, got nil")
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer srv.Close()

		orig := turnstileURL
		turnstileURL = srv.URL
		defer func() { turnstileURL = orig }()

		v := NewTurnstileVerifier("test-secret")
		if err := v.Verify(context.Background(), "token", "127.0.0.1"); err == nil {
			t.Error("expected non-nil error for malformed JSON, got nil")
		}
	})

	t.Run("cancelled context returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true}`))
		}))
		defer srv.Close()

		orig := turnstileURL
		turnstileURL = srv.URL
		defer func() { turnstileURL = orig }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel before calling

		v := NewTurnstileVerifier("test-secret")
		if err := v.Verify(ctx, "token", "127.0.0.1"); err == nil {
			t.Error("expected non-nil error for cancelled context, got nil")
		}
	})
}
