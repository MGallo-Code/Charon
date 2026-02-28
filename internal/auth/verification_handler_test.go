// verification_handler_test.go -- unit tests for VerifyEmail and ResendVerificationEmail handlers.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
)

// nowPlusHour is a test helper for token expiry in VerifyEmail tests.
func nowPlusHour() time.Time {
	return time.Now().Add(time.Hour)
}

// genericResendMsg is the no-enumeration response ResendVerificationEmail always returns on 200.
const genericResendMsg = `{"message":"if that email is registered and unverified, a verification link has been sent"}`

// assertGenericResendResponse checks handler returned 200 with the no-enumeration message.
func assertGenericResendResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Errorf("status: expected 200, got %d", w.Code)
	}
	body := strings.TrimSuffix(w.Body.String(), "\n")
	if body != genericResendMsg {
		t.Errorf("body: expected generic resend message, got %q", body)
	}
}

func TestVerifyEmail(t *testing.T) {
	// Helper: builds a raw token, stores it in MockStore, returns encoded token string.
	makeToken := func(t *testing.T, ms *testutil.MockStore, userID uuid.UUID) string {
		t.Helper()
		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			t.Fatalf("generating token: %v", err)
		}
		hash := sha256.Sum256(rawToken)
		tokenID := uuid.Must(uuid.NewV7())
		_ = ms.CreateToken(context.Background(), tokenID, userID, "email_verification", hash[:], nowPlusHour())
		return base64.RawURLEncoding.EncodeToString(rawToken)
	}

	testUserID := uuid.Must(uuid.NewV7())

	t.Run("valid token verifies email and returns 200", func(t *testing.T) {
		ms := testutil.NewMockStore()
		tokenStr := makeToken(t, ms, testUserID)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		bodyBytes, _ := io.ReadAll(w.Body)
		body2 := strings.TrimSuffix(string(bodyBytes), "\n")
		if body2 != `{"message":"email verified"}` {
			t.Errorf("body: got %q, want email verified message", body2)
		}
	})

	t.Run("invalid token returns 400", func(t *testing.T) {
		ms := testutil.NewMockStore()
		// Encode a random token that was never stored.
		raw := make([]byte, 32)
		rand.Read(raw)
		tokenStr := base64.RawURLEncoding.EncodeToString(raw)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"` + tokenStr + `"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "invalid or expired token")
	})

	t.Run("bad base64 returns 400", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":"!!!not-base64!!!"}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "invalid token")
	})

	t.Run("empty token returns 400", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}
		body := strings.NewReader(`{"token":""}`)
		r := httptest.NewRequest(http.MethodPost, "/verify/email", body)
		w := httptest.NewRecorder()

		h.VerifyEmail(w, r)

		assertBadRequest(t, w, "token is required")
	})

	t.Run("replayed token returns 400", func(t *testing.T) {
		ms := testutil.NewMockStore()
		tokenStr := makeToken(t, ms, testUserID)

		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		// First use -- succeeds.
		r1 := httptest.NewRequest(http.MethodPost, "/verify/email", strings.NewReader(`{"token":"`+tokenStr+`"}`))
		h.VerifyEmail(httptest.NewRecorder(), r1)

		// Replay -- ConsumeToken returns ErrNoRows (used_at already set).
		r2 := httptest.NewRequest(http.MethodPost, "/verify/email", strings.NewReader(`{"token":"`+tokenStr+`"}`))
		w2 := httptest.NewRecorder()
		h.VerifyEmail(w2, r2)

		assertBadRequest(t, w2, "invalid or expired token")
	})
}

func TestResendVerificationEmail(t *testing.T) {
	email := "user@example.com"
	userID := uuid.Must(uuid.NewV7())

	// unverifiedUser has no EmailConfirmedAt -- eligible for resend.
	unverifiedUser := &store.User{ID: userID, Email: &email}

	// confirmedAt holds a timestamp for seeding an already-verified user.
	confirmedAt := time.Now().Add(-24 * time.Hour)
	verifiedUser := &store.User{ID: userID, Email: &email, EmailConfirmedAt: &confirmedAt}

	// resendReq builds a POST /resend/verification-email request with the given body.
	resendReq := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/resend/verification-email", strings.NewReader(body))
	}

	// baseHandler returns a handler wired with a no-error rate limiter and mailer.
	// Swap PS / RL / ML fields per sub-test as needed.
	baseHandler := func(ps Store) AuthHandler {
		return AuthHandler{
			PS: ps,
			RS: testutil.NewMockCache(),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
			Policies: RateLimitPolicies{
				ResendVerification: store.RateLimit{MaxAttempts: 3, Window: time.Hour, LockoutTTL: time.Hour},
			},
		}
	}

	t.Run("bad JSON returns 400", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore())
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq("not-json"))
		assertBadRequest(t, w, "invalid request")
	})

	t.Run("invalid email returns 400", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore())
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"notanemail"}`))
		if w.Code != http.StatusBadRequest {
			t.Errorf("status: expected 400, got %d", w.Code)
		}
	})

	t.Run("rate limited returns 429", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore(unverifiedUser))
		h.RL = &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded}
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("status: expected 429, got %d", w.Code)
		}
	})

	// -- CAPTCHA (400) --

	t.Run("captcha required, token rejected returns 400", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore(unverifiedUser))
		h.CV = &testutil.MockCaptchaVerifier{VerifyErr: errors.New("bad token")}
		h.CaptchaCP = CaptchaPolicies{ResendVerification: true}
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com","captcha_token":"bad"}`))
		assertBadRequest(t, w, "captcha verification failed")
	})

	t.Run("captcha required, token valid proceeds past captcha check", func(t *testing.T) {
		// Empty store -- user not found returns generic 200, confirming captcha didn't block.
		h := baseHandler(testutil.NewMockStore())
		h.CV = &testutil.MockCaptchaVerifier{}
		h.CaptchaCP = CaptchaPolicies{ResendVerification: true}
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"nobody@example.com","captcha_token":"good"}`))
		assertGenericResendResponse(t, w)
	})

	t.Run("happy path: unverified user gets email, returns generic 200", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(unverifiedUser))
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != email {
			t.Errorf("verification sent to: expected %q, got %q", email, mailer.LastVerifTo)
		}
		if mailer.LastVerifToken == "" {
			t.Error("expected a verification token to be sent, got empty string")
		}
	})

	t.Run("user not found returns generic 200 (no enumeration)", func(t *testing.T) {
		h := baseHandler(testutil.NewMockStore()) // no users seeded
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"nobody@example.com"}`))
		assertGenericResendResponse(t, w)
	})

	t.Run("already confirmed user returns generic 200 (no enumeration)", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(verifiedUser))
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != "" {
			t.Errorf("no email expected for confirmed user, but got LastVerifTo=%q", mailer.LastVerifTo)
		}
	})

	t.Run("DB error on GetUserByEmail returns generic 200 (no enumeration)", func(t *testing.T) {
		ms := &testutil.MockStore{
			GetUserByEmailErr: errors.New("connection refused"),
		}
		h := baseHandler(ms)
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"user@example.com"}`))
		assertGenericResendResponse(t, w)
	})

	t.Run("email is lowercased before lookup", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := baseHandler(testutil.NewMockStore(unverifiedUser)) // seeded with lowercase email
		h.ML = mailer
		w := httptest.NewRecorder()
		h.ResendVerificationEmail(w, resendReq(`{"email":"User@Example.COM"}`))
		assertGenericResendResponse(t, w)
		if mailer.LastVerifTo != email {
			t.Errorf("expected normalised email %q, got %q", email, mailer.LastVerifTo)
		}
	})
}
