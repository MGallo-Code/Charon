// password_handler_test.go -- unit tests for PasswordChange, PasswordReset, and PasswordConfirm handlers.
package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/MGallo-Code/charon/internal/testutil"
	"github.com/gofrs/uuid/v5"
)

func TestPasswordChange(t *testing.T) {
	testPassword := "oldpassword1"
	testHash, _ := HashPassword(testPassword)
	testEmail := "pwchange@example.com"
	testUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: &testHash,
	}

	// freshUser returns a new User with a freshly hashed testPassword.
	// MockStore stores users by pointer, and UpdateUserPassword mutates PasswordHash
	// in place; tests that reach UpdateUserPassword need their own copy.
	freshUser := func() *store.User {
		h, _ := HashPassword(testPassword)
		return &store.User{ID: testUser.ID, Email: testUser.Email, PasswordHash: &h}
	}

	// -- Input validation (400s) --

	t.Run("empty body returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/password/change", nil)
		ctx := context.WithValue(r.Context(), userIDKey, testUser.ID)
		w := httptest.NewRecorder()

		h.PasswordChange(w, r.WithContext(ctx))

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		body := strings.NewReader(`{not valid json}`)
		r := httptest.NewRequest(http.MethodPost, "/password/change", body)
		ctx := context.WithValue(r.Context(), userIDKey, testUser.ID)
		w := httptest.NewRecorder()

		h.PasswordChange(w, r.WithContext(ctx))

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("missing current_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, "", "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertBadRequest(t, w, "current_password required")
	})

	t.Run("invalid new_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdChangeReq(testUser.ID, testPassword, "short")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	// -- Missing context (500) --

	t.Run("missing userID in context returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		// No context, simulates handler called without RequireAuth.
		r := httptest.NewRequest(http.MethodPost, "/password/change",
			strings.NewReader(`{"current_password":"oldpassword1","new_password":"validnewpassword"}`))
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	// -- Auth failures (401s) --

	t.Run("wrong current_password returns Unauthorized", func(t *testing.T) {
		h := AuthHandler{PS: testutil.NewMockStore(testUser), RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, "wrongpassword", "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertUnauthorized(t, w, "invalid credentials")
	})

	// -- Store errors (500s) --

	t.Run("GetPwdHashByUserID failure returns InternalServerError", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{GetPwdHashByUserIDErr: errors.New("database connection failed")},
			RS: testutil.NewMockCache(),
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("UpdateUserPassword failure returns InternalServerError", func(t *testing.T) {
		// UpdateUserPasswordErr causes early return before mutation; testUser is safe.
		ps := testutil.NewMockStore(testUser)
		ps.UpdateUserPasswordErr = errors.New("database write failed")
		h := AuthHandler{PS: ps, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("Postgres DeleteAllUserSessions failure returns InternalServerError", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		ps := testutil.NewMockStore(freshUser())
		ps.DeleteAllSessionsErr = errors.New("database write failed")
		h := AuthHandler{PS: ps, RS: testutil.NewMockCache()}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures --

	t.Run("Redis DeleteAllUserSessions failure still returns OK", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		h := AuthHandler{
			PS: testutil.NewMockStore(freshUser()),
			RS: &testutil.MockCache{DeleteAllSessionsErr: errors.New("redis unavailable")},
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path (200) --

	t.Run("valid request returns OK and clears cookie", func(t *testing.T) {
		// Reaches UpdateUserPassword successfully (mutates); use fresh copy.
		h := AuthHandler{
			PS: testutil.NewMockStore(freshUser()),
			RS: testutil.NewMockCache(),
		}

		r := pwdChangeReq(testUser.ID, testPassword, "validnewpassword")
		w := httptest.NewRecorder()

		h.PasswordChange(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		assertClearedSessionCookie(t, w)
	})
}

func TestPasswordReset(t *testing.T) {
	email := "user@example.com"
	userID, _ := uuid.NewV7()
	existingUser := &store.User{ID: userID, Email: &email}

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader("not-json"))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertBadRequest(t, w, "invalid request")
	})

	t.Run("unknown email returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(), // no users seeded
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"nobody@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("rate limited returns 429", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{AllowErr: store.ErrRateLimitExceeded},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("status: expected 429, got %d", w.Code)
		}
	})

	// -- CAPTCHA (400) --

	t.Run("captcha required, token rejected returns 400", func(t *testing.T) {
		h := AuthHandler{
			PS:        testutil.NewMockStore(existingUser),
			ML:        &testutil.MockMailer{},
			CV:        &testutil.MockCaptchaVerifier{VerifyErr: errors.New("bad token")},
			CaptchaCP: CaptchaPolicies{PasswordResetRequest: true},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com","captcha_token":"bad"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertBadRequest(t, w, "captcha verification failed")
	})

	t.Run("captcha required, token valid proceeds past captcha check", func(t *testing.T) {
		// Empty store -- user not found returns generic 200, confirming captcha didn't block.
		h := AuthHandler{
			PS:        testutil.NewMockStore(),
			RL:        &testutil.MockRateLimiter{},
			ML:        &testutil.MockMailer{},
			CV:        &testutil.MockCaptchaVerifier{},
			CaptchaCP: CaptchaPolicies{PasswordResetRequest: true},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"nobody@example.com","captcha_token":"good"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("CreateToken failure returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: &testutil.MockStore{
				Users:          map[string]*store.User{email: existingUser},
				CreateTokenErr: errors.New("db error"),
			},
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("email send failure returns generic 200 (no enumeration)", func(t *testing.T) {
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: &testutil.MockMailer{SendPasswordResetErr: errors.New("smtp unavailable")},
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
	})

	t.Run("happy path returns generic 200 and sends email", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser),
			RL: &testutil.MockRateLimiter{},
			ML: mailer,
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
		if mailer.LastResetTo != email {
			t.Errorf("email sent to: expected %q, got %q", email, mailer.LastResetTo)
		}
		if mailer.LastResetToken == "" {
			t.Error("expected a token to be sent, got empty string")
		}
	})

	t.Run("email is normalised to lowercase before lookup", func(t *testing.T) {
		mailer := &testutil.MockMailer{}
		h := AuthHandler{
			PS: testutil.NewMockStore(existingUser), // seeded with lowercase email
			RL: &testutil.MockRateLimiter{},
			ML: mailer,
		}
		// Submit with mixed case -- should still find the user
		r := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"email":"User@Example.COM"}`))
		w := httptest.NewRecorder()

		h.PasswordReset(w, r)

		assertGenericResetResponse(t, w)
		if mailer.LastResetTo != email {
			t.Errorf("email sent to: expected normalised %q, got %q", email, mailer.LastResetTo)
		}
	})
}

func TestPasswordConfirm(t *testing.T) {
	validPassword := "newpwd12*"
	testEmail := "confirm@example.com"
	testUserID := uuid.Must(uuid.NewV7())
	testUser := &store.User{
		ID:    testUserID,
		Email: &testEmail,
	}

	// freshStore seeds testUser + one valid reset token; returns store and base64 token string.
	freshStore := func() (*testutil.MockStore, string) {
		ms := testutil.NewMockStore(testUser)
		tok := seedConfirmToken(ms, testUserID)
		return ms, tok
	}

	// -- Input validation (400s) --

	t.Run("empty body returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/auth/password/confirm", nil)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("invalid JSON returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := httptest.NewRequest(http.MethodPost, "/auth/password/confirm", strings.NewReader(`{not json}`))
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "error decoding request body")
	})

	t.Run("empty new_password returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		// Password validation runs before token decode -- token field irrelevant here.
		r := pwdConfirmReq("sometoken", "")
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	t.Run("password too short returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdConfirmReq("sometoken", "abc")
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at least 8 characters")
	})

	t.Run("password too long returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache(), Policy: PasswordPolicy{MinLength: 8, MaxLength: 128}}

		r := pwdConfirmReq("sometoken", strings.Repeat("a", 129))
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "password must be at most 128 characters")
	})

	t.Run("malformed base64 token returns BadRequest", func(t *testing.T) {
		h := AuthHandler{PS: &testutil.MockStore{}, RS: testutil.NewMockCache()}

		r := pwdConfirmReq("!!!not-base64!!!", validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "invalid reset token")
	})

	// -- Token validation (400s) --

	t.Run("unknown token returns BadRequest", func(t *testing.T) {
		// No token seeded -- ConsumeToken returns pgx.ErrNoRows for unknown hash.
		h := AuthHandler{
			PS: testutil.NewMockStore(testUser),
			RS: testutil.NewMockCache(),
		}

		unknownRaw := make([]byte, 32) // zero bytes, valid base64, no matching token in store
		r := pwdConfirmReq(base64.RawURLEncoding.EncodeToString(unknownRaw), validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertBadRequest(t, w, "invalid or expired reset token")
	})

	t.Run("ConsumeToken store error returns InternalServerError", func(t *testing.T) {
		ms := testutil.NewMockStore(testUser)
		ms.ConsumeTokenErr = errors.New("database error")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		// ConsumeTokenErr fires before lookup -- any valid base64 triggers it.
		unknownRaw := make([]byte, 32)
		r := pwdConfirmReq(base64.RawURLEncoding.EncodeToString(unknownRaw), validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	// -- Store errors after token consumed (500s) --

	t.Run("UpdateUserPassword failure returns InternalServerError", func(t *testing.T) {
		ms, tok := freshStore()
		ms.UpdateUserPasswordErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	t.Run("Postgres DeleteAllUserSessions failure returns InternalServerError", func(t *testing.T) {
		ms, tok := freshStore()
		ms.DeleteAllSessionsErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		assertInternalServerError(t, w)
	})

	// -- Non-fatal failures (200) --

	t.Run("Redis DeleteAllUserSessions failure still returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		h := AuthHandler{
			PS: ms,
			RS: &testutil.MockCache{DeleteAllSessionsErr: errors.New("redis unavailable")},
		}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	t.Run("SetEmailConfirmedAt failure still returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		ms.SetEmailConfirmedAtErr = errors.New("database write failed")
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
	})

	// -- Happy path (200) --

	t.Run("valid token and password returns OK", func(t *testing.T) {
		ms, tok := freshStore()
		h := AuthHandler{PS: ms, RS: testutil.NewMockCache()}

		r := pwdConfirmReq(tok, validPassword)
		w := httptest.NewRecorder()

		h.PasswordConfirm(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status: expected 200, got %d", w.Code)
		}
		bodyBytes, _ := io.ReadAll(w.Body)
		body := strings.TrimSuffix(string(bodyBytes), "\n")
		if body != `{"message":"password updated"}` {
			t.Errorf("body: expected password updated message, got %q", body)
		}
	})
}

// TestPasswordChange_PolicyViolation verifies that PasswordChange rejects a
// new_password that violates h.Policy and returns 400 with the failure message.
func TestPasswordChange_PolicyViolation(t *testing.T) {
	currentPwd := "OldPassword1!"
	currentHash, _ := HashPassword(currentPwd)
	testEmail := "pwchange-policy@example.com"
	testUser := &store.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        &testEmail,
		PasswordHash: &currentHash,
	}

	// Policy requires uppercase; new password is all lowercase.
	h := AuthHandler{
		PS: testutil.NewMockStore(testUser),
		RS: testutil.NewMockCache(),
		Policy: PasswordPolicy{
			MinLength:        8,
			RequireUppercase: true,
		},
	}

	r := pwdChangeReq(testUser.ID, currentPwd, "alllowercase")
	w := httptest.NewRecorder()

	h.PasswordChange(w, r)

	assertPolicyViolation(t, w, "password must contain at least one uppercase letter")
}

// TestPasswordConfirm_PolicyViolation verifies that PasswordConfirm rejects a
// new_password that violates h.Policy and returns 400 with the failure message.
func TestPasswordConfirm_PolicyViolation(t *testing.T) {
	testEmail := "confirm-policy@example.com"
	testUserID := uuid.Must(uuid.NewV7())
	testUser := &store.User{ID: testUserID, Email: &testEmail}

	ms := testutil.NewMockStore(testUser)
	tok := seedConfirmToken(ms, testUserID)

	// Policy requires a special character; submitted password has none.
	h := AuthHandler{
		PS: ms,
		RS: testutil.NewMockCache(),
		Policy: PasswordPolicy{
			MinLength:      8,
			RequireSpecial: true,
		},
	}

	r := pwdConfirmReq(tok, "NoSpecialChars1A")
	w := httptest.NewRecorder()

	h.PasswordConfirm(w, r)

	assertPolicyViolation(t, w, "password must contain at least one special character")
}
