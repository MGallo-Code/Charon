// verification_handler.go -- handlers and helpers for email verification flows.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// sendVerificationEmail generates a token, stores it, and mails the verification link.
// trigger identifies the source: "registration" or "resend". Non-fatal: errors are logged but never fail the enclosing request.
func (h *AuthHandler) sendVerificationEmail(r *http.Request, userID uuid.UUID, email, trigger string) {
	verifyToken, verifyTokenHash, err := GenerateToken()
	if err != nil {
		logWarn(r, "failed to generate verification token", "error", err)
		return
	}

	tokenID, err := uuid.NewV7()
	if err != nil {
		logWarn(r, "failed to generate verification token id", "error", err)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if err = h.PS.CreateToken(r.Context(), tokenID, userID, "email_verification", verifyTokenHash[:], expiresAt); err != nil {
		logWarn(r, "failed to store verification token", "error", err)
		return
	}

	tokenStr := base64.RawURLEncoding.EncodeToString(verifyToken[:])
	if err = h.ML.SendEmailVerification(r.Context(), email, tokenStr, 24*time.Hour, map[string]string{}); err != nil {
		logWarn(r, "failed to send verification email", "error", err)
		return
	}
	h.auditLog(r, &userID, "user.email_verification_requested", marshalMeta(struct {
		Trigger string `json:"trigger"`
	}{trigger}))
}

// ResendVerificationEmail handles POST /resend/verification-email -- re-sends the verification link.
// Rate-limited per email. Returns generic 200 regardless of whether the email exists
// or is already confirmed (no enumeration).
func (h *AuthHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email        string `json:"email"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logWarn(r, "failed to decode resend verification email input", "error", err)
		BadRequest(w, r, "invalid request")
		return
	}

	email := strings.ToLower(input.Email)

	if errMsg := ValidateEmail(email); errMsg != "" {
		BadRequest(w, r, errMsg)
		return
	}

	const resendMsg = "if that email is registered and unverified, a verification link has been sent"

	if !h.checkCaptcha(w, r, input.CaptchaToken, h.CaptchaCP.ResendVerification) {
		return
	}

	if err := h.RL.Allow(r.Context(), "resend:email:"+email, h.Policies.ResendVerification); err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "resend verification failed", "reason", "rate_limited", "email", email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	user, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Generic response for both not-found and DB errors -- no enumeration.
		if !errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "failed to fetch user for resend verification", "error", err)
		} else {
			logInfo(r, "resend verification failed", "reason", "user_not_found", "email", email)
		}
		OK(w, resendMsg)
		return
	}

	if user.EmailConfirmedAt != nil {
		logInfo(r, "resend verification failed", "reason", "already_confirmed", "user_id", user.ID)
		OK(w, resendMsg)
		return
	}

	// sendVerificationEmail handles its own logging and audit.
	h.sendVerificationEmail(r, user.ID, *user.Email, "resend")
	OK(w, resendMsg)
}

// VerifyEmail handles POST /verify/email -- consumes a single-use token from
// the verification link and sets email_confirmed_at for the associated user.
// Returns 200 on success, 400 for an invalid/expired token, 500 for DB errors.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token        string `json:"token"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logWarn(r, "failed to decode verify email input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}
	if input.Token == "" {
		BadRequest(w, r, "token is required")
		return
	}

	if !h.checkCaptcha(w, r, input.CaptchaToken, h.CaptchaCP.VerifyEmail) {
		return
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil {
		logWarn(r, "failed to decode verification token", "error", err)
		BadRequest(w, r, "invalid token")
		return
	}

	tokenHash := sha256.Sum256(rawToken)
	userID, err := h.PS.ConsumeToken(r.Context(), tokenHash[:], "email_verification")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "invalid or expired verification token")
			BadRequest(w, r, "invalid or expired token")
			return
		}
		logError(r, "failed to consume verification token", "error", err)
		InternalServerError(w, r, err)
		return
	}

	if err = h.PS.SetEmailConfirmedAt(r.Context(), userID); err != nil {
		logError(r, "failed to set email_confirmed_at", "error", err, "user_id", userID)
		InternalServerError(w, r, err)
		return
	}

	h.auditLog(r, &userID, "user.email_verified", nil)
	logInfo(r, "email verified", "user_id", userID)
	OK(w, "email verified")
}
