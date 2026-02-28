// password_handler.go -- HTTP handlers for password change, reset, and confirm flows.
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

// PasswordChange handles POST /password/change...updates the authenticated user's password.
// Verifies current password, re-hashes the new one, then invalidates all sessions.
// Returns 200 on success, 400 for invalid input, 401 for wrong current password, 500 for server errors.
func (h *AuthHandler) PasswordChange(w http.ResponseWriter, r *http.Request) {
	// Decode request body, expect current_password and new_password
	var pwdChangeInput struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdChangeInput); err != nil {
		logWarn(r, "failed to decode password change input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	if pwdChangeInput.CurrentPassword == "" {
		BadRequest(w, r, "current_password required")
		return
	}

	// Validate new pwd
	if failures := h.Policy.Validate(pwdChangeInput.NewPassword); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	// Pull user_id from context
	id, ok := UserIDFromContext(r.Context())
	if !ok {
		InternalServerError(w, r, errors.New("missing session context"))
		return
	}

	// Fetch stored hash for current password verification.
	passwordHash, err := h.PS.GetPwdHashByUserID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNoPassword) {
			BadRequest(w, r, "password change is not available for OAuth-only accounts")
			return
		}
		InternalServerError(w, r, err)
		return
	}

	// Verify current_password against the stored hash.
	pwdMatch, err := VerifyPassword(pwdChangeInput.CurrentPassword, passwordHash)
	if err != nil {
		InternalServerError(w, r, err)
		return
	} else if !pwdMatch {
		logWarn(r, "password change failed: wrong current password", "user_id", id)
		h.auditLog(r, &id, "user.password_change_failed", nil)
		Unauthorized(w, r, "invalid credentials")
		return
	}

	// Hash new_password with HashPassword.
	newPassword, err := HashPassword(pwdChangeInput.NewPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Update the hash in Postgres with UpdateUserPassword.
	err = h.PS.UpdateUserPassword(r.Context(), id, newPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Delete all sessions from Redis (non-fatal, log warn on error).
	err = h.RS.DeleteAllUserSessions(r.Context(), id)
	if err != nil {
		logWarn(r, "failed to delete all sessions from redis", "error", err)
	}

	// Delete all sessions from Postgres (fatal, return 500 on error).
	err = h.PS.DeleteAllUserSessions(r.Context(), id)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Clear the session cookie; current session is now invalid.
	ClearSessionCookie(w)
	h.auditLog(r, &id, "user.password_changed", nil)
	logInfo(r, "user changed password", "user_id", id)
	OK(w, "password updated")
}

// PasswordReset handles POST /auth/password/reset -- initiates the reset flow for a given email.
func (h *AuthHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	// Get email from req
	var pwdResetInput struct {
		Email        string `json:"email"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdResetInput); err != nil {
		BadRequest(w, r, "invalid request")
		return
	}

	email := strings.ToLower(pwdResetInput.Email)

	// Validate before rate-limit -- keeps garbage strings out of Redis keys.
	if msg := ValidateEmail(email); msg != "" {
		BadRequest(w, r, msg)
		return
	}

	if !h.checkCaptcha(w, r, pwdResetInput.CaptchaToken, h.CaptchaCP.PasswordResetRequest) {
		return
	}

	err := h.RL.Allow(r.Context(), "reset:email:"+email, h.Policies.PasswordReset)
	if err != nil {
		if errors.Is(err, store.ErrRateLimitExceeded) {
			logInfo(r, "password reset failed", "reason", "rate_limited", "email", email)
			TooManyRequests(w)
			return
		}
		InternalServerError(w, r, err)
		return
	}

	const resetMsg = "if that email exists, a reset link has been sent"

	// Get user
	user, err := h.PS.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Generic 200 -- no enumeration (caller cannot learn whether email exists)
		logInfo(r, "password reset failed", "reason", "user_not_found", "email", email)
		OK(w, resetMsg)
		return
	}

	// Gen token
	token, tokenHash, err := GenerateToken()
	if err != nil {
		logError(r, "failed to generate password reset token", "error", err)
		OK(w, resetMsg)
		return
	}

	// Create id for token
	tokenID, err := uuid.NewV7()
	if err != nil {
		logError(r, "failed to generate token id", "error", err)
		OK(w, resetMsg)
		return
	}

	// Add token to pg db, expires in 1 hour
	err = h.PS.CreateToken(r.Context(), tokenID, user.ID, "password_reset", tokenHash[:], time.Now().Add(1*time.Hour))
	if err != nil {
		logError(r, "failed to persist password reset token", "error", err, "user_id", user.ID)
		OK(w, resetMsg)
		return
	}

	// Build vars from available user fields; omit nil pointers.
	vars := map[string]string{}
	if user.FirstName != nil {
		vars["firstName"] = *user.FirstName
	}
	if user.LastName != nil {
		vars["lastName"] = *user.LastName
	}

	// Send pwd reset
	err = h.ML.SendPasswordReset(r.Context(), *user.Email, base64.RawURLEncoding.EncodeToString(token[:]), 1*time.Hour, vars)
	if err != nil {
		logError(r, "failed to send password reset email", "error", err, "user_id", user.ID)
		OK(w, resetMsg)
		return
	}

	h.auditLog(r, &user.ID, "user.password_reset_requested", nil)
	logInfo(r, "password reset email sent", "user_id", user.ID)
	OK(w, resetMsg)
}

// PasswordConfirm handles POST /auth/password/confirm -- completes the reset using the token from the email link.
func (h *AuthHandler) PasswordConfirm(w http.ResponseWriter, r *http.Request) {
	// Decode request body, expect token and new_password
	var pwdConfirmInput struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pwdConfirmInput); err != nil {
		logWarn(r, "failed to decode reset password confirm input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	}

	// Validate new pwd
	if failures := h.Policy.Validate(pwdConfirmInput.NewPassword); len(failures) > 0 {
		BadRequest(w, r, strings.Join(failures, "; "))
		return
	}

	// Decode and hash token
	tokenStr, err := base64.RawURLEncoding.DecodeString(pwdConfirmInput.Token)
	if err != nil {
		BadRequest(w, r, "invalid reset token")
		return
	}
	tokenHash := sha256.Sum256(tokenStr)

	// Use hashed token to consume token in db
	userID, err := h.PS.ConsumeToken(r.Context(), tokenHash[:], "password_reset")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logWarn(r, "password reset failed: invalid or expired token")
			h.auditLog(r, nil, "user.password_reset_failed", nil)
			BadRequest(w, r, "invalid or expired reset token")
			return
		}
		logError(r, "failed to consume reset token", "error", err)
		InternalServerError(w, r, err)
		return
	}

	// Hash new_password with HashPassword.
	newPassword, err := HashPassword(pwdConfirmInput.NewPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Update the hash in Postgres with UpdateUserPassword.
	err = h.PS.UpdateUserPassword(r.Context(), userID, newPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Delete all sessions from Redis (non-fatal, log warn on error).
	err = h.RS.DeleteAllUserSessions(r.Context(), userID)
	if err != nil {
		logWarn(r, "failed to delete all sessions from redis", "error", err)
	}

	// Delete all sessions from Postgres (fatal, return 500 on error).
	err = h.PS.DeleteAllUserSessions(r.Context(), userID)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Set email confirmed. reset proves ownership so non-fatal if fails
	if err = h.PS.SetEmailConfirmedAt(r.Context(), userID); err != nil {
		logWarn(r, "failed to set email_confirmed_at after password reset", "error", err, "user_id", userID)
	}

	// No ClearSessionCookie -- reset flow is unauthenticated; caller has no session cookie.
	// Sessions already purged above. Any stale cookie from a prior login will 401 on next use.
	h.auditLog(r, &userID, "user.password_reset_completed", nil)
	logInfo(r, "user reset password", "user_id", userID)
	OK(w, "password updated")
}
