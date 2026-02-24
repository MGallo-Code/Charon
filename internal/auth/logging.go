// logging.go -- Request-scoped logging and audit helpers.
//
// Wraps slog with automatic extraction of request context (IP, user agent,
// method, path) so handlers don't have to repeat these fields on every call.
package auth

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gofrs/uuid/v5"

	"github.com/MGallo-Code/charon/internal/store"
)

// reqAttrs returns standard request-scoped attributes for logging.
func reqAttrs(r *http.Request) []any {
	return []any{
		"request_id", middleware.GetReqID(r.Context()),
		"ip", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"method", r.Method,
		"path", r.URL.Path,
	}
}

// logDebug logs at debug level with automatic request context.
func logDebug(r *http.Request, msg string, args ...any) {
	slog.Debug(msg, append(reqAttrs(r), args...)...)
}

// logInfo logs at info level with automatic request context.
func logInfo(r *http.Request, msg string, args ...any) {
	slog.Info(msg, append(reqAttrs(r), args...)...)
}

// logWarn logs at warn level with automatic request context.
func logWarn(r *http.Request, msg string, args ...any) {
	slog.Warn(msg, append(reqAttrs(r), args...)...)
}

// logError logs at error level with automatic request context.
func logError(r *http.Request, msg string, args ...any) {
	slog.Error(msg, append(reqAttrs(r), args...)...)
}

// auditLog writes an audit event to the DB. Non-fatal -- logs on failure but never fails the request.
// Pass nil for userID on pre-auth failures. Pass nil for metadata when no extra context is needed.
func (h *AuthHandler) auditLog(r *http.Request, userID *uuid.UUID, action string, metadata []byte) {
	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.PS.WriteAuditLog(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    action,
		IPAddress: &ip,
		UserAgent: &ua,
		Metadata:  metadata,
	}); err != nil {
		logError(r, "audit log write failed", "action", action, "error", err)
	}
}
