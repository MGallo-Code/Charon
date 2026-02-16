// logging.go -- Request-scoped logging helpers.
//
// Wraps slog with automatic extraction of request context (IP, user agent,
// method, path) so handlers don't have to repeat these fields on every call.
package auth

import (
	"log/slog"
	"net/http"
)

// reqAttrs returns standard request-scoped attributes for logging.
func reqAttrs(r *http.Request) []any {
	return []any{
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
