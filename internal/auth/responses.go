// responses.go -- Package-wide HTTP response helpers.
// Shared by handlers and middleware.
package auth

import (
	"encoding/json"
	"net/http"
)

// InternalServerError logs the error and returns a generic 500 JSON response.
// Never exposes internal error details to prevent information leakage.
func InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	logError(r, "internal server error", "error", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{"internal server error"})
}

// ServiceUnavailable logs the error and returns a 503 JSON response.
// Use when a dependency (Postgres, Redis) is unreachable. Never exposes error details.
func ServiceUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	logError(r, "service unavailable", "error", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{"service unavailable"})
}

// BadRequest returns a 400 JSON response with the given message.
// Use for client input validation failures.
func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}

// Unauthorized returns a 401 JSON response with a generic message.
// Use for authentication failures. Keep message generic to prevent user enumeration.
func Unauthorized(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}

// Forbidden returns a 403 JSON response with a generic message.
// Intentionally vague, avoids leaking which validation stage failed.
func Forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{"forbidden"})
}

// TooManyRequests returns a 429 JSON response.
func TooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{"too many requests"})
}

// OK returns a 200 JSON response with the given message.
func OK(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{message})
}
