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
		Message string `json:"message"`
	}{"internal server error"})
}

// BadRequest returns a 400 JSON response with the given message.
// Use for client input validation failures.
func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{message})
}

// Unauthorized returns a 401 JSON response with a generic message.
// Use for authentication failures. Keep message generic to prevent user enumeration.
func Unauthorized(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{message})
}

// Forbidden returns a 403 JSON response with a generic message.
// Intentionally vague, avoids leaking which validation stage failed.
func Forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{"forbidden"})
}

// OK returns a 200 JSON response with the given message.
func OK(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{message})
}
