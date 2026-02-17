// responses.go -- Package-wide HTTP response helpers.
//
// Shared by handlers and middleware. All JSON is encoded via json.Marshal
// (never fmt.Sprintf) to prevent injection from attacker-controlled strings.
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
	w.Write([]byte(`{"message":"internal server error"}`))
}

// BadRequest returns a 400 JSON response with the given message.
// Use for client input validation failures.
func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	resp, _ := json.Marshal(map[string]string{"message": message})
	w.Write(resp)
}

// Unauthorized returns a 401 JSON response with a generic message.
// Use for authentication failures. Keep message generic to prevent user enumeration.
func Unauthorized(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	resp, _ := json.Marshal(map[string]string{"message": message})
	w.Write(resp)
}
