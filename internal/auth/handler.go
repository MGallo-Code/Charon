// Package auth contains HTTP handlers and core authentication logic.
//
// handler.go -- HTTP handlers for all /auth/* endpoints.
// Registers routes on a chi router, returns JSON responses.
// Delegates to session, password, and csrf packages for logic.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// SessionCache defines session cache operations needed by auth handlers.
// Satisfied by *store.RedisStore — defined here (at consumer) per Go convention.
type SessionCache interface {
	GetSession(ctx context.Context, tokenHash string) (*store.CachedSession, error)
}

// AuthHandler holds dependencies for all /auth/* HTTP handlers and middleware.
type AuthHandler struct {
	PS *store.PostgresStore
	RS SessionCache
}

func InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	// HELP WITH THIS?
	slog.Error("internal server error", "error", err, "method", r.Method, "path", r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"message":"internal server error"}`))
}

func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(fmt.Sprintf(`{"message":"%s"}`, message)))
}

// Register handles a client request to create a new user
func (h *AuthHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	// registration input requirements
	var registerInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// Attempt to read body into input requirements
	err := json.NewDecoder(r.Body).Decode(&registerInput)
	if err != nil {
		slog.Warn("failed to decode register input", "error", err)
		BadRequest(w, r, "error decoding request body")
		return
	} else if registerInput.Email == "" {
		BadRequest(w, r, "No email provided")
		return
	} else if emailLen := len(registerInput.Email); emailLen < 5 {
		BadRequest(w, r, "Email too short!")
		return
	} else if emailLen > 254 {
		BadRequest(w, r, "Email too long!")
		return
	}
	if _, err := mail.ParseAddress(registerInput.Email); err != nil {
		BadRequest(w, r, "Invalid email format")
		return
	}
	if registerInput.Password == "" {
		BadRequest(w, r, "No password provided!")
		return
	} else if pwdLen := len(registerInput.Password); pwdLen < 6 {
		BadRequest(w, r, "Password too short!")
		return
	} else if pwdLen > 128 {
		BadRequest(w, r, "Password too long!")
		return
	}

	// Try to hash password, if doesn't work internal server error
	hashedPassword, err := HashPassword(registerInput.Password)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Attempt to generate user ID
	userID, err := uuid.NewV7()
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// Attempt to create user w/ postgres store, if doesn't work internal server error
	err = h.PS.CreateUserByEmail(r.Context(), userID, registerInput.Email, hashedPassword)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	// User created! Return user ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(fmt.Sprintf(`{"user_id":"%s"}`, userID)))
}
