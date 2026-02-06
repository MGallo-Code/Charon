// csrf.go -- CSRF token generation and validation.
//
// Generates a per-session CSRF token (crypto/rand).
// Validates on all state-changing requests (POST, PUT, DELETE).
// SameSite=Lax handles most cases; CSRF tokens cover the rest.
package auth
