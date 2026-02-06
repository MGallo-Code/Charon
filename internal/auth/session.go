// session.go -- Session token generation, validation, and destruction.
//
// Tokens: 256-bit cryptographically random (crypto/rand).
// Storage: tokens are SHA-256 hashed before storing (never store plaintext).
// Validation: check Redis first (fast path), fall back to Postgres.
// Cookies: HttpOnly, Secure, SameSite=Lax, __Host-session prefix.
package auth
