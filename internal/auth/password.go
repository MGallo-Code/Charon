// password.go -- Password hashing and verification using Argon2id.
//
// Argon2id is GPU-resistant and recommended over bcrypt.
// Uses golang.org/x/crypto/argon2.
// All password comparisons use constant-time comparison (crypto/subtle).
package auth
