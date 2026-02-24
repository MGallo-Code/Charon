// password.go

// Argon2id password hashing and verification.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	netmail "net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonSaltLen = 16
	argonTime    = uint32(3)
	argonMemory  = uint32(64 * 1024)
	argonThreads = uint8(2)
	argonKeyLen  = uint32(32)
)

// HashPassword returns PHC-formatted Argon2id hash of plaintext password.
// Format: $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
func HashPassword(password string) (string, error) {
	// Gen 16-byte random salt
	salt := make([]byte, argonSaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	// Derive hash
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// Encode as PHC format string
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword checks plaintext password against stored Argon2id hash.
// Extracts params from stored hash so old passwords verify after param changes.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Split PHC string
	// Format: $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
	parts := strings.Split(encodedHash, "$")
	// Make sure string divided into 6 parts
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Check to make sure using correct algorithm
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// init vars, scan string and pull values out from string
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("parsing hash params: %w", err)
	}

	// Decode salt string, return any errors
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decoding salt: %w", err)
	}

	// Decode hash to string
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}

	// Re-derive hash with extracted params
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	// Compare pwds w/ constant time for timing attacks
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}

// ValidateEmail checks format and length constraints; returns error message or empty string.
// RFC 5321: min ~5 chars (a@b.c), max 254.
func ValidateEmail(email string) string {
	if email == "" {
		return "No email provided"
	}
	emailLen := len(email)
	if emailLen < 5 {
		return "Email too short!"
	}
	if emailLen > 254 {
		return "Email too long!"
	}
	if _, err := netmail.ParseAddress(email); err != nil {
		return "Invalid email format"
	}
	return ""
}

// ValidatePassword checks length constraints; returns error message or empty string.
func ValidatePassword(password string) string {
	// Validate password — min 8 chars (user-perceived), max 128 bytes (Argon2id DoS guard).
	if password == "" {
		return "No password provided!"
	}
	if utf8.RuneCountInString(password) < 8 {
		return "Password too short!"
	}
	if len(password) > 128 {
		return "Password too long!"
	}
	return ""
}
