package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// HashPassword hashes a plaintext password with bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(bytes), err
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// GenerateRandomString produces a cryptographically random base64url string of n bytes.
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateClientSecret generates a random OIDC client secret (32 bytes = 43 chars base64url).
func GenerateClientSecret() (string, error) {
	return GenerateRandomString(32)
}

// GenerateInviteCode generates a random invite code (16 bytes = 22 chars base64url).
func GenerateInviteCode() (string, error) {
	return GenerateRandomString(16)
}
