package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type APIKey struct {
	Raw    string // shown to user ONCE, never stored
	Hash   string // stored in DB
	Prefix string // sk_live_ or sk_test_
}

func GenerateAPIKey(live bool) (APIKey, error) {
	// 32 random bytes = 64 hex chars
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return APIKey{}, fmt.Errorf("generate key: %w", err)
	}

	prefix := "sk_test_"
	if live {
		prefix = "sk_live_"
	}

	raw := prefix + hex.EncodeToString(b)
	hash := HashKey(raw)

	return APIKey{Raw: raw, Hash: hash, Prefix: prefix}, nil
}

// HashKey hashes a raw API key for safe DB storage
func HashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

const bcryptCost = 12 // higher = slower = harder to crack
// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(bytes), nil
}

// ComparePassword checks a plain password against a bcrypt hash
func ComparePassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
