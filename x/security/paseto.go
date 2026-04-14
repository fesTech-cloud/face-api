package security

import (
	"fmt"
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

// ── Claims — what you get back after verifying ────────────────────────────────
type Claims struct {
	UserID    string
	Email     string
	ExpiresAt time.Time
}

type PasetoManager struct {
	secretKey paseto.V4SymmetricKey
}

func NewPasetoManager() *PasetoManager {
	hex := os.Getenv("PASETO_SECRET")
	if hex == "" {
		panic("PASETO_SECRET environment variable not set")
	}

	key, err := paseto.V4SymmetricKeyFromHex(hex)
	if err != nil {
		panic(fmt.Sprintf("invalid PASETO_SECRET: %v", err))
	}

	return &PasetoManager{secretKey: key}
}

// GenerateToken creates a PASETO token for a user
func (m *PasetoManager) GenerateToken(userID, email string, duration time.Duration) (string, error) {
	token := paseto.NewToken()

	// Standard claims
	token.SetJti(uuid.New().String())       // unique token ID
	token.SetIssuer("face-api")             // who issued it
	token.SetSubject(userID)                // who it belongs to
	token.SetAudience("face-api-dashboard") // who it is for
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(duration))

	// Custom claims
	token.SetString("user_id", userID)
	token.SetString("email", email)

	// Encrypt → produces v4.local.xxxxx string
	encrypted := token.V4Encrypt(m.secretKey, nil)
	return encrypted, nil
}

func (m *PasetoManager) VerifyToken(tokenStr string) (*Claims, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))
	parser.AddRule(paseto.IssuedBy("face-api"))
	parser.AddRule(paseto.ForAudience("face-api-dashboard"))

	token, err := parser.ParseV4Local(m.secretKey, tokenStr, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	userID, err := token.GetString("user_id")
	if err != nil {
		return nil, fmt.Errorf("missing user_id claim")
	}

	email, err := token.GetString("email")
	if err != nil {
		return nil, fmt.Errorf("missing email claim")
	}

	expiration, err := token.GetExpiration()
	if err != nil {
		return nil, fmt.Errorf("missing expiration claim")
	}

	return &Claims{
		UserID:    userID,
		Email:     email,
		ExpiresAt: expiration,
	}, nil
}
