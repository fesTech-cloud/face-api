package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ── Models ────────────────────────────────────────────────────────────────────

type Plan struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Name           string    `gorm:"uniqueIndex;not null"`
	CallLimit      int       `gorm:"not null;default:500"`
	PriceUSDCents  int       `gorm:"not null;default:0"`
	StripePriceID  *string
	CreatedAt      time.Time
}

type User struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Email            string    `gorm:"uniqueIndex;not null"`
	PasswordHash     string    `gorm:"not null"`
	PlanID           uuid.UUID `gorm:"type:uuid;not null"`
	Plan             Plan      `gorm:"foreignKey:PlanID"`
	StripeCustomerID *string
	CreatedAt        time.Time
}

type APIKey struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_api_keys_user_id"`
	User       User       `gorm:"foreignKey:UserID"`
	KeyHash    string     `gorm:"uniqueIndex:idx_api_keys_key_hash;not null"`
	Name       string     `gorm:"not null;default:default"`
	IsLive     bool       `gorm:"not null;default:true"`
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

type UsageLog struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	APIKeyID uuid.UUID `gorm:"type:uuid;not null;index:idx_usage_logs_api_key_id"`
	APIKey   APIKey    `gorm:"foreignKey:APIKeyID"`
	Endpoint string    `gorm:"not null"`
	CallID   string    `gorm:"not null"`
	ElapsedMs *int
	CreatedAt time.Time `gorm:"index:idx_usage_logs_created_at"`
}

type Collection struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_collections_user_id"`
	User      User      `gorm:"foreignKey:UserID"`
	Name      string    `gorm:"not null;uniqueIndex:idx_collections_user_name"`
	FaceCount int       `gorm:"not null;default:0"`
	CreatedAt time.Time
}

func (Collection) TableName() string { return "collections" }

// FaceEmbedding stores a 128-dim pgvector embedding.
// The `embedding` column is managed as a raw type; pgvector is not natively
// supported by GORM so we use a []float32 with a custom column type tag.
type FaceEmbedding struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	CollectionID uuid.UUID  `gorm:"type:uuid;not null;index:idx_face_embeddings_collection"`
	Collection   Collection `gorm:"foreignKey:CollectionID"`
	PersonID     string     `gorm:"not null"`
	Embedding    []float32  `gorm:"type:vector(128);not null"`
	CreatedAt    time.Time
}

// ── APIKeyRecord is the lightweight DTO returned to callers ───────────────────

type APIKeyRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CallLimit int
	IsLive    bool
}

// ── Store ─────────────────────────────────────────────────────────────────────

type Store struct {
	db *gorm.DB
}

func New(dbURL string) (*Store, error) {
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("gorm.Open: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("db.DB: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() {
	if sqlDB, err := s.db.DB(); err == nil {
		sqlDB.Close()
	}
}

// GetAPIKey looks up an active API key by its raw token.
// Returns nil, nil if not found.
func (s *Store) GetAPIKey(ctx context.Context, token string) (*APIKeyRecord, error) {
	var key APIKey
	err := s.db.WithContext(ctx).
		Joins("JOIN users u ON u.id = api_keys.user_id").
		Joins("JOIN plans p ON p.id = u.plan_id").
		Where("api_keys.key_hash = ? AND api_keys.is_live = true", hashToken(token)).
		Select("api_keys.id, api_keys.user_id, api_keys.is_live, p.call_limit").
		First(&key).Error
	if err != nil {
		return nil, nil
	}
	return &APIKeyRecord{
		ID:        key.ID,
		UserID:    key.UserID,
		CallLimit: key.User.Plan.CallLimit,
		IsLive:    key.IsLive,
	}, nil
}

func hashToken(token string) string {
	// TODO: replace with crypto/sha256 + hex.EncodeToString
	return token
}
