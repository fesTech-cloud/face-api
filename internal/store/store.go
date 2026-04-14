package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"face-api/internal/cache"
	"face-api/x/interfacex"
	"face-api/x/security"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pgvector/pgvector-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ── Models ────────────────────────────────────────────────────────────────────

// Webhook stores a registered endpoint that receives signed event payloads.
// The Secret is stored in plaintext because we need it to sign outgoing requests.
// It is returned to the user only once at creation time.
type Webhook struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_webhooks_user_id"`
	User      User      `gorm:"foreignKey:UserID"`
	URL       string    `gorm:"not null"`
	Secret    string    `gorm:"not null"`
	Events    string    `gorm:"not null;default:'match,search'"` // comma-separated event names
	IsActive  bool      `gorm:"not null;default:true"`
	CreatedAt time.Time
}

type Plan struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Name          string    `gorm:"uniqueIndex;not null"`
	CallLimit     int       `gorm:"not null;default:500"`
	PriceUSDCents int       `gorm:"not null;default:0"`
	StripePriceID *string
	CreatedAt     time.Time
}

type User struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Email            string    `gorm:"uniqueIndex;not null"`
	PasswordHash     string    `gorm:"not null"`
	PlanID           uuid.UUID `gorm:"type:uuid;not null"`
	Plan             Plan      `gorm:"foreignKey:PlanID"`
	StripeCustomerID *string
	BrandName        string `gorm:"not null"`
	CreatedAt        time.Time
}

type APIKey struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index:idx_api_keys_user_id"`
	User       User      `gorm:"foreignKey:UserID"`
	KeyHash    string    `gorm:"uniqueIndex:idx_api_keys_key_hash;not null"`
	IsLive     bool      `gorm:"not null;default:true"`
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

type UsageLog struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	APIKeyID  uuid.UUID `gorm:"type:uuid;not null;index:idx_usage_logs_api_key_id"`
	APIKey    APIKey    `gorm:"foreignKey:APIKeyID"`
	Endpoint  string    `gorm:"not null"`
	CallID    string    `gorm:"not null"`
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
	ID           uuid.UUID       `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	CollectionID uuid.UUID       `gorm:"type:uuid;not null;index:idx_face_embeddings_collection"`
	Collection   Collection      `gorm:"foreignKey:CollectionID"`
	PersonID     string          `gorm:"not null"`
	Embedding    pgvector.Vector `gorm:"type:vector(128)"`
	Metadata     string
	CreatedAt    time.Time
}

// FaceSearchResult is the enriched DTO returned from SearchFaces.
type FaceSearchResult struct {
	FaceID         uuid.UUID `json:"face_id"`
	PersonID       string    `json:"person_id"`
	Metadata       string    `json:"metadata"`
	Distance       float64   `json:"distance"`
	Confidence     float64   `json:"confidence"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	CollectionID   uuid.UUID `json:"collection_id"`
	CollectionName string    `json:"collection_name"`
}

type APIKeyRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CallLimit int
	IsLive    bool
}

// ── Store ─────────────────────────────────────────────────────────────────────

type Store struct {
	db    *gorm.DB
	cache *cache.Cache
}

func New(dbURL string, c *cache.Cache) (*Store, error) {
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

	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return nil, fmt.Errorf("uuid-ossp extension: %w", err)
	}
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS vector").Error; err != nil {
		return nil, fmt.Errorf("pgvector extension: %w", err)
	}

	if err := db.AutoMigrate(
		&Plan{},
		&User{},
		&APIKey{},
		&UsageLog{},
		&Collection{},
		&FaceEmbedding{},
		&Webhook{},
	); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}

	return &Store{db: db, cache: c}, nil
}

func (s *Store) Close() {
	if sqlDB, err := s.db.DB(); err == nil {
		sqlDB.Close()
	}
}

// GetAPIKey looks up an active API key by its raw token.
// Returns nil, nil if not found.
func (s *Store) GetAPIKey(ctx context.Context, token string) (*APIKeyRecord, error) {
	var rec APIKeyRecord
	err := s.db.WithContext(ctx).
		Raw(`
			SELECT ak.id, ak.user_id, ak.is_live, p.call_limit
			FROM api_keys ak
			JOIN users u ON u.id = ak.user_id
			JOIN plans p ON p.id = u.plan_id
			WHERE ak.key_hash = ? AND ak.is_live = true
			LIMIT 1
		`, security.HashKey(token)).
		Scan(&rec).Error
	if err != nil || rec.ID == (uuid.UUID{}) {
		return nil, nil
	}

	return &rec, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, req interfacex.CreateAPIKeyRequest) (*APIKeyRecord, string, error) {
	apiKey, err := security.GenerateAPIKey(req.IsLive)
	if err != nil {
		return nil, "", fmt.Errorf("generate API key: %w", err)
	}

	key := APIKey{
		UserID:  req.UserID,
		KeyHash: apiKey.Hash,
		IsLive:  req.IsLive,
	}

	if err := s.db.WithContext(ctx).Create(&key).Error; err != nil {
		// Handle the extremely rare DB unique violation
		if isUniqueViolation(err) {
			return nil, "", fmt.Errorf("key collision, please retry")
		}
		return nil, "", fmt.Errorf("db create API key: %w", err)
	}

	return &APIKeyRecord{
		ID:     key.ID,
		UserID: key.UserID,
		IsLive: key.IsLive,
	}, apiKey.Raw, nil
}

// isUniqueViolation checks for PostgreSQL unique constraint error
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
func (s *Store) GetOrCreateCollection(ctx context.Context, userID uuid.UUID, name string) (*Collection, error) {
	var col Collection
	err := s.db.WithContext(ctx).
		Where(Collection{UserID: userID, Name: name}).
		FirstOrCreate(&col).Error
	if err != nil {
		return nil, fmt.Errorf("get or create collection: %w", err)
	}
	return &col, nil
}

func (s *Store) EnrollFace(ctx context.Context, collectionID uuid.UUID, personID string, embedding []float32, metadata string) error {
	face := FaceEmbedding{
		CollectionID: collectionID,
		PersonID:     personID,
		Embedding:    pgvector.NewVector(embedding),
		Metadata:     metadata,
	}
	return s.db.WithContext(ctx).Create(&face).Error
}

func (s *Store) SearchFaces(ctx context.Context, collectionID uuid.UUID, queryEmbedding []float32, limit int) ([]FaceSearchResult, error) {
	var results []FaceSearchResult

	vec := pgvector.NewVector(queryEmbedding)

	err := s.db.WithContext(ctx).
		Raw(`
			SELECT
				fe.id          AS face_id,
				fe.person_id,
				fe.metadata,
				fe.created_at  AS enrolled_at,
				fe.collection_id,
				c.name         AS collection_name,
				(fe.embedding <-> ?::vector) AS distance
			FROM face_embeddings fe
			JOIN collections c ON c.id = fe.collection_id
			WHERE fe.collection_id = ?
			  AND (fe.embedding <-> ?::vector) < 0.6
			ORDER BY distance ASC
			LIMIT ?
		`, vec, collectionID, vec, limit).
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	// Compute confidence from distance: 1 - (dist / 1.2), clamped to [0, 1]
	for i, r := range results {
		conf := 1.0 - (r.Distance / 1.2)
		if conf < 0 {
			conf = 0
		}
		results[i].Confidence = math.Round(conf*10000) / 10000
	}

	return results, nil
}

func (s *Store) GetAPIKeyCached(ctx context.Context, rawToken string) (*APIKeyRecord, error) {
	hash := security.HashKey(rawToken)
	cacheKey := "apikey:" + hash

	// Check Redis first
	cached, err := s.cache.Get(ctx, cacheKey)
	if err == nil {
		var rec APIKeyRecord
		json.Unmarshal([]byte(cached), &rec)
		return &rec, nil
	}

	// Miss — hit DB
	rec, err := s.GetAPIKey(ctx, rawToken)
	if err != nil || rec == nil {
		return nil, err
	}

	// Cache for 5 minutes
	data, _ := json.Marshal(rec)
	s.cache.Set(ctx, cacheKey, data, 5*time.Minute)

	return rec, nil
}

func (s *Store) CreateUser(ctx context.Context, req interfacex.CreateAccountRequest) (*User, error) {
	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := User{
		Email:        req.Email,
		BrandName:    req.BrandName,
		PasswordHash: passwordHash,
		PlanID:       req.PlanID,
	}

	if err := s.db.WithContext(ctx).Create(&user).Error; err != nil {
		return nil, fmt.Errorf("db create user: %w", err)
	}

	return &user, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetPlanByID(ctx context.Context, id uuid.UUID) (*Plan, error) {
	var plan Plan
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&plan).Error
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *Store) GetAllPlans(ctx context.Context) ([]Plan, error) {
	var plans []Plan
	err := s.db.WithContext(ctx).Find(&plans).Error
	if err != nil {
		return nil, err
	}
	return plans, nil
}

func (s *Store) GetUserById(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) CreatePlan(ctx context.Context, req interfacex.CreatePlanRequest) (*Plan, error) {
	plan := Plan{
		Name:          req.Name,
		CallLimit:     req.CallLimit,
		PriceUSDCents: req.PriceCents,
	}

	if err := s.db.WithContext(ctx).Create(&plan).Error; err != nil {
		return nil, fmt.Errorf("db create plan: %w", err)
	}

	return &plan, nil
}

func (s *Store) ActivatePlan(ctx context.Context, userID uuid.UUID, planID uuid.UUID) (*User, error) {
	if err := s.db.WithContext(ctx).First(&Plan{}, "id = ?", planID).Error; err != nil {
		return nil, fmt.Errorf("plan not found")
	}

	if err := s.db.WithContext(ctx).Model(&User{}).Where("id = ?", userID).Update("plan_id", planID).Error; err != nil {
		return nil, fmt.Errorf("db activate plan: %w", err)
	}

	return s.GetUserById(ctx, userID.String())
}

// DeleteCollection removes a collection and all its face embeddings.
// It verifies ownership by requiring both userID and collectionID to match.
func (s *Store) DeleteCollection(ctx context.Context, userID uuid.UUID, collectionID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Verify ownership before deleting
		var col Collection
		if err := tx.Where("id = ? AND user_id = ?", collectionID, userID).First(&col).Error; err != nil {
			return fmt.Errorf("collection not found or access denied")
		}
		if err := tx.Where("collection_id = ?", collectionID).Delete(&FaceEmbedding{}).Error; err != nil {
			return fmt.Errorf("delete embeddings: %w", err)
		}
		if err := tx.Delete(&col).Error; err != nil {
			return fmt.Errorf("delete collection: %w", err)
		}
		return nil
	})
}

// ListAPIKeys returns all API keys for a user (hashes are not exposed).
func (s *Store) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]APIKey, error) {
	var keys []APIKey
	err := s.db.WithContext(ctx).
		Select("id, user_id, is_live, last_used_at, created_at").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&keys).Error
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	return keys, nil
}

// DeleteAPIKey deactivates an API key, verifying it belongs to the user.
func (s *Store) DeleteAPIKey(ctx context.Context, userID uuid.UUID, keyID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&APIKey{}).
		Where("id = ? AND user_id = ?", keyID, userID).
		Update("is_live", false)
	if result.Error != nil {
		return fmt.Errorf("delete api key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found or access denied")
	}
	return nil
}

// GetUserCollections returns all collections for a given user.
func (s *Store) GetUserCollections(ctx context.Context, userID uuid.UUID) ([]Collection, error) {
	var collections []Collection
	err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&collections).Error
	if err != nil {
		return nil, fmt.Errorf("get user collections: %w", err)
	}
	return collections, nil
}

// ── Webhook methods ───────────────────────────────────────────────────────────

// generateWebhookSecret returns a cryptographically random 32-byte hex string.
func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateWebhook registers a new webhook for the user and returns the record
// along with the plaintext secret (shown only once).
func (s *Store) CreateWebhook(ctx context.Context, userID uuid.UUID, url string, events []string) (*Webhook, string, error) {
	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, "", fmt.Errorf("generate webhook secret: %w", err)
	}

	wh := Webhook{
		UserID:   userID,
		URL:      url,
		Secret:   secret,
		Events:   strings.Join(events, ","),
		IsActive: true,
	}

	if err := s.db.WithContext(ctx).Create(&wh).Error; err != nil {
		return nil, "", fmt.Errorf("db create webhook: %w", err)
	}

	return &wh, secret, nil
}

// ListWebhooks returns all active webhooks for a user (secret omitted).
func (s *Store) ListWebhooks(ctx context.Context, userID uuid.UUID) ([]Webhook, error) {
	var hooks []Webhook
	err := s.db.WithContext(ctx).
		Select("id, user_id, url, events, is_active, created_at").
		Where("user_id = ? AND is_active = true", userID).
		Order("created_at DESC").
		Find(&hooks).Error
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return hooks, nil
}

// DeleteWebhook deactivates a webhook, verifying it belongs to the user.
func (s *Store) DeleteWebhook(ctx context.Context, userID uuid.UUID, webhookID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&Webhook{}).
		Where("id = ? AND user_id = ?", webhookID, userID).
		Update("is_active", false)
	if result.Error != nil {
		return fmt.Errorf("delete webhook: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("webhook not found or access denied")
	}
	return nil
}

// GetActiveWebhooksForEvent returns active webhooks for a user subscribed to the given event.
func (s *Store) GetActiveWebhooksForEvent(ctx context.Context, userID uuid.UUID, event string) ([]Webhook, error) {
	var hooks []Webhook
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true", userID).
		Find(&hooks).Error
	if err != nil {
		return nil, fmt.Errorf("get webhooks: %w", err)
	}

	var matched []Webhook
	for _, wh := range hooks {
		for _, e := range strings.Split(wh.Events, ",") {
			if strings.TrimSpace(e) == event {
				matched = append(matched, wh)
				break
			}
		}
	}
	return matched, nil
}

// SearchFacesAcrossCollections searches for matching faces across all collections for a user.
func (s *Store) SearchFacesAcrossCollections(ctx context.Context, userID uuid.UUID, queryEmbedding []float32, limit int) ([]FaceSearchResult, error) {
	var results []FaceSearchResult

	vec := pgvector.NewVector(queryEmbedding)

	err := s.db.WithContext(ctx).
		Raw(`
			SELECT
				fe.id          AS face_id,
				fe.person_id,
				fe.metadata,
				fe.created_at  AS enrolled_at,
				fe.collection_id,
				c.name         AS collection_name,
				(fe.embedding <-> ?::vector) AS distance
			FROM face_embeddings fe
			JOIN collections c ON c.id = fe.collection_id
			WHERE c.user_id = ?
			  AND (fe.embedding <-> ?::vector) < 0.6
			ORDER BY distance ASC
			LIMIT ?
		`, vec, userID, vec, limit).
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	// Compute confidence from distance: 1 - (dist / 1.2), clamped to [0, 1]
	for i, r := range results {
		conf := 1.0 - (r.Distance / 1.2)
		if conf < 0 {
			conf = 0
		}
		results[i].Confidence = math.Round(conf*10000) / 10000
	}

	return results, nil
}
