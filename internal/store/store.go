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
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"  json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_webhooks_user_id"    json:"user_id"`
	User      User      `gorm:"foreignKey:UserID"                                json:"-"`
	URL       string    `gorm:"not null"                                         json:"url"`
	Secret    string    `gorm:"not null"                                         json:"-"`
	Events    string    `gorm:"not null;default:'match,search'"                  json:"events"`
	IsActive  bool      `gorm:"not null;default:true"                            json:"is_active"`
	CreatedAt time.Time `                                                        json:"created_at"`
}

type Plan struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	Name             string    `gorm:"uniqueIndex;not null"                            json:"name"`
	CallLimit        int       `gorm:"not null;default:500"                            json:"call_limit"`
	PriceNaira        int       `gorm:"not null;default:0"                              json:"price_naira"`
	PaystackPlanCode *string   `                                                       json:"paystack_plan_code,omitempty"`
	CreatedAt        time.Time `                                                       json:"created_at"`
}

type User struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	Email                string    `gorm:"uniqueIndex;not null"                            json:"email"`
	PasswordHash         string    `gorm:"default:''"                                      json:"-"`
	FirebaseUID          *string   `gorm:"uniqueIndex;default:null"                        json:"-"`
	PlanID               uuid.UUID `gorm:"type:uuid;not null"                              json:"plan_id"`
	Plan                 Plan      `gorm:"foreignKey:PlanID"                               json:"plan"`
	PaystackCustomerCode *string   `                                                       json:"paystack_customer_code,omitempty"`
	BrandName            string    `gorm:"not null"                                        json:"brand_name"`
	IsAdmin              bool      `gorm:"not null;default:false"                          json:"is_admin"`
	CreatedAt            time.Time `                                                       json:"created_at"`
}

// Subscription tracks a user's Paystack payment for a plan.
type Subscription struct {
	ID                uuid.UUID  `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	UserID            uuid.UUID  `gorm:"type:uuid;not null;index"                        json:"user_id"`
	User              User       `gorm:"foreignKey:UserID"                               json:"-"`
	PlanID            uuid.UUID  `gorm:"type:uuid;not null"                              json:"plan_id"`
	PaystackReference string     `gorm:"uniqueIndex;not null"                            json:"paystack_reference"`
	Status            string     `gorm:"not null;default:'pending'"                      json:"status"` // pending | active | failed
	AmountPaid        int        `gorm:"not null;default:0"                              json:"amount_paid"`
	CreatedAt         time.Time  `                                                       json:"created_at"`
	UpdatedAt         time.Time  `                                                       json:"updated_at"`
	ExpiresAt         *time.Time `                                                       json:"expires_at,omitempty"`
}

// AdminStats holds platform-wide aggregate counters.
type AdminStats struct {
	TotalUsers       int64 `json:"total_users"`
	TotalPlans       int64 `json:"total_plans"`
	TotalAPIKeys     int64 `json:"total_api_keys"`
	TotalAPICalls    int64 `json:"total_api_calls"`
	TotalCollections int64 `json:"total_collections"`
	CallsToday       int64 `json:"calls_today"`
}

type APIKey struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"  json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_api_keys_user_id"    json:"user_id"`
	User       User       `gorm:"foreignKey:UserID"                                json:"-"`
	KeyHash    string     `gorm:"uniqueIndex:idx_api_keys_key_hash;not null"       json:"-"`
	IsLive     bool       `gorm:"not null;default:true"                            json:"is_live"`
	LastUsedAt *time.Time `                                                        json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `                                                        json:"created_at"`
}

type UsageLog struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"          json:"id"`
	APIKeyID  uuid.UUID `gorm:"type:uuid;not null;index:idx_usage_logs_api_key_id"       json:"api_key_id"`
	APIKey    APIKey    `gorm:"foreignKey:APIKeyID"                                      json:"-"`
	Endpoint  string    `gorm:"not null"                                                 json:"endpoint"`
	CallID    string    `gorm:"not null"                                                 json:"call_id"`
	ElapsedMs *int      `                                                                json:"elapsed_ms,omitempty"`
	CreatedAt time.Time `gorm:"index:idx_usage_logs_created_at"                          json:"created_at"`
}

type Collection struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"           json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_collections_user_id"          json:"user_id"`
	User      User      `gorm:"foreignKey:UserID"                                         json:"-"`
	Name      string    `gorm:"not null;uniqueIndex:idx_collections_user_name"            json:"name"`
	FaceCount int       `gorm:"not null;default:0"                                        json:"face_count"`
	CreatedAt time.Time `                                                                 json:"created_at"`
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

// WebhookDelivery records each delivery attempt so users can debug delivery issues.
type WebhookDelivery struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	WebhookID  uuid.UUID `gorm:"type:uuid;not null;index"                        json:"webhook_id"`
	Event      string    `gorm:"not null"                                        json:"event"`
	StatusCode int       `gorm:"not null;default:0"                              json:"status_code"` // 0 = network error
	Success    bool      `gorm:"not null;default:false"                          json:"success"`
	Attempt    int       `gorm:"not null;default:1"                              json:"attempt"`
	Error      string    `gorm:"default:''"                                      json:"error,omitempty"`
	CreatedAt  time.Time `gorm:"index"                                           json:"created_at"`
}

// AuditLog records sensitive operations performed by users and admins.
type AuditLog struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	ActorID    uuid.UUID `gorm:"type:uuid;not null;index"                        json:"actor_id"`
	ActorEmail string    `gorm:"not null"                                        json:"actor_email"`
	Action     string    `gorm:"not null"                                        json:"action"`   // e.g. "api_key.create", "plan.assign"
	TargetID   string    `gorm:"default:''"                                      json:"target_id"` // ID of the affected resource
	IPAddress  string    `gorm:"default:''"                                      json:"ip_address"`
	CreatedAt  time.Time `gorm:"index"                                           json:"created_at"`
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
		&WebhookDelivery{},
		&Subscription{},
		&AuditLog{},
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
	apiKey, err := security.GenerateAPIKey(true)
	if err != nil {
		return nil, "", fmt.Errorf("generate API key: %w", err)
	}

	key := APIKey{
		UserID:  req.UserID,
		KeyHash: apiKey.Hash,
		IsLive:  true,
	}

	if err := s.db.WithContext(ctx).Create(&key).Error; err != nil {
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
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&face).Error; err != nil {
			return err
		}
		return tx.Model(&Collection{}).Where("id = ?", collectionID).UpdateColumn("face_count", gorm.Expr("face_count + 1")).Error
	})
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

// GetUserByFirebaseUID looks up a user by their Firebase UID.
func (s *Store) GetUserByFirebaseUID(ctx context.Context, uid string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("firebase_uid = ?", uid).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateFirebaseUser creates a new user record for a Firebase-authenticated account.
// Password is not stored — Firebase owns authentication for these users.
func (s *Store) CreateFirebaseUser(ctx context.Context, firebaseUID, email, brandName string) (*User, error) {
	freePlan, err := s.GetFreePlan(ctx)
	if err != nil {
		return nil, fmt.Errorf("no free plan: %w", err)
	}
	user := User{
		FirebaseUID: &firebaseUID,
		Email:       email,
		BrandName:   brandName,
		PlanID:      freePlan.ID,
	}
	if err := s.db.WithContext(ctx).Create(&user).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("email already registered")
		}
		return nil, fmt.Errorf("db create firebase user: %w", err)
	}
	return &user, nil
}

// CreateAdminUser creates a user with is_admin=true.
// If no free plan exists it auto-creates one so bootstrap works on a blank DB.
// Used only by the bootstrap endpoint — remove or gate after setup.
func (s *Store) CreateAdminUser(ctx context.Context, email, password, brandName string) (*User, error) {
	freePlan, err := s.GetFreePlan(ctx)
	if err != nil {
		// No free plan yet — seed one so bootstrap works on a fresh database.
		seeded := Plan{Name: "Free", CallLimit: 500, PriceNaira: 0}
		if err := s.db.WithContext(ctx).Create(&seeded).Error; err != nil && !isUniqueViolation(err) {
			return nil, fmt.Errorf("seed free plan: %w", err)
		}
		freePlan, err = s.GetFreePlan(ctx)
		if err != nil {
			return nil, fmt.Errorf("get free plan after seed: %w", err)
		}
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	user := User{
		Email:        email,
		PasswordHash: hash,
		BrandName:    brandName,
		PlanID:       freePlan.ID,
		IsAdmin:      true,
	}
	if err := s.db.WithContext(ctx).Create(&user).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("email already registered")
		}
		return nil, fmt.Errorf("db create admin: %w", err)
	}
	return &user, nil
}

// GetFreePlan returns the first plan with price_naira = 0, ordered by call_limit ascending.
// Used to assign a default plan to new users at signup; they pay to upgrade later.
func (s *Store) GetFreePlan(ctx context.Context) (*Plan, error) {
	var plan Plan
	err := s.db.WithContext(ctx).
		Where("price_naira = 0").
		Order("call_limit ASC").
		First(&plan).Error
	if err != nil {
		return nil, fmt.Errorf("no free plan found: %w", err)
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

// ErrDuplicatePlanName is returned when a plan with that name already exists.
var ErrDuplicatePlanName = errors.New("a plan with that name already exists")

func (s *Store) CreatePlan(ctx context.Context, req interfacex.CreatePlanRequest) (*Plan, error) {
	plan := Plan{
		Name:       req.Name,
		CallLimit:  req.CallLimit,
		PriceNaira: req.PriceNaira,
	}

	if err := s.db.WithContext(ctx).Create(&plan).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDuplicatePlanName
		}
		return nil, fmt.Errorf("db create plan: %w", err)
	}

	return &plan, nil
}

// UpdatePlan applies partial updates to a plan.
func (s *Store) UpdatePlan(ctx context.Context, planID uuid.UUID, req interfacex.UpdatePlanRequest) (*Plan, error) {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.CallLimit > 0 {
		updates["call_limit"] = req.CallLimit
	}
	// PriceNaira can legitimately be 0 (free plan), so we always include it
	updates["price_naira"] = req.PriceNaira

	if len(updates) == 0 {
		return s.GetPlanByID(ctx, planID)
	}

	if err := s.db.WithContext(ctx).Model(&Plan{}).Where("id = ?", planID).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update plan: %w", err)
	}
	return s.GetPlanByID(ctx, planID)
}

// DeletePlan removes a plan. Returns an error if users are still on this plan.
func (s *Store) DeletePlan(ctx context.Context, planID uuid.UUID) error {
	var count int64
	if err := s.db.WithContext(ctx).Model(&User{}).Where("plan_id = ?", planID).Count(&count).Error; err != nil {
		return fmt.Errorf("check plan users: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("cannot delete plan: %d user(s) are currently on this plan", count)
	}
	result := s.db.WithContext(ctx).Delete(&Plan{}, "id = ?", planID)
	if result.Error != nil {
		return fmt.Errorf("delete plan: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("plan not found")
	}
	return nil
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

// DowngradePlan moves a user back to the free plan (price_naira = 0).
// Returns the updated user or an error if no free plan is configured.
func (s *Store) DowngradePlan(ctx context.Context, userID uuid.UUID) (*User, error) {
	freePlan, err := s.GetFreePlan(ctx)
	if err != nil {
		return nil, fmt.Errorf("no free plan available: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&User{}).Where("id = ?", userID).Update("plan_id", freePlan.ID).Error; err != nil {
		return nil, fmt.Errorf("db downgrade plan: %w", err)
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

// RotateWebhookSecret regenerates the signing secret for a webhook.
// Returns the new plaintext secret (shown only once).
func (s *Store) RotateWebhookSecret(ctx context.Context, userID, webhookID uuid.UUID) (string, error) {
	newSecret, err := generateWebhookSecret()
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	result := s.db.WithContext(ctx).
		Model(&Webhook{}).
		Where("id = ? AND user_id = ? AND is_active = true", webhookID, userID).
		Update("secret", newSecret)
	if result.Error != nil {
		return "", fmt.Errorf("rotate webhook secret: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return "", fmt.Errorf("webhook not found or access denied")
	}
	return newSecret, nil
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

// ── Subscription / Payment methods ────────────────────────────────────────────

// CreateSubscription inserts a new pending subscription record.
func (s *Store) CreateSubscription(ctx context.Context, userID, planID uuid.UUID, reference string, amount int) (*Subscription, error) {
	sub := Subscription{
		UserID:            userID,
		PlanID:            planID,
		PaystackReference: reference,
		Status:            "pending",
		AmountPaid:        amount,
	}
	if err := s.db.WithContext(ctx).Create(&sub).Error; err != nil {
		return nil, fmt.Errorf("create subscription: %w", err)
	}
	return &sub, nil
}

// ActivateSubscription marks a subscription as active and switches the user's plan.
// userID and planID are used as a fallback when the subscription record was never
// pre-created (e.g. CreateSubscription failed silently during initialize).
// Runs in a transaction so both updates succeed or neither does.
func (s *Store) ActivateSubscription(ctx context.Context, reference, customerCode string, userID, planID uuid.UUID, amountKobo int) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var sub Subscription
		err := tx.Where("paystack_reference = ?", reference).First(&sub).Error
		if err != nil {
			// Record was never created — insert it now as active.
			sub = Subscription{
				UserID:            userID,
				PlanID:            planID,
				PaystackReference: reference,
				Status:            "active",
				AmountPaid:        amountKobo,
			}
			if err2 := tx.Create(&sub).Error; err2 != nil {
				return fmt.Errorf("create subscription: %w", err2)
			}
		} else {
			if err := tx.Model(&sub).Updates(map[string]any{
				"status":     "active",
				"updated_at": time.Now(),
			}).Error; err != nil {
				return fmt.Errorf("update subscription status: %w", err)
			}
		}

		updates := map[string]any{"plan_id": sub.PlanID}
		if customerCode != "" {
			updates["paystack_customer_code"] = customerCode
		}
		if err := tx.Model(&User{}).Where("id = ?", sub.UserID).Updates(updates).Error; err != nil {
			return fmt.Errorf("update user plan: %w", err)
		}

		return nil
	})
}

// FailSubscription marks a subscription as failed.
func (s *Store) FailSubscription(ctx context.Context, reference string) error {
	return s.db.WithContext(ctx).
		Model(&Subscription{}).
		Where("paystack_reference = ?", reference).
		Updates(map[string]any{"status": "failed", "updated_at": time.Now()}).Error
}

// ── Webhook delivery history ──────────────────────────────────────────────────

// RecordDelivery persists a single webhook delivery attempt.
// Errors are non-fatal — a logging failure must not block event dispatch.
func (s *Store) RecordDelivery(webhookID uuid.UUID, event string, statusCode int, success bool, attempt int, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := WebhookDelivery{
		WebhookID:  webhookID,
		Event:      event,
		StatusCode: statusCode,
		Success:    success,
		Attempt:    attempt,
		Error:      errMsg,
	}
	if err := s.db.WithContext(ctx).Create(&d).Error; err != nil {
		// Non-fatal: log but continue.
		_ = err
	}
}

// ListWebhookDeliveries returns the most recent delivery attempts for a webhook.
func (s *Store) ListWebhookDeliveries(ctx context.Context, userID, webhookID uuid.UUID, limit int) ([]WebhookDelivery, error) {
	// Verify the webhook belongs to the requesting user before returning history.
	var wh Webhook
	if err := s.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", webhookID, userID).
		First(&wh).Error; err != nil {
		return nil, fmt.Errorf("webhook not found or access denied")
	}

	var deliveries []WebhookDelivery
	err := s.db.WithContext(ctx).
		Where("webhook_id = ?", webhookID).
		Order("created_at DESC").
		Limit(limit).
		Find(&deliveries).Error
	return deliveries, err
}

// ── Audit log ─────────────────────────────────────────────────────────────────

// WriteAuditLog inserts an audit entry. Errors are intentionally non-fatal —
// a logging failure must never block a business operation.
func (s *Store) WriteAuditLog(ctx context.Context, actorID uuid.UUID, actorEmail, action, targetID, ip string) {
	entry := AuditLog{
		ActorID:    actorID,
		ActorEmail: actorEmail,
		Action:     action,
		TargetID:   targetID,
		IPAddress:  ip,
	}
	if err := s.db.WithContext(ctx).Create(&entry).Error; err != nil {
		// Use background context so a cancelled request context doesn't
		// swallow the audit write.
		_ = s.db.Create(&entry).Error
	}
}

// AdminListAuditLogs returns paginated audit entries, newest first.
func (s *Store) AdminListAuditLogs(ctx context.Context, page, pageSize int) ([]AuditLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 25
	}
	offset := (page - 1) * pageSize

	var total int64
	if err := s.db.WithContext(ctx).Model(&AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []AuditLog
	if err := s.db.WithContext(ctx).
		Order("created_at DESC").
		Offset(offset).Limit(pageSize).
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// GetSubscriptionByReference looks up a subscription by its Paystack reference.
func (s *Store) GetSubscriptionByReference(ctx context.Context, reference string) (*Subscription, error) {
	var sub Subscription
	if err := s.db.WithContext(ctx).Where("paystack_reference = ?", reference).First(&sub).Error; err != nil {
		return nil, fmt.Errorf("subscription not found: %w", err)
	}
	return &sub, nil
}
