package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ── Admin store methods ───────────────────────────────────────────────────────
// All methods here operate across all users (no ownership scoping).
// They must only be called from admin-protected handlers.

// AdminListUsers returns paginated users with an optional search filter on
// email or brand_name. Returns the slice and the total match count.
func (s *Store) AdminListUsers(ctx context.Context, search string, page, pageSize int) ([]User, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	q := s.db.WithContext(ctx).Model(&User{}).Preload("Plan")
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("email ILIKE ? OR brand_name ILIKE ?", like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list users count: %w", err)
	}

	var users []User
	if err := q.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list users: %w", err)
	}

	return users, total, nil
}

// AdminGetUser returns a single user with their plan loaded.
func (s *Store) AdminGetUser(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Preload("Plan").Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("admin get user: %w", err)
	}
	return &user, nil
}

// AdminAssignPlan changes a user's active plan.
func (s *Store) AdminAssignPlan(ctx context.Context, userID uuid.UUID, planID uuid.UUID) (*User, error) {
	if err := s.db.WithContext(ctx).First(&Plan{}, "id = ?", planID).Error; err != nil {
		return nil, fmt.Errorf("plan not found")
	}
	if err := s.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", userID).
		Update("plan_id", planID).Error; err != nil {
		return nil, fmt.Errorf("admin assign plan: %w", err)
	}
	return s.AdminGetUser(ctx, userID.String())
}

// AdminDeleteUser removes a user and cascade-deletes their API keys.
// Usage logs reference API keys so they are deleted too.
func (s *Store) AdminDeleteUser(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete usage logs via api_key references
		if err := tx.
			Where("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)", userID).
			Delete(&UsageLog{}).Error; err != nil {
			return fmt.Errorf("delete usage logs: %w", err)
		}
		// Delete api keys
		if err := tx.Where("user_id = ?", userID).Delete(&APIKey{}).Error; err != nil {
			return fmt.Errorf("delete api keys: %w", err)
		}
		// Delete face embeddings via collections
		if err := tx.
			Where("collection_id IN (SELECT id FROM collections WHERE user_id = ?)", userID).
			Delete(&FaceEmbedding{}).Error; err != nil {
			return fmt.Errorf("delete face embeddings: %w", err)
		}
		// Delete collections
		if err := tx.Where("user_id = ?", userID).Delete(&Collection{}).Error; err != nil {
			return fmt.Errorf("delete collections: %w", err)
		}
		// Delete webhooks
		if err := tx.Where("user_id = ?", userID).Delete(&Webhook{}).Error; err != nil {
			return fmt.Errorf("delete webhooks: %w", err)
		}
		// Delete user
		if err := tx.Delete(&User{}, "id = ?", userID).Error; err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	})
}

// AdminListAPIKeys returns paginated API keys, optionally filtered by user ID.
func (s *Store) AdminListAPIKeys(ctx context.Context, userIDFilter string, page, pageSize int) ([]APIKey, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	q := s.db.WithContext(ctx).Model(&APIKey{}).
		Select("id, user_id, is_live, last_used_at, created_at")
	if userIDFilter != "" {
		q = q.Where("user_id = ?", userIDFilter)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list api keys count: %w", err)
	}

	var keys []APIKey
	if err := q.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&keys).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list api keys: %w", err)
	}

	return keys, total, nil
}

// AdminRevokeAPIKey disables any API key regardless of owner.
func (s *Store) AdminRevokeAPIKey(ctx context.Context, keyID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&APIKey{}).
		Where("id = ?", keyID).
		Update("is_live", false)
	if result.Error != nil {
		return fmt.Errorf("admin revoke api key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

// AdminListUsageLogs returns paginated usage logs with optional filters.
func (s *Store) AdminListUsageLogs(ctx context.Context, userIDFilter, endpoint string, page, pageSize int) ([]UsageLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 25
	}
	offset := (page - 1) * pageSize

	q := s.db.WithContext(ctx).Model(&UsageLog{})
	if endpoint != "" {
		q = q.Where("endpoint = ?", endpoint)
	}
	if userIDFilter != "" {
		q = q.Where("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)", userIDFilter)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list usage logs count: %w", err)
	}

	var logs []UsageLog
	if err := q.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, fmt.Errorf("admin list usage logs: %w", err)
	}

	return logs, total, nil
}

// UserStats holds per-user aggregate counters returned by AdminGetUserStats.
type UserStats struct {
	TotalAPICalls   int64            `json:"total_api_calls"`
	CallsThisMonth  int64            `json:"calls_this_month"`
	TotalAPIKeys    int64            `json:"total_api_keys"`
	LiveAPIKeys     int64            `json:"live_api_keys"`
	Collections     int64            `json:"collections"`
	TotalFaces      int64            `json:"total_faces"`
	Webhooks        int64            `json:"webhooks"`
	CallsByEndpoint map[string]int64 `json:"calls_by_endpoint"`
}

// AdminGetUserStats returns aggregate activity statistics for a single user.
func (s *Store) AdminGetUserStats(ctx context.Context, userID uuid.UUID) (*UserStats, error) {
	var stats UserStats

	// Total API calls (all time)
	if err := s.db.WithContext(ctx).Model(&UsageLog{}).
		Where("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)", userID).
		Count(&stats.TotalAPICalls).Error; err != nil {
		return nil, fmt.Errorf("count api calls: %w", err)
	}

	// Calls this month (UTC month boundary)
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if err := s.db.WithContext(ctx).Model(&UsageLog{}).
		Where("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?) AND created_at >= ?", userID, monthStart).
		Count(&stats.CallsThisMonth).Error; err != nil {
		return nil, fmt.Errorf("count calls this month: %w", err)
	}

	// Total API keys
	if err := s.db.WithContext(ctx).Model(&APIKey{}).
		Where("user_id = ?", userID).
		Count(&stats.TotalAPIKeys).Error; err != nil {
		return nil, fmt.Errorf("count api keys: %w", err)
	}

	// Live (active) API keys
	if err := s.db.WithContext(ctx).Model(&APIKey{}).
		Where("user_id = ? AND is_live = true", userID).
		Count(&stats.LiveAPIKeys).Error; err != nil {
		return nil, fmt.Errorf("count live api keys: %w", err)
	}

	// Collections
	if err := s.db.WithContext(ctx).Model(&Collection{}).
		Where("user_id = ?", userID).
		Count(&stats.Collections).Error; err != nil {
		return nil, fmt.Errorf("count collections: %w", err)
	}

	// Total face embeddings across all collections
	if err := s.db.WithContext(ctx).Model(&FaceEmbedding{}).
		Where("collection_id IN (SELECT id FROM collections WHERE user_id = ?)", userID).
		Count(&stats.TotalFaces).Error; err != nil {
		return nil, fmt.Errorf("count faces: %w", err)
	}

	// Active webhooks
	if err := s.db.WithContext(ctx).Model(&Webhook{}).
		Where("user_id = ? AND is_active = true", userID).
		Count(&stats.Webhooks).Error; err != nil {
		return nil, fmt.Errorf("count webhooks: %w", err)
	}

	// Calls grouped by endpoint
	type endpointCount struct {
		Endpoint string
		Count    int64
	}
	var rows []endpointCount
	if err := s.db.WithContext(ctx).
		Model(&UsageLog{}).
		Select("endpoint, COUNT(*) AS count").
		Where("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)", userID).
		Group("endpoint").
		Order("count DESC").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("calls by endpoint: %w", err)
	}
	stats.CallsByEndpoint = make(map[string]int64, len(rows))
	for _, r := range rows {
		stats.CallsByEndpoint[r.Endpoint] = r.Count
	}

	return &stats, nil
}

// AdminGetStats returns platform-wide aggregate counts.
func (s *Store) AdminGetStats(ctx context.Context) (*AdminStats, error) {
	var stats AdminStats

	if err := s.db.WithContext(ctx).Model(&User{}).Count(&stats.TotalUsers).Error; err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&Plan{}).Count(&stats.TotalPlans).Error; err != nil {
		return nil, fmt.Errorf("count plans: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&APIKey{}).Count(&stats.TotalAPIKeys).Error; err != nil {
		return nil, fmt.Errorf("count api keys: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&UsageLog{}).Count(&stats.TotalAPICalls).Error; err != nil {
		return nil, fmt.Errorf("count api calls: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&Collection{}).Count(&stats.TotalCollections).Error; err != nil {
		return nil, fmt.Errorf("count collections: %w", err)
	}

	// Calls today (UTC midnight → now)
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	if err := s.db.WithContext(ctx).Model(&UsageLog{}).
		Where("created_at >= ?", todayStart).
		Count(&stats.CallsToday).Error; err != nil {
		return nil, fmt.Errorf("count calls today: %w", err)
	}

	return &stats, nil
}
