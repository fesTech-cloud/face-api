package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache wraps a Redis client.
type Cache struct {
	rdb *redis.Client
}

// New creates a new Cache connected to the given Redis URL.
func New(redisURL string) (*Cache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Cache{rdb: rdb}, nil
}

// Close closes the Redis connection.
func (c *Cache) Close() error {
	return c.rdb.Close()
}

// monthKey returns the Redis key for an API key's monthly usage counter.
// e.g. rate:sk_live_abc123:2026-03
func monthKey(apiKey string) string {
	month := time.Now().UTC().Format("2006-01")
	return fmt.Sprintf("rate:%s:%s", apiKey, month)
}

// GetMonthlyUsage returns the number of API calls made this month.
func (c *Cache) GetMonthlyUsage(ctx context.Context, apiKey string) (int64, error) {
	val, err := c.rdb.Get(ctx, monthKey(apiKey)).Int64()
	if err == redis.Nil {
		return 0, nil // key doesn't exist yet = 0 calls
	}
	return val, err
}

// IncrementUsage increments the monthly call counter and sets a 32-day TTL.
func (c *Cache) IncrementUsage(ctx context.Context, apiKey string) error {
	key := monthKey(apiKey)
	pipe := c.rdb.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 32*24*time.Hour) // slightly more than a month
	_, err := pipe.Exec(ctx)
	return err
}

// userMonthKey returns the Redis key for a user's aggregate monthly usage.
// e.g. rate:user:uuid:2026-03
func userMonthKey(userID string) string {
	month := time.Now().UTC().Format("2006-01")
	return fmt.Sprintf("rate:user:%s:%s", userID, month)
}

// IncrementUserUsage increments a user-level aggregate counter (for the dashboard).
func (c *Cache) IncrementUserUsage(ctx context.Context, userID string) error {
	key := userMonthKey(userID)
	pipe := c.rdb.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 32*24*time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

// GetUserMonthlyUsage returns aggregate API calls this month for a user.
func (c *Cache) GetUserMonthlyUsage(ctx context.Context, userID string) (int64, error) {
	val, err := c.rdb.Get(ctx, userMonthKey(userID)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	return c.rdb.Get(ctx, key).Result()
}

func (c *Cache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

// CheckLoginRateLimit returns true if the caller is allowed to attempt login.
// Allows up to maxAttempts per IP per window. Uses Redis INCR + EXPIRE so
// the window resets automatically.
func (c *Cache) CheckLoginRateLimit(ctx context.Context, ip string, maxAttempts int64, window time.Duration) (bool, error) {
	key := fmt.Sprintf("login_attempts:%s", ip)
	count, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		// If Redis is down, fail open (allow the request) to avoid locking users out.
		return true, err
	}
	if count == 1 {
		// First attempt in this window — set the expiry.
		c.rdb.Expire(ctx, key, window)
	}
	return count <= maxAttempts, nil
}
