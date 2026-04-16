package cache

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache wraps a Redis client.
type Cache struct {
	rdb *redis.Client
	ns  string // key namespace, e.g. "prod" or "dev"
}

// New creates a new Cache connected to the given Redis URL.
// All keys are prefixed with the APP_ENV environment variable (default: "dev")
// so that staging and production instances never share Redis keys.
func New(redisURL string) (*Cache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	ns := os.Getenv("APP_ENV")
	if ns == "" {
		ns = "dev"
	}
	return &Cache{rdb: rdb, ns: ns}, nil
}

// key returns a namespaced Redis key: "<env>:<rest>"
func (c *Cache) key(rest string) string {
	return c.ns + ":" + rest
}

// Close closes the Redis connection.
func (c *Cache) Close() error {
	return c.rdb.Close()
}

// GetMonthlyUsage returns the number of API calls made this month for a raw API key.
func (c *Cache) GetMonthlyUsage(ctx context.Context, apiKey string) (int64, error) {
	month := time.Now().UTC().Format("2006-01")
	k := c.key(fmt.Sprintf("rate:%s:%s", apiKey, month))
	val, err := c.rdb.Get(ctx, k).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

// IncrementUsage increments the per-API-key monthly call counter with a 32-day TTL.
func (c *Cache) IncrementUsage(ctx context.Context, apiKey string) error {
	month := time.Now().UTC().Format("2006-01")
	k := c.key(fmt.Sprintf("rate:%s:%s", apiKey, month))
	pipe := c.rdb.Pipeline()
	pipe.Incr(ctx, k)
	pipe.Expire(ctx, k, 32*24*time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

// IncrementUserUsage increments the user-level aggregate counter used by the dashboard.
func (c *Cache) IncrementUserUsage(ctx context.Context, userID string) error {
	month := time.Now().UTC().Format("2006-01")
	k := c.key(fmt.Sprintf("rate:user:%s:%s", userID, month))
	pipe := c.rdb.Pipeline()
	pipe.Incr(ctx, k)
	pipe.Expire(ctx, k, 32*24*time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

// GetUserMonthlyUsage returns aggregate API calls this month for a user.
func (c *Cache) GetUserMonthlyUsage(ctx context.Context, userID string) (int64, error) {
	month := time.Now().UTC().Format("2006-01")
	k := c.key(fmt.Sprintf("rate:user:%s:%s", userID, month))
	val, err := c.rdb.Get(ctx, k).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (c *Cache) Get(ctx context.Context, rawKey string) (string, error) {
	return c.rdb.Get(ctx, c.key(rawKey)).Result()
}

func (c *Cache) Set(ctx context.Context, rawKey string, value any, ttl time.Duration) error {
	return c.rdb.Set(ctx, c.key(rawKey), value, ttl).Err()
}

// CheckLoginRateLimit returns true if the caller is allowed to attempt login.
// Allows up to maxAttempts per IP per window.
func (c *Cache) CheckLoginRateLimit(ctx context.Context, ip string, maxAttempts int64, window time.Duration) (bool, error) {
	k := c.key(fmt.Sprintf("login_attempts:%s", ip))
	count, err := c.rdb.Incr(ctx, k).Result()
	if err != nil {
		return true, err // fail open if Redis is down
	}
	if count == 1 {
		c.rdb.Expire(ctx, k, window)
	}
	return count <= maxAttempts, nil
}

// CheckAccountLockout tracks failed login attempts per email address.
// Returns false (locked) once the email exceeds maxAttempts within the window.
func (c *Cache) CheckAccountLockout(ctx context.Context, email string, maxAttempts int64, window time.Duration) (bool, error) {
	k := c.key(fmt.Sprintf("login_fail_email:%s", email))
	count, err := c.rdb.Incr(ctx, k).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		c.rdb.Expire(ctx, k, window)
	}
	return count <= maxAttempts, nil
}

// CheckAPIKeyFailures tracks failed API key authentication attempts per IP.
// Returns false (blocked) once the IP exceeds maxFailures within the window.
func (c *Cache) CheckAPIKeyFailures(ctx context.Context, ip string, maxFailures int64, window time.Duration) (bool, error) {
	k := c.key(fmt.Sprintf("apikey_fail:%s", ip))
	count, err := c.rdb.Incr(ctx, k).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		c.rdb.Expire(ctx, k, window)
	}
	return count <= maxFailures, nil
}

// CheckPaymentInitLimit prevents payment initialization spam per user.
// Allows up to maxAttempts per window (e.g. 5 per hour).
func (c *Cache) CheckPaymentInitLimit(ctx context.Context, userID string, maxAttempts int64, window time.Duration) (bool, error) {
	k := c.key(fmt.Sprintf("pay_init:%s", userID))
	count, err := c.rdb.Incr(ctx, k).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		c.rdb.Expire(ctx, k, window)
	}
	return count <= maxAttempts, nil
}

// CheckBurstLimit enforces a per-second burst cap per API key.
// Returns false if the key has exceeded maxPerSecond calls in the current second.
func (c *Cache) CheckBurstLimit(ctx context.Context, apiKey string, maxPerSecond int64) (bool, error) {
	second := time.Now().UTC().Format("20060102T150405")
	k := c.key(fmt.Sprintf("burst:%s:%s", apiKey, second))
	count, err := c.rdb.Incr(ctx, k).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		c.rdb.Expire(ctx, k, 2*time.Second)
	}
	return count <= maxPerSecond, nil
}
