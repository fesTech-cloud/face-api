package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/security"
)

// APIKeyMiddleware validates the Bearer token, enforces burst + monthly quota.
func APIKeyMiddleware(db *store.Store, rdb *cache.Cache) gin.HandlerFunc {
	const (
		maxFailuresPerIP = 50             // block after 50 bad keys per minute per IP
		failureWindow    = time.Minute
		maxBurstPerSec   = 30             // max 30 requests/second per key
	)
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid Authorization header",
			})
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")

		// Brute-force protection: block IPs with too many bad key attempts.
		allowed, _ := rdb.CheckAPIKeyFailures(c.Request.Context(), c.ClientIP(), maxFailuresPerIP, failureWindow)
		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many failed authentication attempts, please try again later",
			})
			return
		}

		// Validate key against DB.
		keyRecord, err := db.GetAPIKeyCached(c.Request.Context(), token)
		if err != nil || keyRecord == nil {
			// Count this failure for brute-force tracking.
			_, _ = rdb.CheckAPIKeyFailures(c.Request.Context(), c.ClientIP(), maxFailuresPerIP, failureWindow)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid API key",
			})
			return
		}

		// Burst rate limit: max N req/sec per key.
		burstOK, _ := rdb.CheckBurstLimit(c.Request.Context(), token, maxBurstPerSec)
		if !burstOK {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "request rate limit exceeded, slow down",
			})
			return
		}

		// Monthly quota check.
		used, err := rdb.GetMonthlyUsage(c.Request.Context(), token)
		if err == nil && used >= int64(keyRecord.CallLimit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "monthly quota exceeded",
				"used":       used,
				"limit":      keyRecord.CallLimit,
				"reset_date": "first day of next month",
			})
			return
		}

		// Increment usage counters (per-key and per-user aggregate).
		_ = rdb.IncrementUsage(c.Request.Context(), token)
		_ = rdb.IncrementUserUsage(c.Request.Context(), keyRecord.UserID.String())

		c.Set("api_key", token)
		c.Set("user_id", keyRecord.UserID.String())
		c.Set("call_limit", keyRecord.CallLimit)

		c.Next()
	}
}

// AdminMiddleware verifies the PASETO token and requires the user to have
// IsAdmin = true. It sets the same "user" context key as AuthenticatedUserMiddleware.
func AdminMiddleware(db *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid Authorization header",
			})
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")

		securityManager := security.NewPasetoManager()
		claims, err := securityManager.VerifyToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		user, err := db.GetUserById(c.Request.Context(), claims.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "user not found",
			})
			return
		}

		if !user.IsAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "admin access required",
			})
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

func AuthenticatedUserMiddleware(db *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid Authorization header",
			})
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")

		securityManager := security.NewPasetoManager()
		claims, err := securityManager.VerifyToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		user, err := db.GetUserById(c.Request.Context(), claims.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "user not found",
			})
			return
		}
		c.Set("user", user)
		c.Next()
	}
}
