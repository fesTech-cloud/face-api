package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/security"
)

// APIKeyMiddleware validates the Bearer token and enforces quota.
func APIKeyMiddleware(db *store.Store, rdb *cache.Cache) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization: Bearer sk_live_...
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid Authorization header",
			})
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")
		// Validate key against DB
		keyRecord, err := db.GetAPIKeyCached(c.Request.Context(), token)
		if err != nil || keyRecord == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid API key",
			})
			return
		}

		// fmt.Printf("API key valid for user ID: %s with call limit: %d\n", keyRecord.UserID, keyRecord.CallLimit)

		// Check monthly quota via Redis
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

		// Increment usage counter
		_ = rdb.IncrementUsage(c.Request.Context(), token)

		// Attach key info to context for handlers
		c.Set("api_key", token)
		c.Set("user_id", keyRecord.UserID.String())
		c.Set("call_limit", keyRecord.CallLimit)

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
