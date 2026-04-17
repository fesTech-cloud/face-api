package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"face-api/internal/cache"
	"face-api/internal/firebase"
	"face-api/internal/store"
	"face-api/x/security"
)

// APIKeyMiddleware validates the Bearer token, enforces burst + monthly quota.
// Accepts two token forms:
//   - PASETO widget token (starts with "v4.local.") — issued by POST /face/session-token
//   - Secret API key — issued by /dashboard/api-keys
func APIKeyMiddleware(db *store.Store, rdb *cache.Cache) gin.HandlerFunc {
	const (
		maxFailuresPerIP = 50
		failureWindow    = time.Minute
		maxBurstPerSec   = 30
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

		// ── Widget session token path ─────────────────────────────────────────
		if strings.HasPrefix(token, "v4.local.") {
			claims, err := security.NewPasetoManager().VerifyWidgetToken(token)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session token"})
				return
			}
			used, _ := rdb.GetUserMonthlyUsage(c.Request.Context(), claims.UserID)
			if used >= int64(claims.CallLimit) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "monthly quota exceeded",
					"used":  used,
					"limit": claims.CallLimit,
				})
				return
			}
			_ = rdb.IncrementUserUsage(c.Request.Context(), claims.UserID)
			c.Set("user_id", claims.UserID)
			c.Set("call_limit", claims.CallLimit)
			c.Set("key_scope", "widget")
			c.Next()
			return
		}

		// ── Standard API key path ─────────────────────────────────────────────
		allowed, _ := rdb.CheckAPIKeyFailures(c.Request.Context(), c.ClientIP(), maxFailuresPerIP, failureWindow)
		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many failed authentication attempts, please try again later",
			})
			return
		}

		keyRecord, err := db.GetAPIKeyCached(c.Request.Context(), token)
		if err != nil || keyRecord == nil {
			_, _ = rdb.CheckAPIKeyFailures(c.Request.Context(), c.ClientIP(), maxFailuresPerIP, failureWindow)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}

		burstOK, _ := rdb.CheckBurstLimit(c.Request.Context(), token, maxBurstPerSec)
		if !burstOK {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "request rate limit exceeded, slow down"})
			return
		}

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

		_ = rdb.IncrementUsage(c.Request.Context(), token)
		_ = rdb.IncrementUserUsage(c.Request.Context(), keyRecord.UserID.String())

		c.Set("api_key", token)
		c.Set("user_id", keyRecord.UserID.String())
		c.Set("call_limit", keyRecord.CallLimit)
		c.Set("key_scope", "secret")

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

// FirebaseTokenMiddleware verifies a Firebase ID token and sets "firebase_uid"
// and "firebase_email" in the context. It does NOT require the user to exist in
// the DB — used only on the /dashboard/sync endpoint.
func FirebaseTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
			return
		}
		token, err := firebase.VerifyIDToken(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Firebase token"})
			return
		}
		email, _ := token.Claims["email"].(string)
		c.Set("firebase_uid", token.UID)
		c.Set("firebase_email", email)
		c.Next()
	}
}

// FirebaseUserMiddleware verifies a Firebase ID token and loads the matching
// user from the DB. Aborts with 401 if the token is invalid or the user has
// not yet been synced (call POST /dashboard/sync first).
func FirebaseUserMiddleware(db *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
			return
		}
		token, err := firebase.VerifyIDToken(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Firebase token"})
			return
		}
		user, err := db.GetUserByFirebaseUID(c.Request.Context(), token.UID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":        "user not found — complete signup first",
				"requires_sync": true,
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
