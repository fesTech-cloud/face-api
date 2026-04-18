package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"face-api/internal/api"
	"face-api/internal/api/admin"
	"face-api/internal/api/dasboard"
	"face-api/internal/auth"
	"face-api/internal/cache"
	"face-api/internal/engine"
	"face-api/internal/firebase"
	"face-api/internal/store"
)

func main() {
	// Load .env (ignored in production if not present)
	_ = godotenv.Load()

	// ── Redis ────────────────────────────────────────────────────────────────
	rdb, err := cache.New(mustEnv("REDIS_URL"))
	if err != nil {
		log.Fatalf("redis connect: %v", err)
	}
	defer rdb.Close()

	// ── Database ────────────────────────────────────────────────────────────
	db, err := store.New(mustEnv("DB_URL"), rdb)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer db.Close()

	// ── Firebase Admin SDK ──────────────────────────────────────────────────
	if err := firebase.Init(context.Background()); err != nil {
		log.Fatalf("firebase init: %v", err)
	}

	// ── Face engine (go-face / dlib) ────────────────────────────────────────
	modelsDir := getEnv("MODELS_DIR", "./models")
	faceEngine, err := engine.New(modelsDir)
	if err != nil {
		log.Fatalf("face engine init: %v", err)
	}
	defer faceEngine.Close()

	// ── Gin router ──────────────────────────────────────────────────────────
	if getEnv("GIN_MODE", "debug") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Global middleware
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(requestid.New())
	r.Use(securityHeaders())

	// ALLOWED_ORIGINS scopes the dashboard CORS.
	// The /face group uses AllowAllOrigins separately (see below).
	// ALLOWED_ORIGINS must be set in production — default is localhost only
	// so a misconfigured prod deploy fails loudly rather than silently open.
	rawOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001")
	corsOrigins := strings.Split(rawOrigins, ",")

	// ── Routes ──────────────────────────────────────────────────────────────
	// Public
	r.GET("/health", healthHandler)

	// Temporary bootstrap — seed first admin account.
	// Requires X-Bootstrap-Secret header matching BOOTSTRAP_SECRET env var.
	// Remove this route (or unset BOOTSTRAP_SECRET) after setup.
	{
		bh := admin.NewHandler(db, rdb)
		r.POST("/bootstrap/admin", bh.BootstrapAdmin)
	}
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "face-api",
			"version": "1.0.0",
			"docs":    "/docs",
		})
	})

	// Authenticated API routes — open CORS so the browser widget can call from
	// any customer domain. Auth is enforced by APIKeyMiddleware.
	face := r.Group("/face")
	face.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           1 * time.Hour,
	}))
	// Catch-all OPTIONS so the CORS preflight is handled before auth middleware.
	// Without this gin returns 404 for OPTIONS and the middleware never fires.
	face.OPTIONS("/*path", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	face.Use(auth.APIKeyMiddleware(db, rdb))
	{
		h := api.NewHandler(db, rdb, faceEngine)

		face.POST("/match", h.Match)
		face.POST("/verify", h.Verify)
		face.POST("/detect", h.Detect)
		face.POST("/enroll", h.Enroll)
		face.POST("/search", h.Search)
		face.GET("/collections", h.ListCollections)
		face.DELETE("/collections/:id", h.DeleteCollection)
		face.GET("/usage", h.Usage)
		face.POST("/session-token", h.CreateSessionToken)
	}

	// Public admin login — issues PASETO token, no Firebase involved
	{
		h := admin.NewHandler(db, rdb)
		r.POST("/admin/login", h.Login)
	}

	adminRoute := r.Group("/admin")
	adminRoute.Use(auth.AdminMiddleware(db))
	{
		h := admin.NewHandler(db, rdb)

		adminRoute.GET("/stats", h.GetStats)
		adminRoute.GET("/users", h.ListUsers)
		adminRoute.GET("/users/:id", h.GetUser)
		adminRoute.GET("/users/:id/stats", h.GetUserStats)
		adminRoute.PATCH("/users/:id/plan", h.AssignPlan)
		adminRoute.DELETE("/users/:id", h.DeleteUser)
		adminRoute.GET("/api-keys", h.ListAPIKeys)
		adminRoute.DELETE("/api-keys/:id", h.RevokeAPIKey)
		adminRoute.GET("/usage-logs", h.ListUsageLogs)
		adminRoute.GET("/audit-logs", h.ListAuditLogs)
		adminRoute.PATCH("/plans/:id", h.UpdatePlan)
		adminRoute.DELETE("/plans/:id", h.DeletePlan)
	}

	dashboardRoute := r.Group("/dashboard")
	dashboardRoute.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowMethods:     []string{"GET", "POST", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           1 * time.Hour,
	}))
	dashboardRoute.OPTIONS("/*path", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	{
		h := dasboard.NewDashboardHandler(db, rdb)

		dashboardRoute.POST("/signup", h.CreateAccount)
		dashboardRoute.POST("/login", h.Login)
		dashboardRoute.GET("/plans", h.GetPlans)

		// Firebase: create/fetch DB user after Firebase sign-in or sign-up.
		dashboardRoute.POST("/sync", auth.FirebaseTokenMiddleware(), h.SyncUser)

		authenticated := dashboardRoute.Group("/")
		authenticated.Use(auth.FirebaseUserMiddleware(db))
		{
			authenticated.POST("/api-keys", h.CreateAPIKey)
			authenticated.GET("/api-keys", h.ListAPIKeys)
			authenticated.DELETE("/api-keys/:id", h.DeleteAPIKey)
			authenticated.POST("/plans", h.CreatePlan)
			authenticated.POST("/plans/activate", h.ActivatePlan)
			authenticated.POST("/plans/downgrade", h.DowngradePlan)
			authenticated.POST("/webhooks", h.CreateWebhook)
			authenticated.GET("/webhooks", h.ListWebhooks)
			authenticated.DELETE("/webhooks/:id", h.DeleteWebhook)
			authenticated.POST("/webhooks/:id/rotate-secret", h.RotateWebhookSecret)
			authenticated.GET("/webhooks/:id/deliveries", h.ListWebhookDeliveries)

			// Usage summary
			authenticated.GET("/usage", h.GetUsage)

			// Paystack payment
			authenticated.POST("/payment/initialize", h.InitializePayment)
			authenticated.GET("/payment/verify/:reference", h.VerifyPayment)
		}

		// Public webhook endpoint — Paystack calls this, no auth needed.
		dashboardRoute.POST("/payment/webhook", h.PaystackWebhook)
	}

	// ── Graceful shutdown ───────────────────────────────────────────────────
	port := getEnv("PORT", "8080")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("face-api listening on :%s (mode: %s)\n", port, getEnv("GIN_MODE", "debug"))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced shutdown: %v", err)
	}
	log.Println("Server exited.")
}

// securityHeaders adds standard security response headers to every request.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// Only send HSTS over HTTPS — skip in non-release mode to avoid breaking local HTTP dev.
		if getEnv("GIN_MODE", "debug") == "release" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
	})
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
