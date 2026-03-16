package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"face-api/internal/api"
	"face-api/internal/auth"
	"face-api/internal/cache"
	"face-api/internal/engine"
	"face-api/internal/store"
)

func main() {
	// Load .env (ignored in production if not present)
	_ = godotenv.Load()

	// ── Database ────────────────────────────────────────────────────────────
	db, err := store.New(mustEnv("DB_URL"))
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer db.Close()

	// ── Redis ────────────────────────────────────────────────────────────────
	rdb, err := cache.New(mustEnv("REDIS_URL"))
	if err != nil {
		log.Fatalf("redis connect: %v", err)
	}
	defer rdb.Close()

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
	r.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders: []string{"X-Request-Id"},
		MaxAge:        12 * time.Hour,
	}))

	// ── Routes ──────────────────────────────────────────────────────────────
	// Public
	r.GET("/health", healthHandler)
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "face-api",
			"version": "1.0.0",
			"docs":    "/docs",
		})
	})

	// Authenticated API routes
	v1 := r.Group("/v1")
	v1.Use(auth.APIKeyMiddleware(db, rdb))
	{
		h := api.NewHandler(db, rdb, faceEngine)

		v1.POST("/match", h.Match)
		v1.POST("/verify", h.Verify)
		v1.POST("/detect", h.Detect)
		v1.POST("/enroll", h.Enroll)
		v1.POST("/search", h.Search)
		v1.GET("/collections", h.ListCollections)
		v1.DELETE("/collections/:id", h.DeleteCollection)
		v1.GET("/usage", h.Usage)
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
