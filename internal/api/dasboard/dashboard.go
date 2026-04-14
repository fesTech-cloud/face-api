package dasboard

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/interfacex"
	"face-api/x/security"
)

type DashboardHandler struct {
	db        *store.Store
	cache     *cache.Cache
	validator *validator.Validate
}

func NewDashboardHandler(db *store.Store, c *cache.Cache) *DashboardHandler {
	return &DashboardHandler{db: db, cache: c, validator: validator.New()}
}

func (h *DashboardHandler) CreateAccount(c *gin.Context) {
	var req interfacex.CreateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.validator.Struct(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = h.db.CreateUser(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account created successfully"})

}

func (h *DashboardHandler) CreateAPIKey(c *gin.Context) {
	var req interfacex.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
		return
	}

	user, ok := userInterface.(*store.User)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user type in context"})
		return
	}

	req.UserID = user.ID
	keyRecord, key, err := h.db.CreateAPIKey(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"record": keyRecord, "key": key})
}

func (h *DashboardHandler) Login(c *gin.Context) {
	// Rate limit: max 10 attempts per IP per minute
	allowed, _ := h.cache.CheckLoginRateLimit(c.Request.Context(), c.ClientIP(), 10, time.Minute)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many login attempts, please try again later"})
		return
	}

	var req interfacex.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.validator.Struct(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !security.ComparePassword(user.PasswordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	client := security.NewPasetoManager()

	token, err := client.GenerateToken(user.ID.String(), user.Email, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "login successful", "user": interfacex.UserResponse{
		ID:        user.ID,
		BrandName: user.BrandName,
		Email:     user.Email,
		PlanID:    user.PlanID,
	}, "token": token})
}

func (h *DashboardHandler) GetPlans(c *gin.Context) {
	plans, err := h.db.GetAllPlans(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve plans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

func (h *DashboardHandler) CreatePlan(c *gin.Context) {
	var req interfacex.CreatePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.validator.Struct(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plan, err := h.db.CreatePlan(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create plan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "plan created successfully", "plan": plan})
}

func (h *DashboardHandler) ListAPIKeys(c *gin.Context) {
	user := c.MustGet("user").(*store.User)

	keys, err := h.db.ListAPIKeys(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_keys": keys, "count": len(keys)})
}

func (h *DashboardHandler) DeleteAPIKey(c *gin.Context) {
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
		return
	}

	user := c.MustGet("user").(*store.User)

	if err := h.db.DeleteAPIKey(c.Request.Context(), user.ID, keyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"revoked": true, "key_id": keyID})
}

func (h *DashboardHandler) ActivatePlan(c *gin.Context) {
	var req interfacex.ActivatePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := c.MustGet("user").(*store.User)

	updated, err := h.db.ActivatePlan(c.Request.Context(), user.ID, req.PlanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "plan activated successfully",
		"user": interfacex.UserResponse{
			ID:        updated.ID,
			BrandName: updated.BrandName,
			Email:     updated.Email,
			PlanID:    updated.PlanID,
		},
	})
}
