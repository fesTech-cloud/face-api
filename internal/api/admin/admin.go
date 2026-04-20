package admin

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/interfacex"
	"face-api/x/security"
)

type Handler struct {
	db    *store.Store
	cache *cache.Cache
}

func NewHandler(db *store.Store, c *cache.Cache) *Handler {
	return &Handler{db: db, cache: c}
}

// ── POST /admin/login ─────────────────────────────────────────────────────────

func (h *Handler) Login(c *gin.Context) {
	// Rate limit: max 10 attempts per IP per minute
	allowed, _ := h.cache.CheckLoginRateLimit(c.Request.Context(), c.ClientIP(), 10, time.Minute)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many login attempts, please try again later"})
		return
	}

	var req struct {
		Email    string `json:"email"    binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
		return
	}

	if !security.ComparePassword(user.PasswordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := security.NewPasetoManager().GenerateToken(user.ID.String(), user.Email, 8*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": interfacex.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			BrandName: user.BrandName,
			PlanID:    user.PlanID,
			IsAdmin:   user.IsAdmin,
		},
	})
}

// ── GET /admin/stats ──────────────────────────────────────────────────────────

func (h *Handler) GetStats(c *gin.Context) {
	stats, err := h.db.AdminGetStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch stats"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// ── GET /admin/users ──────────────────────────────────────────────────────────
// Query params: search, page, page_size

func (h *Handler) ListUsers(c *gin.Context) {
	search := c.Query("search")
	page := queryInt(c, "page", 1)
	pageSize := queryInt(c, "page_size", 20)

	users, total, err := h.db.AdminListUsers(c.Request.Context(), search, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      users,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ── GET /admin/users/:id ──────────────────────────────────────────────────────

func (h *Handler) GetUser(c *gin.Context) {
	id := c.Param("id")
	user, err := h.db.AdminGetUser(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// ── GET /admin/users/:id/stats ────────────────────────────────────────────────

func (h *Handler) GetUserStats(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	stats, err := h.db.AdminGetUserStats(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user stats"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ── PATCH /admin/users/:id/plan ───────────────────────────────────────────────

func (h *Handler) AssignPlan(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var body struct {
		PlanID uuid.UUID `json:"plan_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.db.AdminAssignPlan(c.Request.Context(), userID, body.PlanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	caller := c.MustGet("user").(*store.User)
	h.db.WriteAuditLog(c.Request.Context(), caller.ID, caller.Email, "admin.plan.assign", userID.String(), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "plan assigned", "user": user})
}

// ── DELETE /admin/users/:id ───────────────────────────────────────────────────

func (h *Handler) DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	// Prevent self-deletion
	caller := c.MustGet("user").(*store.User)
	if caller.ID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete your own account"})
		return
	}

	if err := h.db.AdminDeleteUser(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.db.WriteAuditLog(c.Request.Context(), caller.ID, caller.Email, "admin.user.delete", userID.String(), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"deleted": true, "user_id": userID})
}

// ── GET /admin/api-keys ───────────────────────────────────────────────────────
// Query params: user_id, page, page_size

func (h *Handler) ListAPIKeys(c *gin.Context) {
	userIDFilter := c.Query("user_id")
	page := queryInt(c, "page", 1)
	pageSize := queryInt(c, "page_size", 20)

	keys, total, err := h.db.AdminListAPIKeys(c.Request.Context(), userIDFilter, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list api keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      keys,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ── DELETE /admin/api-keys/:id ────────────────────────────────────────────────

func (h *Handler) RevokeAPIKey(c *gin.Context) {
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
		return
	}

	if err := h.db.AdminRevokeAPIKey(c.Request.Context(), keyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	caller := c.MustGet("user").(*store.User)
	h.db.WriteAuditLog(c.Request.Context(), caller.ID, caller.Email, "admin.api_key.revoke", keyID.String(), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"revoked": true, "key_id": keyID})
}

// ── GET /admin/usage-logs ─────────────────────────────────────────────────────
// Query params: user_id, endpoint, page, page_size

func (h *Handler) ListUsageLogs(c *gin.Context) {
	userIDFilter := c.Query("user_id")
	endpoint := c.Query("endpoint")
	page := queryInt(c, "page", 1)
	pageSize := queryInt(c, "page_size", 25)

	logs, total, err := h.db.AdminListUsageLogs(c.Request.Context(), userIDFilter, endpoint, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list usage logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ── GET /admin/audit-logs ─────────────────────────────────────────────────────

func (h *Handler) ListAuditLogs(c *gin.Context) {
	page := queryInt(c, "page", 1)
	pageSize := queryInt(c, "page_size", 25)

	logs, total, err := h.db.AdminListAuditLogs(c.Request.Context(), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list audit logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ── POST /admin/plans ───────────────────────────────────────────────────────

func (h *Handler) CreatePlan(c *gin.Context) {
	var body interfacex.CreatePlanRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plan, err := h.db.CreatePlan(c.Request.Context(), body)
	if err != nil {
		if errors.Is(err, store.ErrDuplicatePlanName) {
			c.JSON(http.StatusConflict, gin.H{"error": "a plan with that name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create plan"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "plan created successfully", "plan": plan})
}

// ── PATCH /admin/plans/:id ────────────────────────────────────────────────────

func (h *Handler) UpdatePlan(c *gin.Context) {
	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plan id"})
		return
	}

	var body interfacex.UpdatePlanRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plan, err := h.db.UpdatePlan(c.Request.Context(), planID, body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "plan updated", "plan": plan})
}

// ── DELETE /admin/plans/:id ───────────────────────────────────────────────────

func (h *Handler) DeletePlan(c *gin.Context) {
	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plan id"})
		return
	}

	if err := h.db.DeletePlan(c.Request.Context(), planID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true, "plan_id": planID})
}

// ── POST /bootstrap/admin ─────────────────────────────────────────────────────
// Temporary endpoint to seed the first admin account.
// Protected by BOOTSTRAP_SECRET env var — remove from routes once done.

func (h *Handler) BootstrapAdmin(c *gin.Context) {
	secret := os.Getenv("BOOTSTRAP_SECRET")
	if secret == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "bootstrap is disabled (BOOTSTRAP_SECRET not set)"})
		return
	}

	if c.GetHeader("X-Bootstrap-Secret") != secret {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid bootstrap secret"})
		return
	}

	var req struct {
		Email     string `json:"email"      binding:"required"`
		Password  string `json:"password"   binding:"required"`
		BrandName string `json:"brand_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.db.CreateAdminUser(c.Request.Context(), req.Email, req.Password, req.BrandName)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "admin created — remove this endpoint when done",
		"id":      user.ID,
		"email":   user.Email,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func queryInt(c *gin.Context, key string, fallback int) int {
	v := c.Query(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return fallback
	}
	return n
}
