package admin

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/interfacex"
)

type Handler struct {
	db    *store.Store
	cache *cache.Cache
}

func NewHandler(db *store.Store, c *cache.Cache) *Handler {
	return &Handler{db: db, cache: c}
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
