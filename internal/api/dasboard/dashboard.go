package dasboard

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/store"
	"face-api/x/interfacex"
	"face-api/x/security"
)

// isPrivateIP returns true if the IP is in a private / loopback / link-local range.
// Used to block SSRF via webhook URLs pointing at internal services.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// validateWebhookURL rejects URLs pointing at private/internal IP addresses.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		// If we can't resolve, reject to be safe
		return err
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && isPrivateIP(ip) {
			return net.InvalidAddrError("webhook URL must not point to a private or internal IP address")
		}
	}
	return nil
}

// GetUsage returns the authenticated user's aggregate API usage for the current month.
func (h *DashboardHandler) GetUsage(c *gin.Context) {
	user := c.MustGet("user").(*store.User)

	plan, err := h.db.GetPlanByID(c.Request.Context(), user.PlanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load plan"})
		return
	}

	used, _ := h.cache.GetUserMonthlyUsage(c.Request.Context(), user.ID.String())

	now := time.Now().UTC()
	resetDate := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	c.JSON(http.StatusOK, gin.H{
		"used":       used,
		"limit":      plan.CallLimit,
		"period":     now.Format("2006-01"),
		"reset_date": resetDate.Format("2006-01-02"),
	})
}

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

	// Always register new users on the free plan regardless of the plan_id sent.
	// Paid plan upgrades happen via Paystack after login.
	freePlan, err := h.db.GetFreePlan(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no free plan available; please contact support"})
		return
	}
	req.PlanID = freePlan.ID

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

	// Require a paid plan before issuing any API key.
	plan, err := h.db.GetPlanByID(c.Request.Context(), user.PlanID)
	if err != nil || plan.PriceNaira == 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "a paid subscription is required to create API keys",
		})
		return
	}

	req.UserID = user.ID
	keyRecord, key, err := h.db.CreateAPIKey(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
		return
	}

	h.db.WriteAuditLog(c.Request.Context(), user.ID, user.Email, "api_key.create", keyRecord.ID.String(), c.ClientIP())
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

	// Per-email lockout: block after 10 failures within 15 minutes.
	emailAllowed, _ := h.cache.CheckAccountLockout(c.Request.Context(), req.Email, 10, 15*time.Minute)
	if !emailAllowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked due to too many failed attempts, try again in 15 minutes"})
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

	token, err := client.GenerateToken(user.ID.String(), user.Email, 8*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "login successful", "user": interfacex.UserResponse{
		ID:        user.ID,
		BrandName: user.BrandName,
		Email:     user.Email,
		PlanID:    user.PlanID,
		IsAdmin:   user.IsAdmin,
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
		if errors.Is(err, store.ErrDuplicatePlanName) {
			c.JSON(http.StatusConflict, gin.H{"error": "a plan with that name already exists"})
			return
		}
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

	h.db.WriteAuditLog(c.Request.Context(), user.ID, user.Email, "api_key.delete", keyID.String(), c.ClientIP())
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

	h.db.WriteAuditLog(c.Request.Context(), user.ID, user.Email, "plan.activate", req.PlanID.String(), c.ClientIP())
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

// ── POST /dashboard/plans/downgrade ──────────────────────────────────────────

func (h *DashboardHandler) DowngradePlan(c *gin.Context) {
	user := c.MustGet("user").(*store.User)

	updated, err := h.db.DowngradePlan(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to downgrade plan"})
		return
	}

	h.db.WriteAuditLog(c.Request.Context(), user.ID, user.Email, "plan.downgrade", updated.PlanID.String(), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{
		"message": "plan downgraded to free tier",
		"user": interfacex.UserResponse{
			ID:        updated.ID,
			BrandName: updated.BrandName,
			Email:     updated.Email,
			PlanID:    updated.PlanID,
		},
	})
}

// ── POST /dashboard/webhooks ──────────────────────────────────────────────────

func (h *DashboardHandler) CreateWebhook(c *gin.Context) {
	var req struct {
		URL    string   `json:"url"    binding:"required,url"`
		Events []string `json:"events" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateWebhookURL(req.URL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook URL: must be a publicly reachable HTTPS address"})
		return
	}

	user := c.MustGet("user").(*store.User)

	wh, secret, err := h.db.CreateWebhook(c.Request.Context(), user.ID, req.URL, req.Events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create webhook"})
		return
	}

	h.db.WriteAuditLog(c.Request.Context(), user.ID, user.Email, "webhook.create", wh.ID.String(), c.ClientIP())
	c.JSON(http.StatusCreated, gin.H{
		"webhook": gin.H{
			"id":         wh.ID,
			"url":        wh.URL,
			"events":     req.Events,
			"is_active":  wh.IsActive,
			"created_at": wh.CreatedAt,
		},
		// Secret is shown only once — store it safely
		"secret": secret,
	})
}

// ── GET /dashboard/webhooks ───────────────────────────────────────────────────

func (h *DashboardHandler) ListWebhooks(c *gin.Context) {
	user := c.MustGet("user").(*store.User)

	hooks, err := h.db.ListWebhooks(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list webhooks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"webhooks": hooks, "count": len(hooks)})
}

// ── POST /dashboard/webhooks/:id/rotate-secret ───────────────────────────────

func (h *DashboardHandler) RotateWebhookSecret(c *gin.Context) {
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook id"})
		return
	}

	user := c.MustGet("user").(*store.User)

	newSecret, err := h.db.RotateWebhookSecret(c.Request.Context(), user.ID, webhookID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rotated": true,
		"secret":  newSecret, // shown only once — store it safely
	})
}

// ── GET /dashboard/webhooks/:id/deliveries ───────────────────────────────────

func (h *DashboardHandler) ListWebhookDeliveries(c *gin.Context) {
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook id"})
		return
	}

	user := c.MustGet("user").(*store.User)

	deliveries, err := h.db.ListWebhookDeliveries(c.Request.Context(), user.ID, webhookID, 50)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries, "count": len(deliveries)})
}

// ── DELETE /dashboard/webhooks/:id ───────────────────────────────────────────

func (h *DashboardHandler) DeleteWebhook(c *gin.Context) {
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook id"})
		return
	}

	user := c.MustGet("user").(*store.User)

	if err := h.db.DeleteWebhook(c.Request.Context(), user.ID, webhookID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true, "webhook_id": webhookID})
}
