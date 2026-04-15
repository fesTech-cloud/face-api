package dasboard

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/payment"
	"face-api/internal/store"
)

// ── POST /dashboard/payment/initialize ───────────────────────────────────────
// Authenticated. Creates a pending subscription and returns a Paystack
// authorization URL that the frontend should redirect the user to.

func (h *DashboardHandler) InitializePayment(c *gin.Context) {
	var req struct {
		PlanID string `json:"plan_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	planID, err := uuid.Parse(req.PlanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plan_id"})
		return
	}

	user := c.MustGet("user").(*store.User)

	plan, err := h.db.GetPlanByID(c.Request.Context(), planID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "plan not found"})
		return
	}

	// Free plans don't require payment — activate directly.
	if plan.PriceNaira == 0 {
		updated, err := h.db.ActivatePlan(c.Request.Context(), user.ID, planID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate free plan"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"free":    true,
			"message": "Free plan activated",
			"user":    updated,
		})
		return
	}

	secretKey := os.Getenv("PAYSTACK_SECRET_KEY")
	if secretKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "payment not configured"})
		return
	}

	callbackURL := os.Getenv("PAYSTACK_CALLBACK_URL")
	if callbackURL == "" {
		callbackURL = os.Getenv("APP_URL") + "/dashboard/billing/callback"
	}

	client := payment.NewClient(secretKey)

	initResp, err := client.InitializeTransaction(c.Request.Context(), payment.InitializeRequest{
		Email:       user.Email,
		Amount:      plan.PriceNaira * 100, // convert naira → kobo (Paystack smallest unit)
		CallbackURL: callbackURL,
		Metadata: map[string]string{
			"user_id": user.ID.String(),
			"plan_id": planID.String(),
		},
	})
	if err != nil {
		log.Printf("paystack initialize: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to initialize payment"})
		return
	}

	// Persist a pending subscription so we can activate it on webhook/verify.
	if _, err := h.db.CreateSubscription(
		c.Request.Context(),
		user.ID,
		planID,
		initResp.Data.Reference,
		plan.PriceNaira,
	); err != nil {
		log.Printf("create subscription record: %v", err)
		// Non-fatal — we still return the URL; we'll handle via webhook.
	}

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": initResp.Data.AuthorizationURL,
		"reference":         initResp.Data.Reference,
		"access_code":       initResp.Data.AccessCode,
	})
}

// ── GET /dashboard/payment/verify/:reference ──────────────────────────────────
// Authenticated. Called by the frontend after Paystack redirects back.
// Verifies the transaction with Paystack and activates the plan on success.

func (h *DashboardHandler) VerifyPayment(c *gin.Context) {
	reference := c.Param("reference")
	if reference == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reference is required"})
		return
	}

	secretKey := os.Getenv("PAYSTACK_SECRET_KEY")
	if secretKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "payment not configured"})
		return
	}

	client := payment.NewClient(secretKey)

	verifyResp, err := client.VerifyTransaction(c.Request.Context(), reference)
	if err != nil {
		log.Printf("paystack verify: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to verify payment"})
		return
	}

	if verifyResp.Data.Status != "success" {
		_ = h.db.FailSubscription(c.Request.Context(), reference)
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error":  "payment not successful",
			"status": verifyResp.Data.Status,
		})
		return
	}

	customerCode := verifyResp.Data.Customer.CustomerCode
	if err := h.db.ActivateSubscription(c.Request.Context(), reference, customerCode); err != nil {
		log.Printf("activate subscription: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "payment verified but plan activation failed"})
		return
	}

	user := c.MustGet("user").(*store.User)
	updatedUser, _ := h.db.GetUserById(c.Request.Context(), user.ID.String())

	c.JSON(http.StatusOK, gin.H{
		"message": "Payment verified and plan activated",
		"status":  "success",
		"user":    updatedUser,
	})
}

// ── POST /dashboard/payment/webhook ──────────────────────────────────────────
// PUBLIC — no auth middleware. Paystack POSTs signed events here.
// Verifies the X-Paystack-Signature header before processing.

func (h *DashboardHandler) PaystackWebhook(c *gin.Context) {
	secretKey := os.Getenv("PAYSTACK_SECRET_KEY")
	if secretKey == "" {
		c.Status(http.StatusNoContent)
		return
	}

	// Read raw body for signature validation.
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read body"})
		return
	}

	sig := c.GetHeader("X-Paystack-Signature")
	client := payment.NewClient(secretKey)
	if !client.ValidateSignature(body, sig) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	var event payment.WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	switch event.Event {
	case "charge.success":
		var data payment.ChargeSuccessData
		if err := json.Unmarshal(event.Data, &data); err != nil {
			log.Printf("paystack webhook: unmarshal charge.success: %v", err)
			break
		}

		if data.Status == "success" {
			customerCode := data.Customer.CustomerCode
			if err := h.db.ActivateSubscription(c.Request.Context(), data.Reference, customerCode); err != nil {
				log.Printf("paystack webhook: activate subscription %s: %v", data.Reference, err)
			} else {
				log.Printf("paystack webhook: subscription activated for reference %s", data.Reference)
			}
		}

	default:
		// Acknowledge unhandled events — Paystack retries if you return non-2xx.
		log.Printf("paystack webhook: unhandled event %s", event.Event)
	}

	// Always respond 200 quickly.
	c.Status(http.StatusOK)
}
