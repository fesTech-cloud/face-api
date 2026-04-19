package api

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/engine"
	"face-api/internal/store"
	"face-api/internal/webhook"
	"face-api/x/security"
)

// engineTimeout is the maximum time allowed for a single face embedding call.
const engineTimeout = 30 * time.Second

// embedWithTimeout wraps engine.EmbedBase64 in a context deadline.
func (h *Handler) embedWithTimeout(parent context.Context, b64 string) ([128]float32, engine.BBox, error) {
	ctx, cancel := context.WithTimeout(parent, engineTimeout)
	defer cancel()

	type result struct {
		emb  [128]float32
		bbox engine.BBox
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		emb, bbox, err := h.engine.EmbedBase64(b64)
		ch <- result{emb, bbox, err}
	}()
	select {
	case r := <-ch:
		return r.emb, r.bbox, r.err
	case <-ctx.Done():
		return [128]float32{}, engine.BBox{}, context.DeadlineExceeded
	}
}

// detectWithTimeout wraps engine.DetectBase64 in a context deadline.
func (h *Handler) detectWithTimeout(parent context.Context, b64 string) ([]engine.DetectedFace, error) {
	ctx, cancel := context.WithTimeout(parent, engineTimeout)
	defer cancel()

	type result struct {
		faces []engine.DetectedFace
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		faces, err := h.engine.DetectBase64(b64)
		ch <- result{faces, err}
	}()
	select {
	case r := <-ch:
		return r.faces, r.err
	case <-ctx.Done():
		return nil, context.DeadlineExceeded
	}
}

// maxBase64ImageSize is ~10 MB decoded (~13.3 MB base64 encoded).
// This prevents memory exhaustion from oversized payloads.
const maxBase64ImageSize = 14_000_000

// Handler holds all dependencies for the API layer
type Handler struct {
	db         *store.Store
	cache      *cache.Cache
	engine     *engine.FaceEngine
	dispatcher *webhook.Dispatcher
}

func NewHandler(db *store.Store, c *cache.Cache, e *engine.FaceEngine) *Handler {
	return &Handler{db: db, cache: c, engine: e, dispatcher: webhook.NewDispatcher(db)}
}

// validateImageSize rejects base64 strings that exceed maxBase64ImageSize.
func validateImageSize(b64 string) bool {
	return len(b64) <= maxBase64ImageSize
}

// ── POST /v1/match ────────────────────────────────────────────────────────────

type MatchRequest struct {
	ImageA string `json:"image_a" binding:"required"` // base64 encoded
	ImageB string `json:"image_b" binding:"required"`
}

func (h *Handler) Match(c *gin.Context) {
	var req MatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validateImageSize(req.ImageA) || !validateImageSize(req.ImageB) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	embA, bboxA, err := h.embedWithTimeout(c.Request.Context(), req.ImageA)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "face_a: " + err.Error()})
		return
	}

	embB, bboxB, err := h.embedWithTimeout(c.Request.Context(), req.ImageB)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "face_b: " + err.Error()})
		return
	}

	dist := euclidean(embA, embB)
	conf := math.Max(0, 1.0-(dist/1.2))

	result := gin.H{
		"match":      dist < 0.6,
		"distance":   round(dist, 4),
		"confidence": round(conf, 4),
		"face_a":     gin.H{"detected": true, "bbox": bboxA},
		"face_b":     gin.H{"detected": true, "bbox": bboxB},
	}

	// Fire webhook event if the caller is authenticated
	// if userID, err := uuid.Parse(c.GetString("user_id")); err == nil && userID != (uuid.UUID{}) {
	// 	h.dispatcher.Fire(userID, "match", result)
	// }

	c.JSON(http.StatusOK, result)
}

// ── POST /v1/verify ───────────────────────────────────────────────────────────
// Same logic as match but semantically for KYC (selfie vs ID photo)

func (h *Handler) Verify(c *gin.Context) {
	var req struct {
		Selfie  string `json:"selfie"   binding:"required"`
		IDPhoto string `json:"id_photo" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validateImageSize(req.Selfie) || !validateImageSize(req.IDPhoto) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	embSelfie, _, err := h.embedWithTimeout(c.Request.Context(), req.Selfie)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "selfie: " + err.Error()})
		return
	}

	embID, _, err := h.embedWithTimeout(c.Request.Context(), req.IDPhoto)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "id_photo: " + err.Error()})
		return
	}

	dist := euclidean(embSelfie, embID)
	conf := math.Max(0, 1.0-(dist/1.2))

	c.JSON(http.StatusOK, gin.H{
		"match":      dist < 0.6,
		"distance":   round(dist, 4),
		"confidence": round(conf, 4),
		"call_id":    "cm_" + uuid.New().String()[:8],
	})
}

// ── POST /v1/detect ───────────────────────────────────────────────────────────

func (h *Handler) Detect(c *gin.Context) {
	var req struct {
		Image string `json:"image" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validateImageSize(req.Image) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	faces, err := h.detectWithTimeout(c.Request.Context(), req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, _ := uuid.Parse(c.GetString("user_id"))

	// Build response with collection matches for each face
	type FaceResponse struct {
		BBox       engine.BBox              `json:"bbox"`
		Confidence float64                  `json:"confidence"`
		Matches    []store.FaceSearchResult `json:"matches,omitempty"`
	}

	response := make([]FaceResponse, len(faces))
	for i, face := range faces {
		response[i] = FaceResponse{
			BBox:       face.BBox,
			Confidence: face.Confidence,
		}

		// Search for matches across all user's collections
		if userID != (uuid.UUID{}) {
			matches, err := h.db.SearchFacesAcrossCollections(
				c.Request.Context(),
				userID,
				face.Embedding[:],
				5, // top 5 matches per face
			)
			if err == nil && len(matches) > 0 {
				response[i].Matches = matches
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"count": len(faces),
		"faces": response,
	})
}

// ── POST /v1/enroll ───────────────────────────────────────────────────────────

// ── POST /face/session-token ──────────────────────────────────────────────────
// Called by the customer's backend server (secret key only) to issue a
// short-lived widget token the browser can use instead of the secret key.

func (h *Handler) CreateSessionToken(c *gin.Context) {
	if c.GetString("key_scope") != "secret" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only secret keys can issue session tokens"})
		return
	}

	userID    := c.GetString("user_id")
	callLimit := c.GetInt("call_limit")

	const maxDuration = 5 * time.Minute
	var body struct {
		DurationSeconds int `json:"duration_seconds"`
	}
	_ = c.ShouldBindJSON(&body)
	duration := time.Duration(body.DurationSeconds) * time.Second
	if duration <= 0 || duration > maxDuration {
		duration = maxDuration
	}

	token, err := security.NewPasetoManager().GenerateWidgetToken(userID, callLimit, duration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate session token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": time.Now().Add(duration).UTC(),
		"expires_in": int(duration.Seconds()),
	})
}

func (h *Handler) Enroll(c *gin.Context) {
	var req struct {
		Collection string `json:"collection" binding:"required"`
		PersonID   string `json:"person_id"  binding:"required"`
		Metadata   string `json:"metadata"`
		Image      string `json:"image"      binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Collection) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "collection name must be 128 characters or fewer"})
		return
	}
	if len(req.PersonID) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "person_id must be 255 characters or fewer"})
		return
	}
	if len(req.Metadata) > 1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "metadata must be 1024 characters or fewer"})
		return
	}
	if !validateImageSize(req.Image) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil || userID == (uuid.UUID{}) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	emb, _, err := h.embedWithTimeout(c.Request.Context(), req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	col, err := h.db.GetOrCreateCollection(c.Request.Context(), userID, req.Collection)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve collection"})
		return
	}

	err = h.db.EnrollFace(c.Request.Context(), col.ID, req.PersonID, emb[:], req.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enroll face"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrolled":   true,
		"person_id":  req.PersonID,
		"collection": req.Collection,
		"face_id":    uuid.New().String(),
	})
}

// ── POST /v1/search ───────────────────────────────────────────────────────────

const maxTopK = 100

func (h *Handler) Search(c *gin.Context) {
	var req struct {
		Collection string  `json:"collection"` // optional — omit to search across all collections
		Image      string  `json:"image"      binding:"required"`
		TopK       int     `json:"top_k"`
		Threshold  float64 `json:"threshold"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Collection) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "collection name must be 128 characters or fewer"})
		return
	}
	if !validateImageSize(req.Image) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	if req.TopK <= 0 {
		req.TopK = 5
	} else if req.TopK > maxTopK {
		req.TopK = maxTopK
	}
	if req.Threshold == 0 {
		req.Threshold = 0.6
	}

	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil || userID == (uuid.UUID{}) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	emb, _, err := h.embedWithTimeout(c.Request.Context(), req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	var results []store.FaceSearchResult
	if req.Collection == "" {
		// No collection specified — search across all user's collections
		results, err = h.db.SearchFacesAcrossCollections(c.Request.Context(), userID, emb[:], req.TopK)
	} else {
		col, colErr := h.db.GetOrCreateCollection(c.Request.Context(), userID, req.Collection)
		if colErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve collection"})
			return
		}
		results, err = h.db.SearchFaces(c.Request.Context(), col.ID, emb[:], req.TopK)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed", "detail": err.Error()})
		return
	}

	searchResult := gin.H{
		"collection": req.Collection,
		"threshold":  req.Threshold,
		"results":    results,
		"count":      len(results),
	}

	h.dispatcher.Fire(userID, "search", searchResult)

	c.JSON(http.StatusOK, searchResult)
}

// ── GET /v1/collections ───────────────────────────────────────────────────────

func (h *Handler) ListCollections(c *gin.Context) {
	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil || userID == (uuid.UUID{}) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	collections, err := h.db.GetUserCollections(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list collections"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"collections": collections,
		"count":       len(collections),
	})
}

// ── DELETE /v1/collections/:id ────────────────────────────────────────────────

func (h *Handler) DeleteCollection(c *gin.Context) {
	if c.GetString("key_scope") != "secret" {
		c.JSON(http.StatusForbidden, gin.H{"error": "deleting collections requires a secret key"})
		return
	}

	collectionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid collection id"})
		return
	}

	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil || userID == (uuid.UUID{}) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	if err := h.db.DeleteCollection(c.Request.Context(), userID, collectionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete collection"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted":       true,
		"collection_id": collectionID,
	})
}

// ── GET /v1/usage ─────────────────────────────────────────────────────────────

func (h *Handler) Usage(c *gin.Context) {
	apiKey := c.GetString("api_key")
	callLimit := c.GetInt("call_limit")

	used, err := h.cache.GetMonthlyUsage(c.Request.Context(), apiKey)
	if err != nil {
		used = 0
	}

	now := time.Now().UTC()
	// First day of next month
	resetDate := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	c.JSON(http.StatusOK, gin.H{
		"used":       used,
		"limit":      callLimit,
		"period":     now.Format("2006-01"),
		"reset_date": resetDate.Format("2006-01-02"),
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func euclidean(a, b [128]float32) float64 {
	var sum float64
	for i := range a {
		d := float64(a[i] - b[i])
		sum += d * d
	}
	return math.Sqrt(sum)
}

func round(v float64, decimals int) float64 {
	p := math.Pow(10, float64(decimals))
	return math.Round(v*p) / p
}
