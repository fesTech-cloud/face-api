package api

import (
	"math"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/engine"
	"face-api/internal/store"
)

// Handler holds all dependencies for the API layer
type Handler struct {
	db     *store.Store
	cache  *cache.Cache
	engine *engine.FaceEngine
}

func NewHandler(db *store.Store, c *cache.Cache, e *engine.FaceEngine) *Handler {
	return &Handler{db: db, cache: c, engine: e}
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

	embA, bboxA, err := h.engine.EmbedBase64(req.ImageA)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "face_a: " + err.Error()})
		return
	}

	embB, bboxB, err := h.engine.EmbedBase64(req.ImageB)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "face_b: " + err.Error()})
		return
	}

	dist := euclidean(embA, embB)
	conf := math.Max(0, 1.0-(dist/1.2))

	c.JSON(http.StatusOK, gin.H{
		"match":      dist < 0.6,
		"distance":   round(dist, 4),
		"confidence": round(conf, 4),
		"face_a":     gin.H{"detected": true, "bbox": bboxA},
		"face_b":     gin.H{"detected": true, "bbox": bboxB},
		"call_id":    "cm_" + uuid.New().String()[:8],
	})
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

	embSelfie, _, err := h.engine.EmbedBase64(req.Selfie)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "selfie: " + err.Error()})
		return
	}

	embID, _, err := h.engine.EmbedBase64(req.IDPhoto)
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

	faces, err := h.engine.DetectBase64(req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"count": len(faces),
		"faces": faces,
	})
}

// ── POST /v1/enroll ───────────────────────────────────────────────────────────

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

	emb, _, err := h.engine.EmbedBase64(req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	// TODO: store embedding in DB under collection

	err = h.db.EnrollFace(c.Request.Context(), uuid.New(), req.PersonID, emb[:], req.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enroll face"})
		return
	}
	_ = emb

	c.JSON(http.StatusOK, gin.H{
		"enrolled":   true,
		"person_id":  req.PersonID,
		"collection": req.Collection,
		"face_id":    uuid.New().String(),
	})
}

// ── POST /v1/search ───────────────────────────────────────────────────────────

func (h *Handler) Search(c *gin.Context) {
	var req struct {
		Collection string  `json:"collection" binding:"required"`
		Image      string  `json:"image"      binding:"required"`
		TopK       int     `json:"top_k"`
		Threshold  float64 `json:"threshold"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.TopK == 0 {
		req.TopK = 5
	}
	if req.Threshold == 0 {
		req.Threshold = 0.6
	}

	_, _, err := h.engine.EmbedBase64(req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	// TODO: pgvector similarity search against collection
	_, err = h.db.SearchFaces(c.Request.Context(), uuid.New(), []float32{}, req.TopK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"collection": req.Collection,
		"results":    []gin.H{},
		"count":      0,
	})
}

// ── GET /v1/collections ───────────────────────────────────────────────────────

func (h *Handler) ListCollections(c *gin.Context) {
	// TODO: fetch from DB by api_key owner
	c.JSON(http.StatusOK, gin.H{
		"collections": []gin.H{},
		"count":       0,
	})
}

// ── DELETE /v1/collections/:id ────────────────────────────────────────────────

func (h *Handler) DeleteCollection(c *gin.Context) {
	id := c.Param("id")
	// TODO: delete collection + embeddings from DB
	c.JSON(http.StatusOK, gin.H{
		"deleted":       true,
		"collection_id": id,
	})
}

// ── GET /v1/usage ─────────────────────────────────────────────────────────────

func (h *Handler) Usage(c *gin.Context) {
	apiKey := c.GetString("api_key")
	used, _ := h.cache.GetMonthlyUsage(c.Request.Context(), apiKey)

	c.JSON(http.StatusOK, gin.H{
		"used":       used,
		"limit":      5000,
		"period":     "2026-03",
		"reset_date": "2026-04-01",
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
