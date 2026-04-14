package api

import (
	"math"
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"face-api/internal/cache"
	"face-api/internal/engine"
	"face-api/internal/store"
)

// matchesDir returns an absolute path to logs/matches/ relative to this source file.
func matchesDir() string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "logs", "matches")
	abs, _ := filepath.Abs(root)
	return abs
}

// maxBase64ImageSize is ~10 MB decoded (~13.3 MB base64 encoded).
// This prevents memory exhaustion from oversized payloads.
const maxBase64ImageSize = 14_000_000

// Handler holds all dependencies for the API layer
type Handler struct {
	db     *store.Store
	cache  *cache.Cache
	engine *engine.FaceEngine
}

func NewHandler(db *store.Store, c *cache.Cache, e *engine.FaceEngine) *Handler {
	return &Handler{db: db, cache: c, engine: e}
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

	// callID := "cm_" + uuid.New().String()[:8]

	// outDir := matchesDir()
	// if err := os.MkdirAll(outDir, 0755); err != nil {
	// 	log.Printf("matches dir: %v", err)
	// } else {
	// 	if err := engine.SaveBase64ToFile(req.ImageA, filepath.Join(outDir, callID+"_a.jpg")); err != nil {
	// 		log.Printf("save image_a: %v", err)
	// 	}
	// 	if err := engine.SaveBase64ToFile(req.ImageB, filepath.Join(outDir, callID+"_b.jpg")); err != nil {
	// 		log.Printf("save image_b: %v", err)
	// 	}
	// }

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
		// "call_id":    callID,
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
	if !validateImageSize(req.Selfie) || !validateImageSize(req.IDPhoto) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
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
	if !validateImageSize(req.Image) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	faces, err := h.engine.DetectBase64(req.Image)
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
	if !validateImageSize(req.Image) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "image exceeds maximum allowed size (10 MB)"})
		return
	}

	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil || userID == (uuid.UUID{}) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	emb, _, err := h.engine.EmbedBase64(req.Image)
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
		Collection string  `json:"collection" binding:"required"`
		Image      string  `json:"image"      binding:"required"`
		TopK       int     `json:"top_k"`
		Threshold  float64 `json:"threshold"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	emb, _, err := h.engine.EmbedBase64(req.Image)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	col, err := h.db.GetOrCreateCollection(c.Request.Context(), userID, req.Collection)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve collection"})
		return
	}

	results, err := h.db.SearchFaces(c.Request.Context(), col.ID, emb[:], req.TopK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"collection": req.Collection,
		"threshold":  req.Threshold,
		"results":    results,
		"count":      len(results),
	})
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
