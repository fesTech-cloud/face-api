package engine

import (
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"os"
	"strings"

	goface "github.com/Kagami/go-face"
)

// FaceEngine wraps go-face's Recognizer with helper methods.
type FaceEngine struct {
	rec *goface.Recognizer
}

// BBox represents a face bounding box [x0, y0, x1, y1].
type BBox [4]int

// DetectedFace is returned from Detect.
type DetectedFace struct {
	BBox       BBox         `json:"bbox"`
	Confidence float64      `json:"confidence"`
	Embedding  [128]float32 `json:"-"`
}

// New initialises the face recognizer with models from modelsDir.
func New(modelsDir string) (*FaceEngine, error) {
	rec, err := goface.NewRecognizer(modelsDir)
	if err != nil {
		return nil, fmt.Errorf("init recognizer: %w", err)
	}
	return &FaceEngine{rec: rec}, nil
}

// Close releases the underlying dlib resources.
func (e *FaceEngine) Close() {
	e.rec.Close()
}

// EmbedBase64 decodes a base64 image, detects the first face,
// and returns its 128-dim embedding + bounding box.
func (e *FaceEngine) EmbedBase64(b64 string) ([128]float32, BBox, error) {
	// Strip data URI prefix if present (e.g. "data:image/jpeg;base64,...")
	if idx := strings.Index(b64, ","); idx != -1 {
		b64 = b64[idx+1:]
	}
	imgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Fall back to URL-safe encoding
		imgBytes, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return [128]float32{}, BBox{}, fmt.Errorf("base64 decode: %w", err)
		}
	}
	return e.EmbedBytes(imgBytes)
}

// EmbedBytes detects the first face in raw image bytes and returns its embedding.
func (e *FaceEngine) EmbedBytes(imgBytes []byte) ([128]float32, BBox, error) {
	faces, err := e.rec.Recognize(imgBytes)
	if err != nil {
		return [128]float32{}, BBox{}, fmt.Errorf("recognize: %w", err)
	}
	if len(faces) == 0 {
		return [128]float32{}, BBox{}, fmt.Errorf("no face detected")
	}

	f := faces[0]
	r := f.Rectangle

	// ✅ Reject faces smaller than 80x80 pixels
	width := r.Max.X - r.Min.X
	height := r.Max.Y - r.Min.Y
	if width < 80 || height < 80 {
		return [128]float32{}, BBox{}, fmt.Errorf(
			"face too small (%dx%d) — minimum 80x80px required, use a clearer photo",
			width, height,
		)
	}

	bbox := BBox{r.Min.X, r.Min.Y, r.Max.X, r.Max.Y}
	return f.Descriptor, bbox, nil
}

// DetectBase64 returns all detected faces with bounding boxes and embeddings.
func (e *FaceEngine) DetectBase64(b64 string) ([]DetectedFace, error) {
	// Strip data URI prefix if present (e.g. "data:image/jpeg;base64,...")
	if idx := strings.Index(b64, ","); idx != -1 {
		b64 = b64[idx+1:]
	}
	imgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Fall back to URL-safe encoding
		imgBytes, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	faces, err := e.rec.Recognize(imgBytes)
	if err != nil {
		return nil, fmt.Errorf("recognize: %w", err)
	}

	result := make([]DetectedFace, len(faces))
	for i, f := range faces {
		r := f.Rectangle
		result[i] = DetectedFace{
			BBox:       BBox{r.Min.X, r.Min.Y, r.Max.X, r.Max.Y},
			Confidence: 0.9, // go-face doesn't expose raw confidence; placeholder
			Embedding:  f.Descriptor,
		}
	}
	return result, nil
}

func SaveJPEG(img image.Image, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return jpeg.Encode(f, img, &jpeg.Options{Quality: 90})
}

func SaveBase64ToFile(b64, path string) error {
	// Decode base64
	imgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("decode base64: %w", err)
	}
	// Write raw bytes to file
	return os.WriteFile(path, imgBytes, 0644)
}
