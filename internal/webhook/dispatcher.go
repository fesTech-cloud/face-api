package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"

	"face-api/internal/store"
)

const (
	deliveryTimeout = 10 * time.Second
	signatureHeader = "X-Webhook-Signature"
	eventHeader     = "X-Webhook-Event"
	timestampHeader = "X-Webhook-Timestamp"
	maxRetries      = 4 // attempts: 0s, 5s, 25s, 125s
)

// Dispatcher fetches registered webhooks and delivers signed event payloads.
type Dispatcher struct {
	store  *store.Store
	client *http.Client
}

func NewDispatcher(s *store.Store) *Dispatcher {
	return &Dispatcher{
		store:  s,
		client: &http.Client{Timeout: deliveryTimeout},
	}
}

// Fire dispatches an event to all matching webhooks for the user.
// Each delivery runs in its own goroutine with exponential-backoff retries.
func (d *Dispatcher) Fire(userID uuid.UUID, event string, payload any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		hooks, err := d.store.GetActiveWebhooksForEvent(ctx, userID, event)
		if err != nil || len(hooks) == 0 {
			return
		}

		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("webhook: marshal payload: %v", err)
			return
		}

		ts := fmt.Sprintf("%d", time.Now().Unix())

		for _, wh := range hooks {
			d.deliverWithRetry(ctx, wh, event, ts, body)
		}
	}()
}

// deliverWithRetry attempts delivery up to maxRetries times using exponential
// backoff (5^attempt seconds: 0s, 5s, 25s, 125s).
func (d *Dispatcher) deliverWithRetry(ctx context.Context, wh store.Webhook, event, ts string, body []byte) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(5, float64(attempt))) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				log.Printf("webhook: context cancelled for %s after %d attempts", wh.URL, attempt)
				return
			}
		}

		statusCode, err := d.deliver(wh, event, ts, body)
		if err == nil {
			d.store.RecordDelivery(wh.ID, event, statusCode, true, attempt+1, "")
			if attempt > 0 {
				log.Printf("webhook: delivered to %s after %d retries", wh.URL, attempt)
			}
			return
		}
		d.store.RecordDelivery(wh.ID, event, statusCode, false, attempt+1, err.Error())
		log.Printf("webhook: attempt %d/%d failed for %s: %v", attempt+1, maxRetries, wh.URL, err)
	}
	log.Printf("webhook: gave up delivering to %s after %d attempts", wh.URL, maxRetries)
}

// deliver sends a single signed HTTP POST to the webhook URL.
// Returns the HTTP status code (0 on network error) and any error.
func (d *Dispatcher) deliver(wh store.Webhook, event, ts string, body []byte) (int, error) {
	sig := sign(wh.Secret, ts, body)

	req, err := http.NewRequest(http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(eventHeader, event)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(signatureHeader, "sha256="+sig)

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("non-2xx response: %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// sign returns HMAC-SHA256(secret, timestamp + "." + body) as a hex string.
// Recipients can verify: HMAC-SHA256(secret, X-Webhook-Timestamp + "." + raw_body)
func sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
