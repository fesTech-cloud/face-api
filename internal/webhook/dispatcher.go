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
// It runs each delivery in its own goroutine so the caller is never blocked.
func (d *Dispatcher) Fire(userID uuid.UUID, event string, payload any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
			if err := d.deliver(wh, event, ts, body); err != nil {
				log.Printf("webhook: deliver to %s: %v", wh.URL, err)
			}
		}
	}()
}

// deliver sends a single signed HTTP POST to the webhook URL.
func (d *Dispatcher) deliver(wh store.Webhook, event, ts string, body []byte) error {
	sig := sign(wh.Secret, ts, body)

	req, err := http.NewRequest(http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(eventHeader, event)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(signatureHeader, "sha256="+sig)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx response: %d", resp.StatusCode)
	}
	return nil
}

// sign returns HMAC-SHA256(secret, timestamp + "." + body) as a hex string.
// Recipients can verify: HMAC-SHA256(secret, X-Webhook-Timestamp + "." + raw_body)
func sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
