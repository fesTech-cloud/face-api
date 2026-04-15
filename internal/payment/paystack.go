package payment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const paystackBaseURL = "https://api.paystack.co"

// Client is a minimal Paystack HTTP client.
type Client struct {
	secretKey  string
	httpClient *http.Client
}

func NewClient(secretKey string) *Client {
	return &Client{
		secretKey:  secretKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// ── Initialize transaction ────────────────────────────────────────────────────

type InitializeRequest struct {
	Email       string            `json:"email"`
	Amount      int               `json:"amount"` // smallest currency unit (kobo / pesewas / cents)
	CallbackURL string            `json:"callback_url"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type InitializeResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		AuthorizationURL string `json:"authorization_url"`
		AccessCode       string `json:"access_code"`
		Reference        string `json:"reference"`
	} `json:"data"`
}

func (c *Client) InitializeTransaction(ctx context.Context, req InitializeRequest) (*InitializeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		paystackBaseURL+"/transaction/initialize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.secretKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	var result InitializeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !result.Status {
		return nil, fmt.Errorf("paystack: %s", result.Message)
	}
	return &result, nil
}

// ── Verify transaction ────────────────────────────────────────────────────────

type VerifyResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		Status    string `json:"status"` // "success" | "failed" | "pending"
		Reference string `json:"reference"`
		Amount    int    `json:"amount"`
		Customer  struct {
			Email        string `json:"email"`
			CustomerCode string `json:"customer_code"`
		} `json:"customer"`
		Metadata map[string]string `json:"metadata"`
	} `json:"data"`
}

func (c *Client) VerifyTransaction(ctx context.Context, reference string) (*VerifyResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		paystackBaseURL+"/transaction/verify/"+reference, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.secretKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	var result VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !result.Status {
		return nil, fmt.Errorf("paystack: %s", result.Message)
	}
	return &result, nil
}

// ── Webhook ───────────────────────────────────────────────────────────────────

// WebhookEvent is the top-level payload Paystack POSTs to your endpoint.
type WebhookEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// ChargeSuccessData is the Data payload for the "charge.success" event.
type ChargeSuccessData struct {
	Reference string `json:"reference"`
	Amount    int    `json:"amount"`
	Status    string `json:"status"`
	Customer  struct {
		Email        string `json:"email"`
		CustomerCode string `json:"customer_code"`
	} `json:"customer"`
	Metadata map[string]string `json:"metadata"`
}

// ValidateSignature verifies the X-Paystack-Signature header value.
// Paystack signs the raw request body with HMAC-SHA512 using your secret key.
func (c *Client) ValidateSignature(payload []byte, signature string) bool {
	mac := hmac.New(sha512.New, []byte(c.secretKey))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}
