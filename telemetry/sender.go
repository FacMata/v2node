package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const maxTelemetryResponseBytes = 64 * 1024

type SenderConfig struct {
	Endpoint string
	Timeout  time.Duration
}

type Sender struct {
	endpoint string
	client   *http.Client
	signer   *Signer
	now      func() time.Time
}

type SendResult struct {
	Accepted  uint32
	Duplicate bool
}

type SendError struct {
	StatusCode int
	Code       string
	Retryable  bool
	RetryAfter string
}

func (e *SendError) Error() string {
	return fmt.Sprintf("telemetry send failed: status=%d code=%s", e.StatusCode, e.Code)
}

func NewSender(config SenderConfig, signer *Signer) (*Sender, error) {
	if signer == nil {
		return nil, fmt.Errorf("telemetry signer is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse telemetry endpoint: %w", err)
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("telemetry endpoint cannot contain credentials, query, or fragment")
	}
	if endpoint.Scheme != "https" && !isLoopbackHTTP(endpoint) {
		return nil, fmt.Errorf("telemetry endpoint requires HTTPS")
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("telemetry timeout must be positive")
	}
	return &Sender{
		endpoint: endpoint.String(),
		client:   &http.Client{Timeout: config.Timeout},
		signer:   signer,
		now:      time.Now,
	}, nil
}

func (s *Sender) Send(ctx context.Context, body []byte) (SendResult, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SendResult{}, fmt.Errorf("generate telemetry nonce: %w", err)
	}
	headers, err := s.signer.Sign(body, s.now().UTC(), nonce)
	if err != nil {
		return SendResult{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return SendResult{}, fmt.Errorf("create telemetry request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Node-Id", headers.NodeID)
	request.Header.Set("X-Telemetry-Key-Id", headers.KeyID)
	request.Header.Set("X-Telemetry-Timestamp", headers.Timestamp)
	request.Header.Set("X-Telemetry-Nonce", headers.Nonce)
	request.Header.Set("X-Telemetry-Signature", headers.Signature)

	response, err := s.client.Do(request)
	if err != nil {
		return SendResult{}, &SendError{
			Code:      "TELEMETRY_TRANSPORT_ERROR",
			Retryable: true,
		}
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxTelemetryResponseBytes+1))
	if readErr != nil {
		return SendResult{}, fmt.Errorf("read telemetry response: %w", readErr)
	}
	if len(responseBody) > maxTelemetryResponseBytes {
		return SendResult{}, fmt.Errorf("telemetry response exceeds %d bytes", maxTelemetryResponseBytes)
	}

	var payload struct {
		Code string `json:"code"`
		Data *struct {
			Accepted  *uint32 `json:"accepted"`
			Duplicate *bool   `json:"duplicate"`
		} `json:"data"`
	}
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &payload); err != nil {
			return SendResult{}, fmt.Errorf("decode telemetry response: %w", err)
		}
	}

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if payload.Data == nil ||
			payload.Data.Accepted == nil ||
			payload.Data.Duplicate == nil {
			return SendResult{}, fmt.Errorf("telemetry success response is incomplete")
		}
		return SendResult{
			Accepted:  *payload.Data.Accepted,
			Duplicate: *payload.Data.Duplicate,
		}, nil
	}

	code := payload.Code
	if code == "" {
		code = http.StatusText(response.StatusCode)
	}
	return SendResult{}, &SendError{
		StatusCode: response.StatusCode,
		Code:       code,
		Retryable: response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError,
		RetryAfter: response.Header.Get("Retry-After"),
	}
}

func isLoopbackHTTP(endpoint *url.URL) bool {
	if endpoint.Scheme != "http" {
		return false
	}
	host := endpoint.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
