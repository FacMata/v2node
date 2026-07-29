package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const maxTelemetryResponseBytes = 64 * 1024

type SenderConfig struct {
	Endpoint string
	Timeout  time.Duration
	NodeID   uint64
	APIKey   string
}

type Sender struct {
	endpoint string
	client   *http.Client
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

func NewSender(config SenderConfig) (*Sender, error) {
	if config.NodeID == 0 || config.APIKey == "" {
		return nil, fmt.Errorf("telemetry server API identity is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse telemetry endpoint: %w", err)
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return nil, fmt.Errorf("telemetry endpoint cannot contain credentials or fragment")
	}
	if endpoint.Scheme != "https" && !isLoopbackHTTP(endpoint) {
		return nil, fmt.Errorf("telemetry endpoint requires HTTPS")
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("telemetry timeout must be positive")
	}
	query := endpoint.Query()
	query.Set("node_type", "v2node")
	query.Set("node_id", strconv.FormatUint(config.NodeID, 10))
	query.Set("token", config.APIKey)
	endpoint.RawQuery = query.Encode()
	return &Sender{
		endpoint: endpoint.String(),
		client:   &http.Client{Timeout: config.Timeout},
	}, nil
}

func (s *Sender) Send(ctx context.Context, body []byte) (SendResult, error) {
	request, err := s.newRequest(ctx, body)
	if err != nil {
		return SendResult{}, fmt.Errorf("create telemetry request: %w", err)
	}

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
		Retryable: response.StatusCode == http.StatusNotFound ||
			response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError,
		RetryAfter: response.Header.Get("Retry-After"),
	}
}

func (s *Sender) Probe(ctx context.Context) error {
	request, err := s.newRequest(ctx, []byte("{}"))
	if err != nil {
		return fmt.Errorf("create telemetry probe: %w", err)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("send telemetry probe: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxTelemetryResponseBytes+1,
	))
	if err != nil {
		return fmt.Errorf("read telemetry probe response: %w", err)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if len(responseBody) > 0 {
		_ = json.Unmarshal(responseBody, &payload)
	}
	if response.StatusCode == http.StatusBadRequest &&
		payload.Code == "TELEMETRY_INVALID_PAYLOAD" {
		return nil
	}
	return fmt.Errorf(
		"telemetry route unavailable: status=%d code=%s",
		response.StatusCode,
		payload.Code,
	)
}

func (s *Sender) newRequest(
	ctx context.Context,
	body []byte,
) (*http.Request, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return request, nil
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
