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
	Endpoint        string
	ControlEndpoint string
	Timeout         time.Duration
	NodeID          uint64
	APIKey          string
}

type Sender struct {
	endpoint        string
	controlEndpoint string
	apiKey          string
	client          *http.Client
}

type ControlState struct {
	CollectorEnabled bool
	Mode             string
	ModeEpoch        uint64
	ControlTTL       time.Duration
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

func (s *Sender) HasControlEndpoint() bool {
	return s != nil && s.controlEndpoint != ""
}

func (e *SendError) Error() string {
	return fmt.Sprintf("telemetry send failed: status=%d code=%s", e.StatusCode, e.Code)
}

func NewSender(config SenderConfig) (*Sender, error) {
	if config.NodeID == 0 || config.APIKey == "" {
		return nil, fmt.Errorf("telemetry server API identity is required")
	}
	endpoint, err := authenticatedEndpoint(config.Endpoint, config.NodeID)
	if err != nil {
		return nil, err
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("telemetry timeout must be positive")
	}
	controlEndpoint := ""
	if config.ControlEndpoint != "" {
		parsed, err := authenticatedEndpoint(config.ControlEndpoint, config.NodeID)
		if err != nil {
			return nil, fmt.Errorf("control endpoint: %w", err)
		}
		controlEndpoint = parsed
	}
	return &Sender{
		endpoint:        endpoint,
		controlEndpoint: controlEndpoint,
		apiKey:          config.APIKey,
		client:          &http.Client{Timeout: config.Timeout},
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

func (s *Sender) FetchControl(ctx context.Context, modeEpoch uint64) (ControlState, error) {
	if s.controlEndpoint == "" {
		return ControlState{}, fmt.Errorf("telemetry control endpoint is required")
	}
	body, err := json.Marshal(struct {
		SchemaVersion uint16 `json:"schema_version"`
		ModeEpoch     uint64 `json:"mode_epoch"`
	}{SchemaVersion: 2, ModeEpoch: modeEpoch})
	if err != nil {
		return ControlState{}, fmt.Errorf("encode telemetry control request: %w", err)
	}
	request, err := s.newRequestTo(ctx, s.controlEndpoint, body)
	if err != nil {
		return ControlState{}, fmt.Errorf("create telemetry control request: %w", err)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return ControlState{}, fmt.Errorf("fetch telemetry control: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxTelemetryResponseBytes+1))
	if err != nil {
		return ControlState{}, fmt.Errorf("read telemetry control response: %w", err)
	}
	if len(responseBody) > maxTelemetryResponseBytes {
		return ControlState{}, fmt.Errorf("telemetry control response exceeds %d bytes", maxTelemetryResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ControlState{}, fmt.Errorf("telemetry control unavailable: status=%d", response.StatusCode)
	}
	var payload struct {
		Data *struct {
			CollectorEnabled *bool  `json:"collector_enabled"`
			Mode             string `json:"mode"`
			ModeEpoch        uint64 `json:"mode_epoch"`
			ControlTTL       uint32 `json:"control_ttl_seconds"`
		} `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return ControlState{}, fmt.Errorf("decode telemetry control response: %w", err)
	}
	if payload.Data == nil || payload.Data.CollectorEnabled == nil ||
		payload.Data.ModeEpoch == 0 || payload.Data.ControlTTL == 0 {
		return ControlState{}, fmt.Errorf("telemetry control response is incomplete")
	}
	if payload.Data.Mode != "off" && payload.Data.Mode != "observe" &&
		payload.Data.Mode != "auto_protect" {
		return ControlState{}, fmt.Errorf("telemetry control mode is invalid")
	}
	return ControlState{
		CollectorEnabled: *payload.Data.CollectorEnabled,
		Mode:             payload.Data.Mode,
		ModeEpoch:        payload.Data.ModeEpoch,
		ControlTTL:       time.Duration(payload.Data.ControlTTL) * time.Second,
	}, nil
}

func (s *Sender) newRequest(
	ctx context.Context,
	body []byte,
) (*http.Request, error) {
	return s.newRequestTo(ctx, s.endpoint, body)
}

func (s *Sender) newRequestTo(
	ctx context.Context,
	endpoint string,
	body []byte,
) (*http.Request, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	return request, nil
}

func authenticatedEndpoint(raw string, nodeID uint64) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse telemetry endpoint: %w", err)
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return "", fmt.Errorf("telemetry endpoint cannot contain credentials or fragment")
	}
	if endpoint.Scheme != "https" && !isLoopbackHTTP(endpoint) {
		return "", fmt.Errorf("telemetry endpoint requires HTTPS")
	}
	query := endpoint.Query()
	query.Set("node_type", "v2node")
	query.Set("node_id", strconv.FormatUint(nodeID, 10))
	query.Del("token")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
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
