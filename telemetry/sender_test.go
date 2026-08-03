package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSenderPostsExactBodyWithServerAPIAuthentication(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"019fb0c6-ff80-7b22-9202-b7a6c11a6b88"}`)
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/telemetry/connection-buckets" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("node_type") != "v2node" ||
			r.URL.Query().Get("node_id") != "7" ||
			r.URL.Query().Get("token") != "" {
			t.Errorf("server API query = %q", r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "Bearer server-api-key" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Telemetry-Signature") != "" ||
			r.Header.Get("X-Telemetry-Nonce") != "" {
			t.Errorf("legacy telemetry signature headers present: %#v", r.Header)
		}
		var err error
		received, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"accepted":1,"duplicate":false}}`)
	}))
	defer server.Close()

	sender, err := NewSender(SenderConfig{
		Endpoint: server.URL + "/api/v2/server/telemetry/connection-buckets",
		Timeout:  time.Second,
		NodeID:   7,
		APIKey:   "server-api-key",
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}

	result, err := sender.Send(context.Background(), body)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if result.Accepted != 1 || result.Duplicate {
		t.Fatalf("Send() result = %#v", result)
	}
	if string(received) != string(body) {
		t.Fatalf("received body = %q", received)
	}
}

func TestSenderClassifiesRetryableAndPermanentResponses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		code      string
		retryable bool
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, code: "TELEMETRY_RATE_LIMITED", retryable: true},
		{name: "route not ready", status: http.StatusNotFound, code: "Not Found", retryable: true},
		{name: "unavailable", status: http.StatusServiceUnavailable, code: "TELEMETRY_INGEST_UNAVAILABLE", retryable: true},
		{name: "bad server API key", status: http.StatusUnauthorized, code: "TELEMETRY_AUTH_INVALID", retryable: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": tt.code})
			}))
			defer server.Close()

			sender, err := NewSender(SenderConfig{
				Endpoint: server.URL,
				Timeout:  time.Second,
				NodeID:   7,
				APIKey:   "server-api-key",
			})
			if err != nil {
				t.Fatalf("NewSender() error = %v", err)
			}
			_, err = sender.Send(context.Background(), []byte("{}"))
			if err == nil {
				t.Fatal("Send() error = nil")
			}
			sendErr, ok := err.(*SendError)
			if !ok {
				t.Fatalf("Send() error type = %T: %v", err, err)
			}
			if sendErr.Retryable != tt.retryable || !strings.Contains(sendErr.Code, tt.code) {
				t.Fatalf("SendError = %#v", sendErr)
			}
		})
	}
}

func TestSenderRejectsMalformedSuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html>not telemetry json</html>")
	}))
	defer server.Close()

	sender, err := NewSender(SenderConfig{
		Endpoint: server.URL,
		Timeout:  time.Second,
		NodeID:   7,
		APIKey:   "server-api-key",
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	if _, err := sender.Send(context.Background(), []byte("{}")); err == nil {
		t.Fatal("Send() accepted malformed success response")
	}
}

func TestSenderProbeRequiresAuthenticatedTelemetryRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" ||
			r.Header.Get("Authorization") != "Bearer server-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"TELEMETRY_INVALID_PAYLOAD"}`)
	}))
	defer server.Close()

	sender, err := NewSender(SenderConfig{
		Endpoint: server.URL,
		Timeout:  time.Second,
		NodeID:   7,
		APIKey:   "server-api-key",
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	if err := sender.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
}

func TestSenderFetchesAuthenticatedCollectorControl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/telemetry/control" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("token") != "" ||
			r.Header.Get("Authorization") != "Bearer server-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
		}
		if string(body) != `{"schema_version":2,"mode_epoch":3}` {
			t.Errorf("control body = %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"collector_enabled":true,"mode":"observe","mode_epoch":4,"control_ttl_seconds":900}}`)
	}))
	defer server.Close()

	sender, err := NewSender(SenderConfig{
		Endpoint:        server.URL + "/api/v2/server/telemetry/connection-events",
		ControlEndpoint: server.URL + "/api/v2/server/telemetry/control",
		Timeout:         time.Second,
		NodeID:          7,
		APIKey:          "server-api-key",
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	control, err := sender.FetchControl(context.Background(), 3)
	if err != nil {
		t.Fatalf("FetchControl() error = %v", err)
	}
	if !control.CollectorEnabled || control.Mode != "observe" ||
		control.ModeEpoch != 4 || control.ControlTTL != 15*time.Minute {
		t.Fatalf("control = %#v", control)
	}
}
