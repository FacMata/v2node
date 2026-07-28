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

func TestSenderPostsSignedExactBodyWithoutSharedToken(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"019fb0c6-ff80-7b22-9202-b7a6c11a6b88"}`)
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/telemetry/connection-buckets" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query = %q, want empty", r.URL.RawQuery)
		}
		if r.Header.Get("X-Node-Id") != "7" ||
			r.Header.Get("X-Telemetry-Key-Id") != "01JTELEMETRYKEY00000000000" {
			t.Errorf("identity headers = %#v", r.Header)
		}
		if r.Header.Get("X-Telemetry-Signature") == "" ||
			r.Header.Get("X-Telemetry-Nonce") == "" {
			t.Errorf("signature headers missing: %#v", r.Header)
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

	signer, err := NewSigner(7, "01JTELEMETRYKEY00000000000", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	sender, err := NewSender(SenderConfig{
		Endpoint: server.URL + "/api/v2/server/telemetry/connection-buckets",
		Timeout:  time.Second,
	}, signer)
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
		{name: "unavailable", status: http.StatusServiceUnavailable, code: "TELEMETRY_INGEST_UNAVAILABLE", retryable: true},
		{name: "bad signature", status: http.StatusUnauthorized, code: "TELEMETRY_SIGNATURE_INVALID", retryable: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": tt.code})
			}))
			defer server.Close()

			signer, _ := NewSigner(7, "key", []byte("0123456789abcdef0123456789abcdef"))
			sender, err := NewSender(SenderConfig{Endpoint: server.URL, Timeout: time.Second}, signer)
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

	signer, _ := NewSigner(7, "key", []byte("0123456789abcdef0123456789abcdef"))
	sender, err := NewSender(SenderConfig{Endpoint: server.URL, Timeout: time.Second}, signer)
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	if _, err := sender.Send(context.Background(), []byte("{}")); err == nil {
		t.Fatal("Send() accepted malformed success response")
	}
}
