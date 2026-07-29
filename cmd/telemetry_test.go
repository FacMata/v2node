package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/telemetry"
)

func TestNewTelemetryManagerFailsOpenForInvalidNodeConfig(t *testing.T) {
	manager, err := newTelemetryManager(&conf.Conf{NodeConfigs: []conf.NodeConfig{{
		NodeID: 7,
		Telemetry: conf.TelemetryConfig{
			Endpoint: "https://panel.example.com/api/v2/server/telemetry/connection-buckets",
		},
	}}})
	if err == nil {
		t.Fatal("newTelemetryManager() error = nil")
	}
	if manager == nil {
		t.Fatal("newTelemetryManager() manager = nil")
	}
	if manager.Observe(telemetry.Observation{NodeID: 7}) {
		t.Fatal("invalid telemetry pipeline accepted observation")
	}
}

func TestOpenTelemetryPipelineSkipsUnavailableRoute(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	node := testTelemetryNode(t, server.URL, 7)
	pipeline, err := openTelemetryPipeline(&node)
	if err == nil {
		_ = pipeline.Close()
		t.Fatal("openTelemetryPipeline() error = nil")
	}
}

func TestTelemetryCollectorVersionFitsWireContract(t *testing.T) {
	fullSHA := "696168df492fc0b14c1507956757c8c3d8621376"
	if got := telemetryCollectorVersion(fullSHA); got != fullSHA[:32] {
		t.Fatalf("telemetryCollectorVersion() = %q, want %q", got, fullSHA[:32])
	}
	if got := telemetryCollectorVersion(" v3.1.9 "); got != "v3.1.9" {
		t.Fatalf("telemetryCollectorVersion() = %q, want v3.1.9", got)
	}
	if got := telemetryCollectorVersion("bad version"); got != "unknown" {
		t.Fatalf("telemetryCollectorVersion() = %q, want unknown", got)
	}
}

func TestNewTelemetryManagerKeepsFirstAvailableDuplicateNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"TELEMETRY_INVALID_PAYLOAD"}`))
	}))
	defer server.Close()

	first := testTelemetryNode(t, server.URL, 7)
	second := testTelemetryNode(t, server.URL, 7)
	second.Telemetry.QueueDirectory = t.TempDir()
	manager, err := newTelemetryManager(&conf.Conf{
		NodeConfigs: []conf.NodeConfig{first, second},
	})
	if err == nil {
		t.Fatal("newTelemetryManager() error = nil")
	}
	if manager == nil {
		t.Fatal("newTelemetryManager() manager = nil")
	}
	if !manager.Observe(telemetry.Observation{NodeID: 7}) {
		t.Fatal("available telemetry pipeline rejected observation")
	}
	if closeErr := manager.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
}

func testTelemetryNode(
	t *testing.T,
	endpoint string,
	nodeID int,
) conf.NodeConfig {
	t.Helper()
	return conf.NodeConfig{
		NodeID: nodeID,
		Key:    "server-api-key",
		Telemetry: conf.TelemetryConfig{
			Endpoint:               endpoint,
			QueueDirectory:         t.TempDir(),
			QueueMaxBytes:          1024 * 1024,
			QueueMaxAgeSeconds:     60,
			BufferSize:             16,
			FlushIntervalSeconds:   1,
			RequestTimeoutSeconds:  int(time.Second / time.Second),
			RetryMinSeconds:        1,
			RetryMaxSeconds:        2,
			ShutdownTimeoutSeconds: 1,
		},
	}
}
