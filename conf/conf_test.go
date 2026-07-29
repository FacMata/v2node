package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTelemetryDefaultsToEnabledForExistingNodeConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"Nodes": [{
			"ApiHost": "https://panel.example.com/",
			"NodeID": 7,
			"ApiKey": "server-api-key"
		}]
	}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	config := New()
	if err := config.LoadFromPath(path); err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}
	node := config.NodeConfigs[0]
	if !node.Telemetry.IsEnabled() {
		t.Fatal("telemetry defaulted to disabled")
	}
	if node.Telemetry.Endpoint != "https://panel.example.com/api/v2/server/telemetry/connection-buckets" {
		t.Fatalf("endpoint = %q", node.Telemetry.Endpoint)
	}
	if node.Telemetry.QueueDirectory != "/var/lib/v2node/telemetry/7" {
		t.Fatalf("queue directory = %q", node.Telemetry.QueueDirectory)
	}
}

func TestTelemetryCanBeExplicitlyDisabled(t *testing.T) {
	disabled := false
	telemetry := TelemetryConfig{Enabled: &disabled}
	if telemetry.IsEnabled() {
		t.Fatal("explicit false telemetry is enabled")
	}
}
