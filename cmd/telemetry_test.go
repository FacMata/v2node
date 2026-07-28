package cmd

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/telemetry"
)

func TestReadSecretEnvUsesNamedBase64URLVariable(t *testing.T) {
	t.Setenv("V2NODE_TEST_SECRET", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	secret, err := readSecretEnv("V2NODE_TEST_SECRET", 32)
	if err != nil {
		t.Fatalf("readSecretEnv() error = %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret length = %d", len(secret))
	}
}

func TestNewTelemetryManagerFailsOpenForInvalidNodeConfig(t *testing.T) {
	manager, err := newTelemetryManager(&conf.Conf{NodeConfigs: []conf.NodeConfig{{
		NodeID: 7,
		Telemetry: conf.TelemetryConfig{
			Enabled: true,
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

func TestReadSecretEnvDoesNotEchoSecret(t *testing.T) {
	value := strings.Repeat("sensitive!", 8)
	t.Setenv("V2NODE_BAD_SECRET", value)
	_, err := readSecretEnv("V2NODE_BAD_SECRET", 32)
	if err == nil {
		t.Fatal("readSecretEnv() error = nil")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatal("error leaked secret value")
	}
}
