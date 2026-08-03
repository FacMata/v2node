package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig   LogConfig    `mapstructure:"Log"`
	NodeConfigs []NodeConfig `mapstructure:"Nodes"`
	PprofPort   int          `mapstructure:"PprofPort"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type NodeConfig struct {
	APIHost    string          `mapstructure:"ApiHost"`
	NodeID     int             `mapstructure:"NodeID"`
	Key        string          `mapstructure:"ApiKey"`
	Timeout    int             `mapstructure:"Timeout"`
	RetryCount *int            `mapstructure:"RetryCount"`
	Telemetry  TelemetryConfig `mapstructure:"Telemetry"`
}

type TelemetryConfig struct {
	Enabled                *bool  `mapstructure:"Enabled"`
	Endpoint               string `mapstructure:"Endpoint"`
	ControlEndpoint        string `mapstructure:"ControlEndpoint"`
	QueueDirectory         string `mapstructure:"QueueDirectory"`
	QueueMaxBytes          int64  `mapstructure:"QueueMaxBytes"`
	QueueMaxAgeSeconds     int    `mapstructure:"QueueMaxAgeSeconds"`
	BufferSize             int    `mapstructure:"BufferSize"`
	FlushIntervalSeconds   int    `mapstructure:"FlushIntervalSeconds"`
	RequestTimeoutSeconds  int    `mapstructure:"RequestTimeoutSeconds"`
	RetryMinSeconds        int    `mapstructure:"RetryMinSeconds"`
	RetryMaxSeconds        int    `mapstructure:"RetryMaxSeconds"`
	ShutdownTimeoutSeconds int    `mapstructure:"ShutdownTimeoutSeconds"`
}

func (c TelemetryConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
		applyTelemetryDefaults(&p.NodeConfigs[i])
	}
	return nil
}

func applyTelemetryDefaults(node *NodeConfig) {
	telemetry := &node.Telemetry
	if !telemetry.IsEnabled() {
		return
	}
	if telemetry.Endpoint == "" {
		telemetry.Endpoint = strings.TrimRight(node.APIHost, "/") +
			"/api/v2/server/telemetry/connection-events"
	}
	if telemetry.ControlEndpoint == "" {
		telemetry.ControlEndpoint = strings.TrimRight(node.APIHost, "/") +
			"/api/v2/server/telemetry/control"
	}
	if telemetry.QueueDirectory == "" {
		telemetry.QueueDirectory = filepath.Join(
			"/var/lib/v2node/telemetry",
			fmt.Sprintf("%d", node.NodeID),
		)
	}
	if telemetry.QueueMaxBytes == 0 {
		telemetry.QueueMaxBytes = 256 * 1024 * 1024
	}
	if telemetry.QueueMaxAgeSeconds == 0 {
		telemetry.QueueMaxAgeSeconds = 6 * 60 * 60
	}
	if telemetry.BufferSize == 0 {
		telemetry.BufferSize = 4096
	}
	if telemetry.FlushIntervalSeconds == 0 {
		telemetry.FlushIntervalSeconds = 5
	}
	if telemetry.RequestTimeoutSeconds == 0 {
		telemetry.RequestTimeoutSeconds = 10
	}
	if telemetry.RetryMinSeconds == 0 {
		telemetry.RetryMinSeconds = 1
	}
	if telemetry.RetryMaxSeconds == 0 {
		telemetry.RetryMaxSeconds = 60
	}
	if telemetry.ShutdownTimeoutSeconds == 0 {
		telemetry.ShutdownTimeoutSeconds = 5
	}
}

func intPtr(v int) *int {
	return &v
}
