package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/telemetry"
)

func newTelemetryManager(config *conf.Conf) (*telemetry.Manager, error) {
	pipelines := make([]*telemetry.Pipeline, 0)
	activeNodeIDs := make(map[int]struct{})
	var errs []error
	for i := range config.NodeConfigs {
		node := &config.NodeConfigs[i]
		if !node.Telemetry.IsEnabled() {
			continue
		}
		pipeline, err := openTelemetryPipeline(node)
		if err != nil {
			errs = append(errs, fmt.Errorf("node %d: %w", node.NodeID, err))
			continue
		}
		if _, exists := activeNodeIDs[node.NodeID]; exists {
			_ = pipeline.Close()
			errs = append(
				errs,
				fmt.Errorf("node %d: duplicate telemetry node", node.NodeID),
			)
			continue
		}
		activeNodeIDs[node.NodeID] = struct{}{}
		pipelines = append(pipelines, pipeline)
	}
	manager, err := telemetry.NewManager(pipelines...)
	if err != nil {
		for _, opened := range pipelines {
			_ = opened.Close()
		}
		return nil, err
	}
	return manager, errors.Join(errs...)
}

func openTelemetryPipeline(node *conf.NodeConfig) (*telemetry.Pipeline, error) {
	config := node.Telemetry
	if node.NodeID <= 0 || node.Key == "" || config.Endpoint == "" {
		return nil, fmt.Errorf("node ID, server API key, and telemetry endpoint are required")
	}
	requestTimeout := time.Duration(config.RequestTimeoutSeconds) * time.Second
	sender, err := telemetry.NewSender(telemetry.SenderConfig{
		Endpoint: config.Endpoint,
		Timeout:  requestTimeout,
		NodeID:   uint64(node.NodeID),
		APIKey:   node.Key,
	})
	if err != nil {
		return nil, err
	}
	if err := sender.Probe(context.Background()); err != nil {
		return nil, err
	}
	return telemetry.OpenRuntimePipeline(telemetry.RuntimeConfig{
		NodeID:           uint64(node.NodeID),
		APIKey:           node.Key,
		Endpoint:         config.Endpoint,
		QueueDirectory:   config.QueueDirectory,
		QueueMaxBytes:    config.QueueMaxBytes,
		QueueMaxAge:      time.Duration(config.QueueMaxAgeSeconds) * time.Second,
		CollectorVersion: telemetryCollectorVersion(version),
		BufferSize:       config.BufferSize,
		FlushInterval:    time.Duration(config.FlushIntervalSeconds) * time.Second,
		RequestTimeout:   requestTimeout,
		RetryMin:         time.Duration(config.RetryMinSeconds) * time.Second,
		RetryMax:         time.Duration(config.RetryMaxSeconds) * time.Second,
		ShutdownTimeout:  time.Duration(config.ShutdownTimeoutSeconds) * time.Second,
	})
}

func telemetryCollectorVersion(value string) string {
	const maximumLength = 32
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return "unknown"
		}
	}
	if len(value) > maximumLength {
		return value[:maximumLength]
	}
	return value
}
