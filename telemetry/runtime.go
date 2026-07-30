package telemetry

import (
	"crypto/sha256"
	"path/filepath"
	"time"
)

type RuntimeConfig struct {
	NodeID           uint64
	APIKey           string
	Endpoint         string
	QueueDirectory   string
	QueueMaxBytes    int64
	QueueMaxAge      time.Duration
	CollectorVersion string
	BufferSize       int
	FlushInterval    time.Duration
	RequestTimeout   time.Duration
	RetryMin         time.Duration
	RetryMax         time.Duration
	ShutdownTimeout  time.Duration
}

func OpenRuntimePipeline(config RuntimeConfig) (*Pipeline, error) {
	catalog := runtimeCatalog()
	classifier, err := NewClassifier(catalog, time.Now)
	if err != nil {
		return nil, err
	}
	protector := NewSourceProtector()
	state, err := openStreamState(config.QueueDirectory, config.NodeID)
	if err != nil {
		return nil, err
	}
	queueKey := sha256.Sum256(
		[]byte("v2node-telemetry-queue-v1\x00" + config.APIKey),
	)
	queue, err := OpenDiskQueue(QueueConfig{
		Directory:       filepath.Join(config.QueueDirectory, "queue"),
		NodeID:          config.NodeID,
		StreamID:        state.StreamID,
		WriteKeyVersion: 1,
		Keys:            map[uint16][]byte{1: queueKey[:]},
		MaxBytes:        config.QueueMaxBytes,
		MaxAge:          config.QueueMaxAge,
	})
	if err != nil {
		return nil, err
	}
	sender, err := NewSender(SenderConfig{
		Endpoint: config.Endpoint,
		Timeout:  config.RequestTimeout,
		NodeID:   config.NodeID,
		APIKey:   config.APIKey,
	})
	if err != nil {
		_ = queue.Close()
		return nil, err
	}
	pipeline, err := NewPipeline(PipelineConfig{
		NodeID:            config.NodeID,
		CollectorVersion:  config.CollectorVersion,
		ClassifierVersion: catalog.Version,
		StateDirectory:    config.QueueDirectory,
		BufferSize:        config.BufferSize,
		FlushInterval:     config.FlushInterval,
		RetryMin:          config.RetryMin,
		RetryMax:          config.RetryMax,
		ShutdownTimeout:   config.ShutdownTimeout,
	}, NewAggregator(classifier, protector), queue, sender)
	if err != nil {
		_ = queue.Close()
		return nil, err
	}
	return pipeline, nil
}

func runtimeCatalog() Catalog {
	return Catalog{
		Version:    "builtin-v3",
		ValidUntil: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC),
		Rules: []ProbeRule{
			runtimeProbeRule("gstatic_http", "www.gstatic.com", 80, AppProtocolHTTP),
			runtimeProbeRule("gstatic_https", "www.gstatic.com", 443, AppProtocolTLS),
			runtimeProbeRule("cloudflare_one_http", "1.1.1.1", 80, AppProtocolHTTP),
			runtimeProbeRule("cloudflare_one_https", "1.1.1.1", 443, AppProtocolTLS),
			runtimeProbeRule("cloudflare_captive_http", "cp.cloudflare.com", 80, AppProtocolHTTP),
			runtimeProbeRule("cloudflare_captive_https", "cp.cloudflare.com", 443, AppProtocolTLS),
			runtimeProbeRule("android_connectivity_http", "connectivitycheck.gstatic.com", 80, AppProtocolHTTP),
			runtimeProbeRule("android_connectivity_https", "connectivitycheck.gstatic.com", 443, AppProtocolTLS),
		},
	}
}

func runtimeProbeRule(id string, host string, port uint16, protocol AppProtocol) ProbeRule {
	return ProbeRule{
		ID:         id,
		Host:       host,
		Ports:      []uint16{port},
		Protocols:  []AppProtocol{protocol},
		Confidence: ConfidenceLow,
	}
}
