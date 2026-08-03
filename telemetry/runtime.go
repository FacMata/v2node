package telemetry

import (
	"crypto/sha256"
	"path/filepath"
	"time"
)

const schemaV2StateDirectory = "schema-v2"

type RuntimeConfig struct {
	NodeID           uint64
	APIKey           string
	Endpoint         string
	ControlEndpoint  string
	InitialControl   *ControlState
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
	protector := NewSourceProtector()
	stateDirectory := filepath.Join(
		config.QueueDirectory,
		schemaV2StateDirectory,
	)
	state, err := openStreamState(stateDirectory, config.NodeID)
	if err != nil {
		return nil, err
	}
	queueKey := sha256.Sum256(
		[]byte("v2node-telemetry-queue-v1\x00" + config.APIKey),
	)
	queue, err := OpenDiskQueue(QueueConfig{
		Directory:       filepath.Join(stateDirectory, "queue"),
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
		Endpoint:        config.Endpoint,
		ControlEndpoint: config.ControlEndpoint,
		Timeout:         config.RequestTimeout,
		NodeID:          config.NodeID,
		APIKey:          config.APIKey,
	})
	if err != nil {
		_ = queue.Close()
		return nil, err
	}
	pipeline, err := NewPipeline(PipelineConfig{
		NodeID:           config.NodeID,
		CollectorVersion: config.CollectorVersion,
		StateDirectory:   stateDirectory,
		BufferSize:       config.BufferSize,
		FlushInterval:    config.FlushInterval,
		RetryMin:         config.RetryMin,
		RetryMax:         config.RetryMax,
		ShutdownTimeout:  config.ShutdownTimeout,
	}, NewEventBuffer(protector), queue, sender)
	if err != nil {
		_ = queue.Close()
		return nil, err
	}
	if config.InitialControl != nil {
		if err := pipeline.ApplyControl(*config.InitialControl); err != nil {
			_ = pipeline.Close()
			return nil, err
		}
	}
	return pipeline, nil
}
