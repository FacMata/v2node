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
		NodeID:           config.NodeID,
		CollectorVersion: config.CollectorVersion,
		StateDirectory:   config.QueueDirectory,
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
	return pipeline, nil
}
