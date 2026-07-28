package telemetry

import (
	"path/filepath"
	"time"
)

type RuntimeConfig struct {
	NodeID                  uint64
	Endpoint                string
	KeyID                   string
	Secret                  []byte
	SourceSealingPublicKey  []byte
	SourceSealingKeyVersion uint16
	QueueDirectory          string
	QueueKey                []byte
	QueueKeyVersion         uint16
	QueueMaxBytes           int64
	QueueMaxAge             time.Duration
	CollectorVersion        string
	BufferSize              int
	FlushInterval           time.Duration
	RequestTimeout          time.Duration
	RetryMin                time.Duration
	RetryMax                time.Duration
	ShutdownTimeout         time.Duration
}

func OpenRuntimePipeline(config RuntimeConfig, catalog Catalog) (*Pipeline, error) {
	classifier, err := NewClassifier(catalog, time.Now)
	if err != nil {
		return nil, err
	}
	protector, err := NewSourceProtector(
		config.KeyID,
		config.Secret,
		config.SourceSealingKeyVersion,
		config.SourceSealingPublicKey,
	)
	if err != nil {
		return nil, err
	}
	state, err := openStreamState(config.QueueDirectory, config.NodeID)
	if err != nil {
		return nil, err
	}
	queue, err := OpenDiskQueue(QueueConfig{
		Directory:       filepath.Join(config.QueueDirectory, "queue"),
		NodeID:          config.NodeID,
		StreamID:        state.StreamID,
		WriteKeyVersion: config.QueueKeyVersion,
		Keys:            map[uint16][]byte{config.QueueKeyVersion: config.QueueKey},
		MaxBytes:        config.QueueMaxBytes,
		MaxAge:          config.QueueMaxAge,
	})
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(config.NodeID, config.KeyID, config.Secret)
	if err != nil {
		_ = queue.Close()
		return nil, err
	}
	sender, err := NewSender(SenderConfig{
		Endpoint: config.Endpoint,
		Timeout:  config.RequestTimeout,
	}, signer)
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
