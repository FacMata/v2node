package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/telemetry"
)

func newTelemetryManager(config *conf.Conf) (*telemetry.Manager, error) {
	pipelines := make([]*telemetry.Pipeline, 0)
	var errs []error
	for i := range config.NodeConfigs {
		node := &config.NodeConfigs[i]
		if !node.Telemetry.Enabled {
			continue
		}
		pipeline, err := openTelemetryPipeline(node)
		if err != nil {
			errs = append(errs, fmt.Errorf("node %d: %w", node.NodeID, err))
			continue
		}
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
	if node.NodeID <= 0 || config.KeyID == "" ||
		config.SecretEnv == "" || config.QueueKeyEnv == "" ||
		config.SourceSealingKeyVersion == 0 ||
		config.ClassifierCatalogPath == "" {
		return nil, fmt.Errorf("telemetry identity, secret references, sealing key, and catalog are required")
	}
	secret, err := readSecretEnv(config.SecretEnv, 32)
	if err != nil {
		return nil, err
	}
	queueKey, err := readSecretEnv(config.QueueKeyEnv, 32)
	if err != nil {
		return nil, err
	}
	sealingKey, err := decodeBase64URL(
		"source sealing public key",
		config.SourceSealingPublicKey,
		32,
	)
	if err != nil {
		return nil, err
	}
	verificationKey, err := decodeBase64URL(
		"classifier verification key",
		config.ClassifierVerificationKey,
		32,
	)
	if err != nil {
		return nil, err
	}
	catalog, usedCache, err := telemetry.LoadSignedCatalogWithCache(
		config.ClassifierCatalogPath,
		filepath.Join(config.QueueDirectory, "catalog-cache.json"),
		verificationKey,
	)
	if err != nil {
		return nil, err
	}
	if usedCache {
		log.WithFields(log.Fields{
			"node_id":         node.NodeID,
			"catalog_version": catalog.Version,
		}).Warn("using cached telemetry classifier catalog")
	}
	if !time.Now().Before(catalog.ValidUntil) {
		log.WithFields(log.Fields{
			"node_id":         node.NodeID,
			"catalog_version": catalog.Version,
		}).Error("telemetry classifier catalog expired; classification is unknown")
	}
	return telemetry.OpenRuntimePipeline(telemetry.RuntimeConfig{
		NodeID:                  uint64(node.NodeID),
		Endpoint:                config.Endpoint,
		KeyID:                   config.KeyID,
		Secret:                  secret,
		SourceSealingPublicKey:  sealingKey,
		SourceSealingKeyVersion: config.SourceSealingKeyVersion,
		QueueDirectory:          config.QueueDirectory,
		QueueKey:                queueKey,
		QueueKeyVersion:         config.QueueKeyVersion,
		QueueMaxBytes:           config.QueueMaxBytes,
		QueueMaxAge:             time.Duration(config.QueueMaxAgeSeconds) * time.Second,
		CollectorVersion:        version,
		BufferSize:              config.BufferSize,
		FlushInterval:           time.Duration(config.FlushIntervalSeconds) * time.Second,
		RequestTimeout:          time.Duration(config.RequestTimeoutSeconds) * time.Second,
		RetryMin:                time.Duration(config.RetryMinSeconds) * time.Second,
		RetryMax:                time.Duration(config.RetryMaxSeconds) * time.Second,
		ShutdownTimeout:         time.Duration(config.ShutdownTimeoutSeconds) * time.Second,
	}, catalog)
}

func readSecretEnv(name string, minimumBytes int) ([]byte, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return nil, fmt.Errorf("required secret environment variable %q is unset", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimumBytes {
		return nil, fmt.Errorf(
			"secret environment variable %q must be unpadded base64url with at least %d bytes",
			name,
			minimumBytes,
		)
	}
	return decoded, nil
}

func decodeBase64URL(label, value string, exactBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != exactBytes {
		return nil, fmt.Errorf("%s must be unpadded base64url encoding %d bytes", label, exactBytes)
	}
	return decoded, nil
}
