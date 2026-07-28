package telemetry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type signedCatalogEnvelope struct {
	Catalog   json.RawMessage `json:"catalog"`
	Signature string          `json:"signature"`
}

func LoadSignedCatalogWithCache(
	path string,
	cachePath string,
	verificationKey []byte,
) (Catalog, bool, error) {
	catalog, sourceErr := LoadSignedCatalog(path, verificationKey)
	if sourceErr == nil {
		if data, err := os.ReadFile(path); err == nil {
			if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err == nil {
				_ = atomicWriteFile(cachePath, data, 0o600)
			}
		}
		return catalog, false, nil
	}
	cached, cacheErr := LoadSignedCatalog(cachePath, verificationKey)
	if cacheErr != nil {
		return Catalog{}, false, fmt.Errorf(
			"classifier catalog unavailable: source: %v; cache: %w",
			sourceErr,
			cacheErr,
		)
	}
	return cached, true, nil
}

func LoadSignedCatalog(path string, verificationKey []byte) (Catalog, error) {
	if path == "" {
		return Catalog{}, fmt.Errorf("classifier catalog path is required")
	}
	if len(verificationKey) != ed25519.PublicKeySize {
		return Catalog{}, fmt.Errorf("classifier verification key must be %d bytes", ed25519.PublicKeySize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, fmt.Errorf("read classifier catalog: %w", err)
	}
	var envelope signedCatalogEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Catalog{}, fmt.Errorf("decode classifier catalog envelope: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Catalog{}, fmt.Errorf("classifier catalog signature is invalid")
	}
	if !ed25519.Verify(verificationKey, envelope.Catalog, signature) {
		return Catalog{}, fmt.Errorf("classifier catalog signature verification failed")
	}
	var catalog Catalog
	decoder = json.NewDecoder(bytes.NewReader(envelope.Catalog))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode classifier catalog: %w", err)
	}
	return catalog, nil
}
