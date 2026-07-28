package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSignedCatalogVerifiesExactCatalogBytes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	catalogJSON := []byte(`{"version":"v1","valid_until":"2030-01-01T00:00:00Z","rules":[{"id":"probe","host":"1.1.1.1","match_suffix":false,"ports":[80],"protocols":["http"],"confidence":"high"}]}`)
	envelope, err := json.Marshal(map[string]any{
		"catalog":   json.RawMessage(catalogJSON),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, catalogJSON)),
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	catalog, err := LoadSignedCatalog(path, publicKey)
	if err != nil {
		t.Fatalf("LoadSignedCatalog() error = %v", err)
	}
	if catalog.Version != "v1" || len(catalog.Rules) != 1 {
		t.Fatalf("catalog = %#v", catalog)
	}

	envelope[len(envelope)-2] ^= 1
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatalf("WriteFile(tampered) error = %v", err)
	}
	if _, err := LoadSignedCatalog(path, publicKey); err == nil {
		t.Fatal("LoadSignedCatalog() accepted tampered envelope")
	}
}

func TestClassifierSkipsDisabledCatalogRule(t *testing.T) {
	disabled := false
	now := time.Now()
	classifier, err := NewClassifier(Catalog{
		Version:    "v1",
		ValidUntil: now.Add(time.Hour),
		Rules: []ProbeRule{{
			ID:         "disabled",
			Host:       "1.1.1.1",
			Confidence: ConfidenceHigh,
			Enabled:    &disabled,
		}},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}
	if got := classifier.Classify(Destination{Address: "1.1.1.1"}); got.Class != DestinationOther {
		t.Fatalf("Classify() = %#v", got)
	}
}

func TestLoadSignedCatalogFallsBackToVerifiedCache(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	catalogJSON := []byte(`{"version":"cached-v1","valid_until":"2030-01-01T00:00:00Z","rules":[]}`)
	envelope, err := json.Marshal(map[string]any{
		"catalog":   json.RawMessage(catalogJSON),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, catalogJSON)),
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "source.json")
	cache := filepath.Join(directory, "cache", "catalog.json")
	if err := os.WriteFile(source, envelope, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, usedCache, err := LoadSignedCatalogWithCache(source, cache, publicKey); err != nil || usedCache {
		t.Fatalf("initial load cache=%v error=%v", usedCache, err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	catalog, usedCache, err := LoadSignedCatalogWithCache(source, cache, publicKey)
	if err != nil {
		t.Fatalf("cached load error = %v", err)
	}
	if !usedCache || catalog.Version != "cached-v1" {
		t.Fatalf("cached load = %#v, used=%v", catalog, usedCache)
	}
}
