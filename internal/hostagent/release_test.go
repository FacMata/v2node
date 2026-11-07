package hostagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyx2685/v2node/common/management"
)

func TestSignedReleaseAndImmutableState(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "binary")
	key := filepath.Join(dir, "key")
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(binary, []byte("test binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignRelease(binary, key, manifest, "v1.2.3", strings.Repeat("a", 40), "v1.0.0", 1); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(manifest + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	w := releaseWire{Manifest: string(raw), Signature: string(sig), SHA256: hex.EncodeToString(hash[:])}
	m, err := verifyRelease(w, base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "v1.2.3" || m.Assets[0].Size != 11 {
		t.Fatal("manifest changed")
	}
	w.Manifest += " "
	if _, err := verifyRelease(w, base64.StdEncoding.EncodeToString(public)); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	cfg := &Installation{ManagedDirectory: dir}
	for i := int64(1); i <= 3; i++ {
		n, err := nextEvent(cfg)
		if err != nil || n != i {
			t.Fatalf("nonmonotonic event %d: %v", n, err)
		}
	}
	j := journal{Phase: "switched", Operation: operation{ID: "test"}, FromSHA: strings.Repeat("b", 64)}
	if err := persistJournal(cfg, &j); err != nil {
		t.Fatal(err)
	}
	frozen, err := management.Frozen(dir)
	if err != nil || !frozen {
		t.Fatal("unfinished operation did not fence reload")
	}
	j.Phase = "not_started"
	if err := persistJournal(cfg, &j); err != nil {
		t.Fatal(err)
	}
	frozen, err = management.Frozen(dir)
	if err != nil || frozen {
		t.Fatal("finished intent blocked reload")
	}
}
