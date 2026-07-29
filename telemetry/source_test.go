package telemetry

import (
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"testing"
)

func TestSourceProtectorReturnsCanonicalPlaintextIP(t *testing.T) {
	protector := NewSourceProtector()
	source, err := protector.Protect(netip.MustParseAddr("::ffff:1.2.3.4"))
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if source.IP != "1.2.3.4" {
		t.Fatalf("source IP = %q", source.IP)
	}
	sum := sha256.Sum256([]byte("1.2.3.4"))
	wantRef := base64.RawURLEncoding.EncodeToString(sum[:16])
	if source.Ref != wantRef {
		t.Fatalf("source ref = %q, want %q", source.Ref, wantRef)
	}
}

func TestSourceProtectorRejectsInvalidIP(t *testing.T) {
	if _, err := NewSourceProtector().Protect(netip.Addr{}); err == nil {
		t.Fatal("Protect() error = nil")
	}
}
