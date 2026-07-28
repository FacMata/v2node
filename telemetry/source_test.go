package telemetry

import (
	"crypto/rand"
	"net/netip"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSourceProtectorUsesKeyScopedReference(t *testing.T) {
	publicKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	protector, err := NewSourceProtector(
		"01JTELEMETRYKEY00000000000",
		[]byte("0123456789abcdef0123456789abcdef"),
		3,
		publicKey[:],
	)
	if err != nil {
		t.Fatalf("NewSourceProtector() error = %v", err)
	}

	got, err := protector.Protect(netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}

	const want = "m_nUobFtvR0UKDUC2nAaCA"
	if got.Ref != want {
		t.Fatalf("Protect() ref = %q, want %q", got.Ref, want)
	}
	if got.SealingKeyVersion != 3 {
		t.Fatalf("Protect() sealing key version = %d", got.SealingKeyVersion)
	}
}

func TestSourceProtectorSealsCanonicalIP(t *testing.T) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	protector, err := NewSourceProtector(
		"01JTELEMETRYKEY00000000000",
		[]byte("0123456789abcdef0123456789abcdef"),
		7,
		publicKey[:],
	)
	if err != nil {
		t.Fatalf("NewSourceProtector() error = %v", err)
	}

	got, err := protector.Protect(netip.MustParseAddr("::ffff:1.2.3.4"))
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}

	opened, ok := box.OpenAnonymous(nil, got.SealedIP, publicKey, privateKey)
	if !ok {
		t.Fatal("OpenAnonymous() failed")
	}
	if string(opened) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("sealed IP opened to %v", opened)
	}
}

func TestSourceProtectorRejectsInvalidConfiguration(t *testing.T) {
	_, err := NewSourceProtector("key", []byte("short"), 1, make([]byte, 32))
	if err == nil {
		t.Fatal("NewSourceProtector() error = nil, want invalid secret error")
	}
}
