package telemetry

import (
	"testing"
	"time"
)

func TestSignerMatchesCanonicalGoldenVector(t *testing.T) {
	signer, err := NewSigner(
		123,
		"01JTELEMETRYKEY00000000000",
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	got, err := signer.Sign(
		[]byte(`{"schema_version":1}`),
		time.Unix(1785283200, 0).UTC(),
		nonce,
	)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if got.BodySHA256 != "a9d5f6d002d956b8af5787a05e0ca000d45c03977ffa54ee8fbed719fed5fd23" {
		t.Fatalf("body hash = %q", got.BodySHA256)
	}
	if got.Nonce != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX" {
		t.Fatalf("nonce = %q", got.Nonce)
	}
	if got.Signature != "E8nhqGGKUQEzld-nc5iscj2-OA5l8mV5qSQXIAhLW54" {
		t.Fatalf("signature = %q", got.Signature)
	}
	if got.Timestamp != "1785283200" {
		t.Fatalf("timestamp = %q", got.Timestamp)
	}
}

func TestSignerRejectsInvalidNonceLength(t *testing.T) {
	signer, err := NewSigner(123, "key", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, err := signer.Sign([]byte("{}"), time.Now(), []byte("short")); err == nil {
		t.Fatal("Sign() error = nil, want nonce length error")
	}
}
