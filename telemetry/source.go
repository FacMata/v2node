package telemetry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"

	"golang.org/x/crypto/nacl/box"
)

const sourceRefDomain = "source-v1\x00"

type ProtectedSource struct {
	Ref               string
	SealedIP          []byte
	SealingKeyVersion uint16
}

type SourceProtector struct {
	telemetryKeyID string
	hmacSecret     []byte
	sealingVersion uint16
	publicKey      [32]byte
}

func NewSourceProtector(
	telemetryKeyID string,
	hmacSecret []byte,
	sealingVersion uint16,
	publicKey []byte,
) (*SourceProtector, error) {
	if telemetryKeyID == "" {
		return nil, fmt.Errorf("telemetry key ID is required")
	}
	if len(hmacSecret) < 32 {
		return nil, fmt.Errorf("telemetry HMAC secret must be at least 32 bytes")
	}
	if sealingVersion == 0 {
		return nil, fmt.Errorf("sealing key version is required")
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("sealing public key must be 32 bytes")
	}

	protector := &SourceProtector{
		telemetryKeyID: telemetryKeyID,
		hmacSecret:     append([]byte(nil), hmacSecret...),
		sealingVersion: sealingVersion,
	}
	copy(protector.publicKey[:], publicKey)
	return protector, nil
}

func (p *SourceProtector) Protect(ip netip.Addr) (ProtectedSource, error) {
	if !ip.IsValid() {
		return ProtectedSource{}, fmt.Errorf("source IP is invalid")
	}
	ip = ip.Unmap()
	canonical := ip.AsSlice()

	mac := hmac.New(sha256.New, p.hmacSecret)
	_, _ = mac.Write([]byte(sourceRefDomain))
	_, _ = mac.Write([]byte(p.telemetryKeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(canonical)
	ref := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])

	sealed, err := box.SealAnonymous(nil, canonical, &p.publicKey, rand.Reader)
	if err != nil {
		return ProtectedSource{}, fmt.Errorf("seal source IP: %w", err)
	}

	return ProtectedSource{
		Ref:               ref,
		SealedIP:          sealed,
		SealingKeyVersion: p.sealingVersion,
	}, nil
}
