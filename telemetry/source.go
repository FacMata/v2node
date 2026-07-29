package telemetry

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
)

type ProtectedSource struct {
	Ref string
	IP  string
}

type SourceProtector struct{}

func NewSourceProtector() *SourceProtector {
	return &SourceProtector{}
}

func (p *SourceProtector) Protect(ip netip.Addr) (ProtectedSource, error) {
	if !ip.IsValid() {
		return ProtectedSource{}, fmt.Errorf("source IP is invalid")
	}
	canonical := ip.Unmap().String()
	sum := sha256.Sum256([]byte(canonical))
	return ProtectedSource{
		Ref: base64.RawURLEncoding.EncodeToString(sum[:16]),
		IP:  canonical,
	}, nil
}
