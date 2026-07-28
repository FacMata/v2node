package telemetry

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

type DestinationClass string

const (
	DestinationUnknown DestinationClass = "unknown"
	DestinationProbe   DestinationClass = "probe"
	DestinationOther   DestinationClass = "other"
	DestinationPrivate DestinationClass = "private"
)

type DestinationKind string

const (
	DestinationKindUnknown DestinationKind = "unknown"
	DestinationDomain      DestinationKind = "domain"
	DestinationIPv4        DestinationKind = "ipv4"
	DestinationIPv6        DestinationKind = "ipv6"
)

type AppProtocol string

const (
	AppProtocolUnknown AppProtocol = "unknown"
	AppProtocolHTTP    AppProtocol = "http"
	AppProtocolTLS     AppProtocol = "tls"
	AppProtocolQUIC    AppProtocol = "quic"
)

type Confidence string

const (
	ConfidenceUnknown Confidence = "unknown"
	ConfidenceLow     Confidence = "low"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceHigh    Confidence = "high"
)

type Destination struct {
	Address     string
	Port        uint16
	Kind        DestinationKind
	AppProtocol AppProtocol
}

type Classification struct {
	Class             DestinationClass
	Signature         string
	Confidence        Confidence
	CatalogVersion    string
	DestinationKind   DestinationKind
	DestinationPort   uint16
	UnknownDistinct   uint32
	NormalizedAddress string
}

type Catalog struct {
	Version    string
	ValidUntil time.Time
	Rules      []ProbeRule
}

type ProbeRule struct {
	ID          string
	Host        string
	MatchSuffix bool
	Ports       []uint16
	Protocols   []AppProtocol
	Confidence  Confidence
}

type compiledRule struct {
	ProbeRule
	host string
}

type Classifier struct {
	version    string
	validUntil time.Time
	rules      []compiledRule
	now        func() time.Time
}

func NewClassifier(catalog Catalog, now func() time.Time) (*Classifier, error) {
	if catalog.Version == "" {
		return nil, fmt.Errorf("catalog version is required")
	}
	if catalog.ValidUntil.IsZero() {
		return nil, fmt.Errorf("catalog validity is required")
	}
	if now == nil {
		now = time.Now
	}

	rules := make([]compiledRule, 0, len(catalog.Rules))
	ids := make(map[string]struct{}, len(catalog.Rules))
	for _, rule := range catalog.Rules {
		if !validRuleID(rule.ID) {
			return nil, fmt.Errorf("probe rule ID %q is invalid", rule.ID)
		}
		if _, exists := ids[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate probe rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		host, kind, err := normalizeDestination(rule.Host)
		if err != nil {
			return nil, fmt.Errorf("normalize probe rule %s: %w", rule.ID, err)
		}
		if rule.Host != host {
			return nil, fmt.Errorf("probe rule %s host must be canonical ASCII", rule.ID)
		}
		if rule.MatchSuffix && kind != DestinationDomain {
			return nil, fmt.Errorf("probe rule %s: suffix matcher requires domain", rule.ID)
		}
		if kind == DestinationDomain && !validDomain(host) {
			return nil, fmt.Errorf("probe rule %s host is not a valid domain", rule.ID)
		}
		if !validRuleConfidence(rule.Confidence) {
			return nil, fmt.Errorf("probe rule %s confidence is invalid", rule.ID)
		}
		seenPorts := make(map[uint16]struct{}, len(rule.Ports))
		for _, port := range rule.Ports {
			if port == 0 {
				return nil, fmt.Errorf("probe rule %s port is invalid", rule.ID)
			}
			if _, exists := seenPorts[port]; exists {
				return nil, fmt.Errorf("probe rule %s has duplicate port", rule.ID)
			}
			seenPorts[port] = struct{}{}
		}
		seenProtocols := make(map[AppProtocol]struct{}, len(rule.Protocols))
		for _, protocol := range rule.Protocols {
			if protocol != AppProtocolHTTP &&
				protocol != AppProtocolTLS &&
				protocol != AppProtocolQUIC {
				return nil, fmt.Errorf("probe rule %s protocol is invalid", rule.ID)
			}
			if _, exists := seenProtocols[protocol]; exists {
				return nil, fmt.Errorf("probe rule %s has duplicate protocol", rule.ID)
			}
			seenProtocols[protocol] = struct{}{}
		}
		rules = append(rules, compiledRule{ProbeRule: rule, host: host})
	}

	return &Classifier{
		version:    catalog.Version,
		validUntil: catalog.ValidUntil,
		rules:      rules,
		now:        now,
	}, nil
}

func validRuleID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if unicode.IsLower(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validRuleConfidence(value Confidence) bool {
	switch value {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

func validDomain(value string) bool {
	if len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') ||
				r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (c *Classifier) Classify(destination Destination) Classification {
	result := Classification{
		Class:           DestinationUnknown,
		Confidence:      ConfidenceUnknown,
		CatalogVersion:  c.version,
		DestinationKind: destination.Kind,
		DestinationPort: destination.Port,
	}
	if !c.now().Before(c.validUntil) {
		return result
	}

	address, kind, err := normalizeDestination(destination.Address)
	if err != nil {
		return result
	}
	result.NormalizedAddress = address
	result.DestinationKind = kind
	result.Class = DestinationOther

	for _, rule := range c.rules {
		if !matchesHost(rule, address) ||
			!containsPort(rule.Ports, destination.Port) ||
			!containsProtocol(rule.Protocols, destination.AppProtocol) {
			continue
		}
		result.Class = DestinationProbe
		result.Signature = rule.ID
		result.Confidence = rule.Confidence
		return result
	}

	return result
}

func normalizeDestination(value string) (string, DestinationKind, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" {
		return "", DestinationKindUnknown, fmt.Errorf("destination is empty")
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			return addr.String(), DestinationIPv4, nil
		}
		return addr.String(), DestinationIPv6, nil
	}

	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", DestinationKindUnknown, err
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || strings.Contains(ascii, "*") {
		return "", DestinationKindUnknown, fmt.Errorf("invalid destination")
	}
	return ascii, DestinationDomain, nil
}

func matchesHost(rule compiledRule, address string) bool {
	if rule.MatchSuffix {
		return address == rule.host || strings.HasSuffix(address, "."+rule.host)
	}
	return address == rule.host
}

func containsPort(ports []uint16, port uint16) bool {
	if len(ports) == 0 {
		return true
	}
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func containsProtocol(protocols []AppProtocol, protocol AppProtocol) bool {
	if len(protocols) == 0 {
		return true
	}
	for _, candidate := range protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}
