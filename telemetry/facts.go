package telemetry

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type Network string

const (
	NetworkUnknown Network = "unknown"
	NetworkTCP     Network = "tcp"
	NetworkUDP     Network = "udp"
)

type SniffSource string

const (
	SniffNone     SniffSource = "none"
	SniffOriginal SniffSource = "original"
	SniffHTTPHost SniffSource = "http_host"
	SniffTLSSNI   SniffSource = "tls_sni"
	SniffQUIC     SniffSource = "quic"
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

type ConnectionOutcome string

const (
	ConnectionOutcomeUnknown  ConnectionOutcome = "unknown"
	ConnectionOutcomeAccepted ConnectionOutcome = "accepted"
	ConnectionOutcomeFailed   ConnectionOutcome = "failed"
)

type FailureStage string

const (
	FailureStageNone     FailureStage = "none"
	FailureStageDispatch FailureStage = "dispatch"
	FailureStageRoute    FailureStage = "route"
	FailureStageOutbound FailureStage = "outbound"
)

type CompletenessStatus string

const (
	CompletenessPartial CompletenessStatus = "partial"
	CompletenessReady   CompletenessStatus = "ready"
)

type LossReason string

const (
	LossReasonNone                  LossReason = ""
	LossReasonTerminalNotObservable LossReason = "terminal_outcome_unobservable"
)

type Destination struct {
	Address     string
	Port        uint16
	Kind        DestinationKind
	AppProtocol AppProtocol
}

type Observation struct {
	ObservedAt          time.Time
	UserID              uint64
	NodeID              uint64
	SourceIP            netip.Addr
	Destination         Destination
	Network             Network
	AppProtocol         AppProtocol
	SniffSource         SniffSource
	Confidence          Confidence
	UploadBytes         uint64
	DownloadBytes       uint64
	ActiveMillis        uint64
	RuntimeListener     string
	RuntimeListenPort   uint16
	RuntimeSNI          string
	RuntimeHTTPHost     string
	RuntimeProtocol     AppProtocol
	InboundTag          string
	Outcome             ConnectionOutcome
	FailureStage        FailureStage
	LossReason          LossReason
	LatencyMilliseconds uint64
	CompletenessStatus  CompletenessStatus
}

type Emission struct {
	Sources []SourceEnvelope  `json:"sources"`
	Events  []ConnectionEvent `json:"events"`
}

type SourceEnvelope struct {
	SourceRef string `json:"source_ref"`
	SourceIP  string `json:"source_ip"`
}

type MillisTime struct {
	time.Time
}

func (t MillisTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(t.UTC().Format("2006-01-02T15:04:05.000Z"))), nil
}

func normalizeNetwork(network Network) Network {
	switch network {
	case NetworkTCP, NetworkUDP:
		return network
	default:
		return NetworkUnknown
	}
}

func normalizeAppProtocol(protocol AppProtocol) AppProtocol {
	switch protocol {
	case AppProtocolHTTP, AppProtocolTLS, AppProtocolQUIC:
		return protocol
	default:
		return AppProtocolUnknown
	}
}

func normalizeSniffSource(source SniffSource) SniffSource {
	switch source {
	case SniffOriginal, SniffHTTPHost, SniffTLSSNI, SniffQUIC:
		return source
	default:
		return SniffNone
	}
}

func normalizeConfidence(confidence Confidence) Confidence {
	switch confidence {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return confidence
	default:
		return ConfidenceUnknown
	}
}

func normalizeConnectionOutcome(outcome ConnectionOutcome) ConnectionOutcome {
	switch outcome {
	case ConnectionOutcomeAccepted, ConnectionOutcomeFailed:
		return outcome
	default:
		return ConnectionOutcomeUnknown
	}
}

func normalizeFailureStage(stage FailureStage) FailureStage {
	switch stage {
	case FailureStageDispatch, FailureStageRoute, FailureStageOutbound:
		return stage
	default:
		return FailureStageNone
	}
}

func normalizeCompleteness(status CompletenessStatus) CompletenessStatus {
	if status == CompletenessReady {
		return status
	}
	return CompletenessPartial
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
	if ascii == "" || len(ascii) > 253 || strings.Contains(ascii, "*") ||
		!validDomain(ascii) {
		return "", DestinationKindUnknown, fmt.Errorf("invalid destination")
	}
	return ascii, DestinationDomain, nil
}

func validDomain(value string) bool {
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' ||
				character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
