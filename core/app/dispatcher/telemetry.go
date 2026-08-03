package dispatcher

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/wyx2685/v2node/telemetry"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type dispatchTelemetryResult struct {
	Outcome      telemetry.ConnectionOutcome
	FailureStage telemetry.FailureStage
	LossReason   telemetry.LossReason
	Latency      time.Duration
}

func rawTelemetryObservation(
	ctx context.Context,
	original xnet.Destination,
	result SniffResult,
	observedAt time.Time,
) (telemetry.RawObservation, bool) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil ||
		inbound.User == nil ||
		inbound.User.Email == "" ||
		!inbound.Source.IsValid() ||
		!original.IsValid() {
		return telemetry.RawObservation{}, false
	}

	sourceIP, err := netip.ParseAddr(inbound.Source.Address.IP().String())
	if err != nil {
		return telemetry.RawObservation{}, false
	}
	destination := telemetry.Destination{
		Address: destinationAddress(original.Address),
		Port:    uint16(original.Port),
		Kind:    destinationKind(original.Address),
	}
	network := telemetry.NetworkUnknown
	switch original.Network {
	case xnet.Network_TCP:
		network = telemetry.NetworkTCP
	case xnet.Network_UDP:
		network = telemetry.NetworkUDP
	}

	appProtocol := telemetry.AppProtocolUnknown
	sniffSource := telemetry.SniffOriginal
	confidence := telemetry.ConfidenceUnknown
	if result != nil {
		appProtocol, sniffSource = sniffMetadata(result.Protocol())
		if domain := result.Domain(); domain != "" {
			originalDomain := ""
			if original.Address.Family().IsDomain() {
				originalDomain = strings.TrimSuffix(strings.ToLower(original.Address.Domain()), ".")
			}
			destination.Address = domain
			destination.Kind = telemetry.DestinationDomain
			confidence = telemetry.ConfidenceHigh
			if originalDomain != "" &&
				originalDomain != strings.TrimSuffix(strings.ToLower(domain), ".") {
				confidence = telemetry.ConfidenceLow
			}
		} else if appProtocol != telemetry.AppProtocolUnknown {
			confidence = telemetry.ConfidenceMedium
		}
	}
	destination.AppProtocol = appProtocol

	return telemetry.RawObservation{
		ObservedAt:  observedAt.UTC(),
		InboundTag:  inbound.Tag,
		UserEmail:   inbound.User.Email,
		SourceIP:    sourceIP.Unmap(),
		Destination: destination,
		Network:     network,
		AppProtocol: appProtocol,
		SniffSource: sniffSource,
		Confidence:  confidence,
	}, true
}

func rawConnectionTelemetryObservation(
	ctx context.Context,
	original xnet.Destination,
	result SniffResult,
	observedAt time.Time,
	dispatchResult dispatchTelemetryResult,
) (telemetry.RawObservation, bool) {
	observation, ok := rawTelemetryObservation(ctx, original, result, observedAt)
	if !ok {
		return telemetry.RawObservation{}, false
	}
	inbound := session.InboundFromContext(ctx)
	listener := inbound.Name
	if listener == "" {
		listener = inbound.Tag
	}
	listenPort := uint16(0)
	if inbound.Local.IsValid() {
		listenPort = uint16(inbound.Local.Port)
	}
	runtimeSNI := ""
	runtimeHTTPHost := ""
	if observation.AppProtocol == telemetry.AppProtocolTLS && result != nil {
		runtimeSNI = strings.TrimSuffix(strings.ToLower(result.Domain()), ".")
	} else if observation.AppProtocol == telemetry.AppProtocolHTTP && result != nil {
		runtimeHTTPHost = strings.TrimSuffix(strings.ToLower(result.Domain()), ".")
	}
	latency := dispatchResult.Latency
	if latency < 0 {
		latency = 0
	}
	completeness := telemetry.CompletenessReady
	if listener == "" || listenPort == 0 ||
		dispatchResult.Outcome == "" ||
		dispatchResult.Outcome == telemetry.ConnectionOutcomeUnknown {
		completeness = telemetry.CompletenessPartial
	}
	observation.RuntimeListener = listener
	observation.RuntimeListenPort = listenPort
	observation.RuntimeSNI = runtimeSNI
	observation.RuntimeHTTPHost = runtimeHTTPHost
	observation.RuntimeProtocol = observation.AppProtocol
	observation.Outcome = dispatchResult.Outcome
	observation.FailureStage = dispatchResult.FailureStage
	observation.LossReason = dispatchResult.LossReason
	observation.LatencyMilliseconds = uint64(latency / time.Millisecond)
	observation.CompletenessStatus = completeness
	return observation, true
}

func destinationAddress(address xnet.Address) string {
	if address.Family().IsDomain() {
		return address.Domain()
	}
	if address.Family().IsIP() {
		return address.IP().String()
	}
	return ""
}

func destinationKind(address xnet.Address) telemetry.DestinationKind {
	switch {
	case address.Family().IsIPv4():
		return telemetry.DestinationIPv4
	case address.Family().IsIPv6():
		return telemetry.DestinationIPv6
	case address.Family().IsDomain():
		return telemetry.DestinationDomain
	default:
		return telemetry.DestinationKindUnknown
	}
}

func sniffMetadata(protocol string) (telemetry.AppProtocol, telemetry.SniffSource) {
	protocol = strings.ToLower(protocol)
	switch {
	case strings.HasPrefix(protocol, "http"):
		return telemetry.AppProtocolHTTP, telemetry.SniffHTTPHost
	case strings.HasPrefix(protocol, "tls"):
		return telemetry.AppProtocolTLS, telemetry.SniffTLSSNI
	case strings.HasPrefix(protocol, "quic"):
		return telemetry.AppProtocolQUIC, telemetry.SniffQUIC
	default:
		return telemetry.AppProtocolUnknown, telemetry.SniffOriginal
	}
}
