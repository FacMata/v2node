package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/wyx2685/v2node/telemetry"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

type telemetrySniffResult struct {
	domain   string
	protocol string
}

func (r telemetrySniffResult) Domain() string   { return r.domain }
func (r telemetrySniffResult) Protocol() string { return r.protocol }

func TestRawTelemetryObservationUsesInboundIdentityAndTLSSNI(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		Local:  net.TCPDestination(net.ParseAddress("10.0.0.7"), 443),
		Tag:    "node-tag",
		Name:   "vless-inbound-7",
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})
	observedAt := time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC)

	got, ok := rawTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("8.8.8.8"), 443),
		telemetrySniffResult{domain: "cp.cloudflare.com", protocol: "tls"},
		observedAt,
	)
	if !ok {
		t.Fatal("rawTelemetryObservation() rejected valid session")
	}
	if got.InboundTag != "node-tag" || got.UserEmail != "node-tag|user-uuid" {
		t.Fatalf("identity = %#v", got)
	}
	if got.SourceIP.String() != "1.2.3.4" {
		t.Fatalf("source IP = %s", got.SourceIP)
	}
	if got.Destination.Address != "cp.cloudflare.com" ||
		got.Destination.Kind != telemetry.DestinationDomain ||
		got.Destination.Port != 443 {
		t.Fatalf("destination = %#v", got.Destination)
	}
	if got.AppProtocol != telemetry.AppProtocolTLS ||
		got.SniffSource != telemetry.SniffTLSSNI ||
		got.Confidence != telemetry.ConfidenceHigh {
		t.Fatalf("sniff metadata = %#v", got)
	}
}

func TestRawConnectionTelemetryObservationCarriesRuntimeAndRouteOutcome(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		Local:  net.TCPDestination(net.ParseAddress("10.0.0.7"), 443),
		Tag:    "node-tag",
		Name:   "vless-inbound-7",
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})
	observedAt := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)

	got, ok := rawConnectionTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("8.8.8.8"), 443),
		telemetrySniffResult{domain: "cp.cloudflare.com", protocol: "tls"},
		observedAt,
		dispatchTelemetryResult{
			Outcome:      telemetry.ConnectionOutcomeUnknown,
			FailureStage: telemetry.FailureStageOutbound,
			LossReason:   telemetry.LossReasonTerminalNotObservable,
			Latency:      37 * time.Millisecond,
		},
	)
	if !ok {
		t.Fatal("rawConnectionTelemetryObservation() rejected valid session")
	}
	if got.RuntimeListener != "vless-inbound-7" || got.RuntimeListenPort != 443 ||
		got.RuntimeSNI != "cp.cloudflare.com" || got.RuntimeProtocol != telemetry.AppProtocolTLS ||
		got.InboundTag != "node-tag" {
		t.Fatalf("runtime fields = %#v", got)
	}
	if got.Outcome != telemetry.ConnectionOutcomeUnknown ||
		got.FailureStage != telemetry.FailureStageOutbound ||
		got.LossReason != telemetry.LossReasonTerminalNotObservable ||
		got.LatencyMilliseconds != 37 ||
		got.CompletenessStatus != telemetry.CompletenessPartial {
		t.Fatalf("result fields = %#v", got)
	}
}

func TestRawConnectionTelemetryObservationSeparatesHTTPHostFromSNI(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		Local:  net.TCPDestination(net.ParseAddress("10.0.0.7"), 80),
		Tag:    "node-tag",
		Name:   "http-inbound-7",
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})

	got, ok := rawConnectionTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("8.8.8.8"), 80),
		telemetrySniffResult{domain: "service.example.com", protocol: "http"},
		time.Now().UTC(),
		dispatchTelemetryResult{
			Outcome:      telemetry.ConnectionOutcomeUnknown,
			FailureStage: telemetry.FailureStageOutbound,
			LossReason:   telemetry.LossReasonTerminalNotObservable,
		},
	)
	if !ok {
		t.Fatal("rawConnectionTelemetryObservation() rejected valid session")
	}
	if got.RuntimeHTTPHost != "service.example.com" || got.RuntimeSNI != "" {
		t.Fatalf("runtime host fields = %#v", got)
	}
}

func TestRawTelemetryObservationFallsBackToOriginalDestination(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.UDPDestination(net.ParseAddress("2001:db8::1"), 12345),
		Tag:    "node-tag",
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})

	got, ok := rawTelemetryObservation(
		ctx,
		net.UDPDestination(net.ParseAddress("1.1.1.1"), 53),
		nil,
		time.Now(),
	)
	if !ok {
		t.Fatal("rawTelemetryObservation() rejected valid UDP session")
	}
	if got.Network != telemetry.NetworkUDP ||
		got.Destination.Kind != telemetry.DestinationIPv4 ||
		got.SniffSource != telemetry.SniffOriginal {
		t.Fatalf("fallback observation = %#v", got)
	}
}

func TestRawTelemetryObservationRejectsAnonymousSession(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		Tag:    "node-tag",
	})
	if _, ok := rawTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("1.1.1.1"), 443),
		nil,
		time.Now(),
	); ok {
		t.Fatal("rawTelemetryObservation() accepted anonymous session")
	}
}

func TestRawTelemetryObservationAcceptsAttributedSessionWithoutInboundTag(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})
	got, ok := rawTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("1.1.1.1"), 443),
		nil,
		time.Now(),
	)
	if !ok {
		t.Fatal("rawTelemetryObservation() rejected attributable session without tag")
	}
	if got.UserEmail != "node-tag|user-uuid" || got.InboundTag != "" {
		t.Fatalf("identity = %#v", got)
	}
}

func TestRawTelemetryObservationLowersConfidenceForConflictingDomains(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.2.3.4"), 12345),
		Tag:    "node-tag",
		User:   &protocol.MemoryUser{Email: "node-tag|user-uuid"},
	})
	got, ok := rawTelemetryObservation(
		ctx,
		net.TCPDestination(net.ParseAddress("expected.example"), 443),
		telemetrySniffResult{domain: "different.example", protocol: "tls"},
		time.Now(),
	)
	if !ok {
		t.Fatal("rawTelemetryObservation() rejected valid session")
	}
	if got.Confidence != telemetry.ConfidenceLow {
		t.Fatalf("confidence = %q, want low", got.Confidence)
	}
}
