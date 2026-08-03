package core

import (
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/telemetry"
)

type captureTelemetrySink struct {
	got    telemetry.Observation
	accept bool
}

func (s *captureTelemetrySink) Observe(observation telemetry.Observation) bool {
	s.got = observation
	return s.accept
}

func TestTelemetryAdapterResolvesPanelUserAndNode(t *testing.T) {
	users := &UserMap{uidMap: map[string]int{"node-tag|user-uuid": 42}}
	sink := &captureTelemetrySink{accept: true}
	adapter := newTelemetryAdapter(users, []*panel.NodeInfo{{
		Id:  7,
		Tag: "node-tag",
	}}, sink)

	raw := telemetry.RawObservation{
		ObservedAt:          time.Date(2026, 7, 29, 6, 0, 0, 0, time.UTC),
		InboundTag:          "node-tag",
		UserEmail:           "node-tag|user-uuid",
		SourceIP:            netip.MustParseAddr("1.2.3.4"),
		Destination:         telemetry.Destination{Address: "1.1.1.1", Port: 80},
		Network:             telemetry.NetworkTCP,
		RuntimeListener:     "vless-inbound-7",
		RuntimeListenPort:   443,
		RuntimeSNI:          "service.example.com",
		RuntimeProtocol:     telemetry.AppProtocolTLS,
		Outcome:             telemetry.ConnectionOutcomeAccepted,
		FailureStage:        telemetry.FailureStageNone,
		LossReason:          telemetry.LossReasonTerminalNotObservable,
		LatencyMilliseconds: 12,
		CompletenessStatus:  telemetry.CompletenessReady,
	}
	if !adapter.ObserveRaw(raw) {
		t.Fatal("ObserveRaw() rejected known user")
	}
	if sink.got.UserID != 42 || sink.got.NodeID != 7 {
		t.Fatalf("resolved IDs = user %d node %d", sink.got.UserID, sink.got.NodeID)
	}
	if sink.got.SourceIP != raw.SourceIP || sink.got.Destination != raw.Destination {
		t.Fatalf("resolved observation = %#v", sink.got)
	}
	if sink.got.RuntimeListener != raw.RuntimeListener ||
		sink.got.Outcome != raw.Outcome ||
		sink.got.LossReason != raw.LossReason ||
		sink.got.CompletenessStatus != raw.CompletenessStatus {
		t.Fatalf("runtime observation = %#v", sink.got)
	}
}

func TestTelemetryAdapterRejectsUnknownIdentity(t *testing.T) {
	adapter := newTelemetryAdapter(
		&UserMap{uidMap: make(map[string]int)},
		[]*panel.NodeInfo{{Id: 7, Tag: "node-tag"}},
		&captureTelemetrySink{accept: true},
	)
	if adapter.ObserveRaw(telemetry.RawObservation{
		InboundTag: "node-tag",
		UserEmail:  "unknown",
	}) {
		t.Fatal("ObserveRaw() accepted unknown user")
	}
}

func TestTelemetryAdapterLogsDropReasonsOnceWithoutIdentityValues(t *testing.T) {
	logger := log.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
	previousLevel := logger.GetLevel()
	previousOutput := logger.Out
	t.Cleanup(func() {
		logger.ReplaceHooks(previousHooks)
		logger.SetLevel(previousLevel)
		logger.SetOutput(previousOutput)
	})
	logger.SetLevel(log.WarnLevel)
	logger.SetOutput(io.Discard)
	hook := logtest.NewGlobal()

	adapter := newTelemetryAdapter(
		&UserMap{uidMap: map[string]int{"node-tag|known-user": 42}},
		[]*panel.NodeInfo{{Id: 7, Tag: "node-tag"}},
		&captureTelemetrySink{accept: false},
	)
	tests := []telemetry.RawObservation{
		{InboundTag: "node-tag", UserEmail: "private-unknown-user"},
		{InboundTag: "private-unknown-tag", UserEmail: "node-tag|known-user"},
		{InboundTag: "node-tag", UserEmail: "node-tag|known-user"},
	}
	for _, observation := range tests {
		if adapter.ObserveRaw(observation) {
			t.Fatal("ObserveRaw() accepted rejected diagnostic event")
		}
		if adapter.ObserveRaw(observation) {
			t.Fatal("ObserveRaw() accepted repeated rejected diagnostic event")
		}
	}

	entries := hook.AllEntries()
	if len(entries) != 3 {
		t.Fatalf("warning count = %d, want 3", len(entries))
	}
	for _, entry := range entries {
		if entry.Level != log.WarnLevel {
			t.Fatalf("warning level = %s", entry.Level)
		}
		if strings.Contains(entry.Message, "private-unknown-user") ||
			strings.Contains(entry.Message, "private-unknown-tag") ||
			strings.Contains(entry.Message, "known-user") {
			t.Fatalf("warning leaked identity value: %q", entry.Message)
		}
	}
}
