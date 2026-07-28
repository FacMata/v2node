package core

import (
	"net/netip"
	"testing"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/telemetry"
)

type captureTelemetrySink struct {
	got telemetry.Observation
}

func (s *captureTelemetrySink) Observe(observation telemetry.Observation) bool {
	s.got = observation
	return true
}

func TestTelemetryAdapterResolvesPanelUserAndNode(t *testing.T) {
	users := &UserMap{uidMap: map[string]int{"node-tag|user-uuid": 42}}
	sink := &captureTelemetrySink{}
	adapter := newTelemetryAdapter(users, []*panel.NodeInfo{{
		Id:  7,
		Tag: "node-tag",
	}}, sink)

	raw := telemetry.RawObservation{
		ObservedAt:  time.Date(2026, 7, 29, 6, 0, 0, 0, time.UTC),
		InboundTag:  "node-tag",
		UserEmail:   "node-tag|user-uuid",
		SourceIP:    netip.MustParseAddr("1.2.3.4"),
		Destination: telemetry.Destination{Address: "1.1.1.1", Port: 80},
		Network:     telemetry.NetworkTCP,
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
}

func TestTelemetryAdapterRejectsUnknownIdentity(t *testing.T) {
	adapter := newTelemetryAdapter(
		&UserMap{uidMap: make(map[string]int)},
		[]*panel.NodeInfo{{Id: 7, Tag: "node-tag"}},
		&captureTelemetrySink{},
	)
	if adapter.ObserveRaw(telemetry.RawObservation{
		InboundTag: "node-tag",
		UserEmail:  "unknown",
	}) {
		t.Fatal("ObserveRaw() accepted unknown user")
	}
}
