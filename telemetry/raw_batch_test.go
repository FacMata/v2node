package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConnectionEventsV2ContractFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/connection_events_v2.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(body)); got !=
		"16f2e113839aa725d022c233c484e913773620b2cecdd582be2275002bf62aea" {
		t.Fatalf("fixture checksum = %s", got)
	}
	var batch Batch
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if batch.SchemaVersion != 2 || batch.ModeEpoch != 9 || len(batch.Events) != 1 {
		t.Fatalf("fixture envelope = %#v", batch)
	}
	event := batch.Events[0]
	if event.RuntimeHTTPHost != "api.service.example.com" ||
		event.Outcome != ConnectionOutcomeAccepted ||
		event.FailureStage != FailureStageNone ||
		event.CompletenessStatus != CompletenessReady {
		t.Fatalf("fixture event = %#v", event)
	}
	for _, forbidden := range []string{
		"published_host", "published_endpoint_id", "url_path", "query_string",
		"packet_payload", "content",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("fixture contains forbidden field %q", forbidden)
		}
	}
}

func TestAssembleBatchUsesRawConnectionEventsSchemaV1(t *testing.T) {
	streamID := uuid.MustParse("d3b30a72-222f-4b89-8d3e-cb0b9c9b8334")
	observedAt := time.Date(2026, 7, 30, 8, 15, 0, 0, time.UTC)

	batch, err := AssembleBatch(BatchParams{
		SchemaVersion:    1,
		BatchID:          uuid.MustParse("019fb5e9-8fb7-76ce-bb63-b9e38b2d94c9"),
		StreamID:         streamID,
		NodeID:           7,
		CollectorVersion: "test",
		GeneratedAt:      observedAt.Add(time.Second),
		SequenceFirst:    41,
	}, Emission{
		Events: []ConnectionEvent{{
			ObservedAt:         observedAt,
			UserID:             3224,
			SourceRef:          "source",
			DestinationAddress: "www.gstatic.com",
			DestinationKind:    DestinationDomain,
			DestinationPort:    443,
			Network:            NetworkTCP,
			AppProtocol:        AppProtocolTLS,
			SniffSource:        SniffTLSSNI,
			SniffConfidence:    ConfidenceHigh,
			ObservationKind:    ObservationKindDispatch,
		}},
		Sources: []SourceEnvelope{{
			SourceRef: "source",
			SourceIP:  "203.0.113.7",
		}},
	})
	if err != nil {
		t.Fatalf("AssembleBatch() error = %v", err)
	}
	if batch.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", batch.SchemaVersion)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(batch.Events))
	}
	if batch.Events[0].Sequence != 41 {
		t.Fatalf("Sequence = %d, want 41", batch.Events[0].Sequence)
	}
	if batch.Events[0].EventID == uuid.Nil {
		t.Fatal("EventID is nil")
	}

	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(body)
	for _, forbidden := range []string{"classifier_version", `"category"`, `"buckets"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("batch contains node-side derived field %q: %s", forbidden, encoded)
		}
	}
}

func TestAssembleBatchUsesConnectionEventsSchemaV2(t *testing.T) {
	streamID := uuid.MustParse("d3b30a72-222f-4b89-8d3e-cb0b9c9b8334")
	observedAt := time.Date(2026, 8, 3, 8, 15, 0, 0, time.UTC)

	batch, err := AssembleBatch(BatchParams{
		SchemaVersion:    2,
		ModeEpoch:        9,
		BatchID:          uuid.MustParse("019fb5e9-8fb7-76ce-bb63-b9e38b2d94c9"),
		StreamID:         streamID,
		NodeID:           7,
		CollectorVersion: "test",
		GeneratedAt:      observedAt.Add(time.Second),
		SequenceFirst:    41,
	}, Emission{
		Events: []ConnectionEvent{{
			ObservedAt:          observedAt,
			UserID:              3224,
			SourceRef:           "source",
			DestinationAddress:  "service.example.com",
			DestinationKind:     DestinationDomain,
			DestinationPort:     443,
			Network:             NetworkTCP,
			AppProtocol:         AppProtocolTLS,
			SniffSource:         SniffTLSSNI,
			SniffConfidence:     ConfidenceHigh,
			RuntimeListener:     "vless-inbound-7",
			RuntimeListenPort:   443,
			RuntimeSNI:          "service.example.com",
			RuntimeHTTPHost:     "",
			RuntimeProtocol:     AppProtocolTLS,
			InboundTag:          "vless-inbound-7",
			Outcome:             ConnectionOutcomeAccepted,
			FailureStage:        FailureStageNone,
			LatencyMilliseconds: 37,
			CompletenessStatus:  CompletenessReady,
			ObservationKind:     ObservationKindConnection,
		}},
		Sources: []SourceEnvelope{{
			SourceRef: "source",
			SourceIP:  "203.0.113.7",
		}},
	})
	if err != nil {
		t.Fatalf("AssembleBatch() error = %v", err)
	}
	if batch.SchemaVersion != 2 || batch.ModeEpoch != 9 {
		t.Fatalf("batch version/epoch = %d/%d, want 2/9", batch.SchemaVersion, batch.ModeEpoch)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(batch.Events))
	}
	event := batch.Events[0]
	if event.Outcome != ConnectionOutcomeAccepted ||
		event.RuntimeListener != "vless-inbound-7" ||
		event.LatencyMilliseconds != 37 {
		t.Fatalf("V2 event = %#v", event)
	}

	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(body)
	for _, required := range []string{
		`"mode_epoch":9`,
		`"runtime_listener":"vless-inbound-7"`,
		`"failure_stage":"none"`,
		`"outcome":"accepted"`,
		`"completeness_status":"ready"`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("batch missing %q: %s", required, encoded)
		}
	}
	for _, forbidden := range []string{"published_host", "published_endpoint_id"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("v2node fabricated FMPanel field %q: %s", forbidden, encoded)
		}
	}
}

func TestAssembleBatchRequiresAndCarriesLossReasonForUnknownOutcome(t *testing.T) {
	params := BatchParams{
		SchemaVersion:    2,
		ModeEpoch:        9,
		BatchID:          uuid.MustParse("019fb5e9-8fb7-76ce-bb63-b9e38b2d94c9"),
		StreamID:         uuid.MustParse("d3b30a72-222f-4b89-8d3e-cb0b9c9b8334"),
		NodeID:           7,
		CollectorVersion: "test",
		GeneratedAt:      time.Now().UTC(),
		SequenceFirst:    1,
	}
	event := ConnectionEvent{
		ObservedAt:         time.Now().UTC().Add(-time.Second),
		UserID:             42,
		SourceRef:          "source",
		DestinationAddress: "example.com",
		DestinationKind:    DestinationDomain,
		DestinationPort:    443,
		Network:            NetworkTCP,
		Outcome:            ConnectionOutcomeUnknown,
		FailureStage:       FailureStageOutbound,
		CompletenessStatus: CompletenessPartial,
		ObservationKind:    ObservationKindConnection,
	}
	emission := Emission{
		Events:  []ConnectionEvent{event},
		Sources: []SourceEnvelope{{SourceRef: "source", SourceIP: "203.0.113.7"}},
	}

	if _, err := AssembleBatch(params, emission); err == nil {
		t.Fatal("AssembleBatch() accepted unknown outcome without loss reason")
	}
	emission.Events[0].LossReason = LossReasonTerminalNotObservable
	batch, err := AssembleBatch(params, emission)
	if err != nil {
		t.Fatalf("AssembleBatch() error = %v", err)
	}
	if batch.Events[0].LossReason != LossReasonTerminalNotObservable {
		t.Fatalf("LossReason = %q", batch.Events[0].LossReason)
	}
}

func TestEventBufferRejectsMalformedDomain(t *testing.T) {
	buffer := NewEventBuffer(NewSourceProtector())
	if buffer.Observe(Observation{
		ObservedAt:  time.Now().UTC(),
		UserID:      42,
		NodeID:      7,
		SourceIP:    netip.MustParseAddr("203.0.113.7"),
		Destination: Destination{Address: "foo..example.com"},
	}) {
		t.Fatal("Observe() accepted malformed destination")
	}
}
