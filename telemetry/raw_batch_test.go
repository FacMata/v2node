package telemetry

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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
