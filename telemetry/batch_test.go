package telemetry

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAssembleBatchAssignsContiguousSequenceAndExactWireShape(t *testing.T) {
	probe := "cloudflare_one_http"
	emission := Emission{
		Sources: []SourceEnvelope{{
			SourceRef:         "31h2E5m-v7jJ9lJY5fM6yw",
			SealedIP:          "c2VhbGVk",
			SealingKeyVersion: 3,
		}},
		Buckets: []Bucket{
			{
				BucketID:          "e82a6013-556f-50be-8004-02dc9a4c1d5d",
				BucketStart:       MillisTime{Time: time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)},
				UserID:            42,
				SourceRef:         "31h2E5m-v7jJ9lJY5fM6yw",
				DestinationClass:  DestinationProbe,
				ProbeSignature:    probe,
				ProbeConfidence:   ConfidenceHigh,
				DestinationKind:   DestinationIPv4,
				DestinationPort:   80,
				Network:           NetworkTCP,
				AppProtocol:       AppProtocolHTTP,
				SniffSource:       SniffOriginal,
				SniffConfidence:   ConfidenceHigh,
				ConnectionCount:   2,
				ClassifierVersion: "2026-07-29.1",
			},
			{
				BucketID:                "286e0d22-b803-5ff4-9b30-44be9f16c4cb",
				BucketStart:             MillisTime{Time: time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)},
				UserID:                  42,
				SourceRef:               "31h2E5m-v7jJ9lJY5fM6yw",
				DestinationClass:        DestinationOther,
				ProbeConfidence:         ConfidenceUnknown,
				DestinationKind:         DestinationDomain,
				DestinationPort:         443,
				UnknownDestinationCount: 3,
				Network:                 NetworkTCP,
				AppProtocol:             AppProtocolTLS,
				SniffSource:             SniffTLSSNI,
				SniffConfidence:         ConfidenceHigh,
				ConnectionCount:         3,
				ClassifierVersion:       "2026-07-29.1",
			},
		},
	}

	batch, err := AssembleBatch(BatchParams{
		SchemaVersion:     1,
		BatchID:           uuid.MustParse("019fb0c6-ff80-7b22-9202-b7a6c11a6b88"),
		NodeID:            7,
		StreamID:          uuid.MustParse("019fb0c0-2b0d-7e3c-b9bd-d2dc946d3325"),
		GeneratedAt:       time.Date(2026, 7, 29, 1, 1, 0, 0, time.UTC),
		CollectorVersion:  "1.0.0",
		ClassifierVersion: "2026-07-29.1",
		SequenceFirst:     1001,
		DroppedCount:      4,
	}, emission)
	if err != nil {
		t.Fatalf("AssembleBatch() error = %v", err)
	}

	if batch.SequenceFirst != 1001 || batch.SequenceLast != 1002 {
		t.Fatalf("sequence range = %d..%d", batch.SequenceFirst, batch.SequenceLast)
	}
	if batch.Buckets[0].Sequence != 1001 || batch.Buckets[1].Sequence != 1002 {
		t.Fatalf("bucket sequences = %d, %d", batch.Buckets[0].Sequence, batch.Buckets[1].Sequence)
	}

	encoded, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	buckets := decoded["buckets"].([]any)
	first := buckets[0].(map[string]any)
	second := buckets[1].(map[string]any)
	if first["probe_signature"] != probe {
		t.Fatalf("probe signature = %#v", first["probe_signature"])
	}
	if second["probe_signature"] != nil {
		t.Fatalf("other probe signature = %#v, want null", second["probe_signature"])
	}
	if decoded["dropped_count_since_previous_batch"] != float64(4) {
		t.Fatalf("dropped count = %#v", decoded["dropped_count_since_previous_batch"])
	}
}

func TestAssembleBatchRejectsMixedClassifierVersions(t *testing.T) {
	emission := Emission{
		Sources: []SourceEnvelope{{SourceRef: "source"}},
		Buckets: []Bucket{
			{BucketID: uuid.NewString(), SourceRef: "source", ClassifierVersion: "v1"},
			{BucketID: uuid.NewString(), SourceRef: "source", ClassifierVersion: "v2"},
		},
	}
	_, err := AssembleBatch(BatchParams{
		SchemaVersion:     1,
		BatchID:           uuid.New(),
		NodeID:            7,
		StreamID:          uuid.New(),
		CollectorVersion:  "1.0.0",
		ClassifierVersion: "v1",
		SequenceFirst:     1,
	}, emission)
	if err == nil {
		t.Fatal("AssembleBatch() error = nil, want classifier mismatch")
	}
}

func TestAssembleBatchEnforcesEnvelopeBounds(t *testing.T) {
	source := SourceEnvelope{SourceRef: "source"}
	bucket := Bucket{
		BucketID:          uuid.NewString(),
		SourceRef:         source.SourceRef,
		ClassifierVersion: "v1",
	}
	params := BatchParams{
		SchemaVersion:     1,
		BatchID:           uuid.New(),
		NodeID:            7,
		StreamID:          uuid.New(),
		GeneratedAt:       time.Now().UTC(),
		CollectorVersion:  "1.0.0",
		ClassifierVersion: "v1",
		SequenceFirst:     1,
	}

	tooMany := make([]Bucket, maxBucketsPerBatch+1)
	for i := range tooMany {
		tooMany[i] = bucket
		tooMany[i].BucketID = uuid.NewString()
	}
	if _, err := AssembleBatch(params, Emission{Sources: []SourceEnvelope{source}, Buckets: tooMany}); err == nil {
		t.Fatal("AssembleBatch() accepted too many buckets")
	}

	params.SequenceFirst = math.MaxUint64
	if _, err := AssembleBatch(params, Emission{
		Sources: []SourceEnvelope{source},
		Buckets: []Bucket{bucket, bucket},
	}); err == nil {
		t.Fatal("AssembleBatch() accepted overflowing sequence")
	}

	params.SequenceFirst = 1
	source.SealedIP = strings.Repeat("a", maxBatchJSONBytes)
	if _, err := AssembleBatch(params, Emission{
		Sources: []SourceEnvelope{source},
		Buckets: []Bucket{bucket},
	}); err == nil {
		t.Fatal("AssembleBatch() accepted oversized JSON")
	}
}
