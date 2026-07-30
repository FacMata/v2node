package telemetry

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

const (
	maxEventsPerBatch  = 1000
	maxSourcesPerBatch = 256
	maxBatchJSONBytes  = 512 * 1024
)

var eventNamespace = uuid.MustParse("1527fc78-b14e-46d6-9c2e-4e680e22abf8")

type BatchParams struct {
	SchemaVersion    uint16
	BatchID          uuid.UUID
	NodeID           uint64
	StreamID         uuid.UUID
	GeneratedAt      time.Time
	CollectorVersion string
	SequenceFirst    uint64
	DroppedCount     uint64
}

type Batch struct {
	SchemaVersion                  uint16           `json:"schema_version"`
	BatchID                        string           `json:"batch_id"`
	NodeID                         uint64           `json:"node_id"`
	StreamID                       string           `json:"stream_id"`
	GeneratedAt                    MillisTime       `json:"generated_at"`
	CollectorVersion               string           `json:"collector_version"`
	SequenceFirst                  uint64           `json:"sequence_first"`
	SequenceLast                   uint64           `json:"sequence_last"`
	DroppedCountSincePreviousBatch uint64           `json:"dropped_count_since_previous_batch"`
	Sources                        []SourceEnvelope `json:"sources"`
	Events                         []WireEvent      `json:"events"`
}

type WireEvent struct {
	EventID            uuid.UUID       `json:"event_id"`
	Sequence           uint64          `json:"sequence"`
	ObservedAt         MillisTime      `json:"observed_at"`
	UserID             uint64          `json:"user_id"`
	SourceRef          string          `json:"source_ref"`
	DestinationAddress string          `json:"destination_address"`
	DestinationKind    DestinationKind `json:"destination_kind"`
	DestinationPort    uint16          `json:"destination_port"`
	Network            Network         `json:"network"`
	AppProtocol        AppProtocol     `json:"app_protocol"`
	SniffSource        SniffSource     `json:"sniff_source"`
	SniffConfidence    Confidence      `json:"sniff_confidence"`
	UploadBytes        uint64          `json:"upload_bytes"`
	DownloadBytes      uint64          `json:"download_bytes"`
	ActiveMilliseconds uint64          `json:"active_milliseconds"`
	ObservationKind    ObservationKind `json:"observation_kind"`
}

func AssembleBatch(params BatchParams, emission Emission) (Batch, error) {
	if params.SchemaVersion != 1 {
		return Batch{}, fmt.Errorf("unsupported telemetry schema version %d", params.SchemaVersion)
	}
	if params.BatchID == uuid.Nil || params.StreamID == uuid.Nil {
		return Batch{}, fmt.Errorf("batch and stream IDs are required")
	}
	if params.NodeID == 0 || params.SequenceFirst == 0 {
		return Batch{}, fmt.Errorf("node ID and first sequence are required")
	}
	if params.GeneratedAt.IsZero() {
		return Batch{}, fmt.Errorf("generated timestamp is required")
	}
	if params.CollectorVersion == "" {
		return Batch{}, fmt.Errorf("collector version is required")
	}
	if len(emission.Events) == 0 {
		return Batch{}, fmt.Errorf("telemetry batch must contain events")
	}
	if len(emission.Events) > maxEventsPerBatch {
		return Batch{}, fmt.Errorf("telemetry batch exceeds %d events", maxEventsPerBatch)
	}
	if len(emission.Sources) == 0 || len(emission.Sources) > maxSourcesPerBatch {
		return Batch{}, fmt.Errorf("telemetry batch source count is out of bounds")
	}
	if uint64(len(emission.Events)-1) > math.MaxUint64-params.SequenceFirst {
		return Batch{}, fmt.Errorf("telemetry sequence range overflows")
	}

	sourceRefs := make(map[string]struct{}, len(emission.Sources))
	for _, source := range emission.Sources {
		if source.SourceRef == "" {
			return Batch{}, fmt.Errorf("source ref is required")
		}
		if _, err := netip.ParseAddr(source.SourceIP); err != nil {
			return Batch{}, fmt.Errorf("source IP is invalid")
		}
		if _, exists := sourceRefs[source.SourceRef]; exists {
			return Batch{}, fmt.Errorf("duplicate source ref %s", source.SourceRef)
		}
		sourceRefs[source.SourceRef] = struct{}{}
	}

	wireEvents := make([]WireEvent, 0, len(emission.Events))
	usedSources := make(map[string]struct{}, len(emission.Sources))
	for i, event := range emission.Events {
		if event.ObservedAt.IsZero() || event.UserID == 0 {
			return Batch{}, fmt.Errorf("event timestamp and user ID are required")
		}
		if _, exists := sourceRefs[event.SourceRef]; !exists {
			return Batch{}, fmt.Errorf("event references unknown source %s", event.SourceRef)
		}
		if event.DestinationAddress == "" {
			return Batch{}, fmt.Errorf("event destination is required")
		}
		sequence := params.SequenceFirst + uint64(i)
		usedSources[event.SourceRef] = struct{}{}
		wireEvents = append(wireEvents, WireEvent{
			EventID:            uuid.NewSHA1(eventNamespace, []byte(params.StreamID.String()+"|"+fmt.Sprint(sequence))),
			Sequence:           sequence,
			ObservedAt:         MillisTime{Time: event.ObservedAt.UTC()},
			UserID:             event.UserID,
			SourceRef:          event.SourceRef,
			DestinationAddress: event.DestinationAddress,
			DestinationKind:    event.DestinationKind,
			DestinationPort:    event.DestinationPort,
			Network:            normalizeNetwork(event.Network),
			AppProtocol:        normalizeAppProtocol(event.AppProtocol),
			SniffSource:        normalizeSniffSource(event.SniffSource),
			SniffConfidence:    normalizeConfidence(event.SniffConfidence),
			UploadBytes:        event.UploadBytes,
			DownloadBytes:      event.DownloadBytes,
			ActiveMilliseconds: event.ActiveMilliseconds,
			ObservationKind:    event.ObservationKind,
		})
	}
	if len(usedSources) != len(sourceRefs) {
		return Batch{}, fmt.Errorf("telemetry batch contains unused source")
	}

	batch := Batch{
		SchemaVersion:                  params.SchemaVersion,
		BatchID:                        params.BatchID.String(),
		NodeID:                         params.NodeID,
		StreamID:                       params.StreamID.String(),
		GeneratedAt:                    MillisTime{Time: params.GeneratedAt.UTC()},
		CollectorVersion:               params.CollectorVersion,
		SequenceFirst:                  params.SequenceFirst,
		SequenceLast:                   params.SequenceFirst + uint64(len(wireEvents)) - 1,
		DroppedCountSincePreviousBatch: params.DroppedCount,
		Sources:                        append([]SourceEnvelope(nil), emission.Sources...),
		Events:                         wireEvents,
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return Batch{}, fmt.Errorf("marshal telemetry batch: %w", err)
	}
	if len(encoded) > maxBatchJSONBytes {
		return Batch{}, fmt.Errorf("telemetry batch exceeds %d bytes", maxBatchJSONBytes)
	}
	return batch, nil
}
