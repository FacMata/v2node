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
	maxBucketsPerBatch = 1000
	maxSourcesPerBatch = 256
	maxBatchJSONBytes  = 512 * 1024
)

type BatchParams struct {
	SchemaVersion     uint16
	BatchID           uuid.UUID
	NodeID            uint64
	StreamID          uuid.UUID
	GeneratedAt       time.Time
	CollectorVersion  string
	ClassifierVersion string
	SequenceFirst     uint64
	DroppedCount      uint64
}

type Batch struct {
	SchemaVersion                  uint16           `json:"schema_version"`
	BatchID                        string           `json:"batch_id"`
	NodeID                         uint64           `json:"node_id"`
	StreamID                       string           `json:"stream_id"`
	GeneratedAt                    MillisTime       `json:"generated_at"`
	CollectorVersion               string           `json:"collector_version"`
	ClassifierVersion              string           `json:"classifier_version"`
	SequenceFirst                  uint64           `json:"sequence_first"`
	SequenceLast                   uint64           `json:"sequence_last"`
	DroppedCountSincePreviousBatch uint64           `json:"dropped_count_since_previous_batch"`
	Sources                        []SourceEnvelope `json:"sources"`
	Buckets                        []WireBucket     `json:"buckets"`
}

type WireBucket struct {
	BucketID                string           `json:"bucket_id"`
	Sequence                uint64           `json:"sequence"`
	BucketStart             MillisTime       `json:"bucket_start"`
	UserID                  uint64           `json:"user_id"`
	SourceRef               string           `json:"source_ref"`
	DestinationClass        DestinationClass `json:"destination_class"`
	ProbeSignature          *string          `json:"probe_signature"`
	ProbeConfidence         Confidence       `json:"probe_confidence"`
	DestinationKind         DestinationKind  `json:"destination_kind"`
	DestinationPort         uint16           `json:"destination_port"`
	UnknownDestinationCount uint32           `json:"unknown_destination_count"`
	Network                 Network          `json:"network"`
	AppProtocol             AppProtocol      `json:"app_protocol"`
	SniffSource             SniffSource      `json:"sniff_source"`
	SniffConfidence         Confidence       `json:"sniff_confidence"`
	ConnectionCount         uint32           `json:"connection_count"`
	UploadBytes             uint64           `json:"upload_bytes"`
	DownloadBytes           uint64           `json:"download_bytes"`
	ActiveMilliseconds      uint64           `json:"active_milliseconds"`
	TransitionInCount       uint32           `json:"transition_in_count"`
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
	if params.CollectorVersion == "" || params.ClassifierVersion == "" {
		return Batch{}, fmt.Errorf("collector and classifier versions are required")
	}
	if len(emission.Buckets) == 0 {
		return Batch{}, fmt.Errorf("telemetry batch must contain buckets")
	}
	if len(emission.Buckets) > maxBucketsPerBatch {
		return Batch{}, fmt.Errorf("telemetry batch exceeds %d buckets", maxBucketsPerBatch)
	}
	if len(emission.Sources) == 0 || len(emission.Sources) > maxSourcesPerBatch {
		return Batch{}, fmt.Errorf("telemetry batch source count is out of bounds")
	}
	if uint64(len(emission.Buckets)-1) > math.MaxUint64-params.SequenceFirst {
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

	wireBuckets := make([]WireBucket, 0, len(emission.Buckets))
	usedSources := make(map[string]struct{}, len(emission.Sources))
	for i, bucket := range emission.Buckets {
		if bucket.ClassifierVersion != params.ClassifierVersion {
			return Batch{}, fmt.Errorf(
				"bucket classifier version %q does not match batch %q",
				bucket.ClassifierVersion,
				params.ClassifierVersion,
			)
		}
		if _, exists := sourceRefs[bucket.SourceRef]; !exists {
			return Batch{}, fmt.Errorf("bucket references unknown source %s", bucket.SourceRef)
		}
		usedSources[bucket.SourceRef] = struct{}{}

		var signature *string
		if bucket.DestinationClass == DestinationProbe {
			if bucket.ProbeSignature == "" {
				return Batch{}, fmt.Errorf("probe bucket signature is required")
			}
			value := bucket.ProbeSignature
			signature = &value
		}
		wireBuckets = append(wireBuckets, WireBucket{
			BucketID:                bucket.BucketID,
			Sequence:                params.SequenceFirst + uint64(i),
			BucketStart:             bucket.BucketStart,
			UserID:                  bucket.UserID,
			SourceRef:               bucket.SourceRef,
			DestinationClass:        bucket.DestinationClass,
			ProbeSignature:          signature,
			ProbeConfidence:         normalizeConfidence(bucket.ProbeConfidence),
			DestinationKind:         bucket.DestinationKind,
			DestinationPort:         bucket.DestinationPort,
			UnknownDestinationCount: bucket.UnknownDestinationCount,
			Network:                 normalizeNetwork(bucket.Network),
			AppProtocol:             normalizeAppProtocol(bucket.AppProtocol),
			SniffSource:             normalizeSniffSource(bucket.SniffSource),
			SniffConfidence:         normalizeConfidence(bucket.SniffConfidence),
			ConnectionCount:         bucket.ConnectionCount,
			UploadBytes:             bucket.UploadBytes,
			DownloadBytes:           bucket.DownloadBytes,
			ActiveMilliseconds:      bucket.ActiveMilliseconds,
			TransitionInCount:       bucket.TransitionInCount,
		})
	}
	if len(usedSources) != len(sourceRefs) {
		return Batch{}, fmt.Errorf("telemetry batch contains unused source")
	}

	sequenceLast := params.SequenceFirst + uint64(len(wireBuckets)) - 1
	batch := Batch{
		SchemaVersion:                  params.SchemaVersion,
		BatchID:                        params.BatchID.String(),
		NodeID:                         params.NodeID,
		StreamID:                       params.StreamID.String(),
		GeneratedAt:                    MillisTime{Time: params.GeneratedAt.UTC()},
		CollectorVersion:               params.CollectorVersion,
		ClassifierVersion:              params.ClassifierVersion,
		SequenceFirst:                  params.SequenceFirst,
		SequenceLast:                   sequenceLast,
		DroppedCountSincePreviousBatch: params.DroppedCount,
		Sources:                        append([]SourceEnvelope(nil), emission.Sources...),
		Buckets:                        wireBuckets,
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
