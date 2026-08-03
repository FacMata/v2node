package telemetry

import (
	"net/netip"
	"time"
)

type RawSink interface {
	ObserveRaw(RawObservation) bool
}

type RawObservation struct {
	ObservedAt          time.Time
	InboundTag          string
	UserEmail           string
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
	Outcome             ConnectionOutcome
	FailureStage        FailureStage
	LossReason          LossReason
	LatencyMilliseconds uint64
	CompletenessStatus  CompletenessStatus
}
