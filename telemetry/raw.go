package telemetry

import (
	"net/netip"
	"time"
)

type RawSink interface {
	ObserveRaw(RawObservation) bool
}

type RawObservation struct {
	ObservedAt    time.Time
	InboundTag    string
	UserEmail     string
	SourceIP      netip.Addr
	Destination   Destination
	Network       Network
	AppProtocol   AppProtocol
	SniffSource   SniffSource
	Confidence    Confidence
	UploadBytes   uint64
	DownloadBytes uint64
	ActiveMillis  uint64
}
