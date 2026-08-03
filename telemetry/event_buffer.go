package telemetry

import (
	"sort"
	"sync"
	"time"
)

const (
	maxPendingEvents      = 32768
	maxEventsPerEmission  = 300
	maxSourcesPerEmission = 256
)

type ObservationKind string

const (
	ObservationKindDispatch   ObservationKind = "dispatch"
	ObservationKindConnection ObservationKind = "connection"
)

type ConnectionEvent struct {
	ObservedAt          time.Time
	UserID              uint64
	SourceRef           string
	DestinationAddress  string
	DestinationKind     DestinationKind
	DestinationPort     uint16
	Network             Network
	AppProtocol         AppProtocol
	SniffSource         SniffSource
	SniffConfidence     Confidence
	UploadBytes         uint64
	DownloadBytes       uint64
	ActiveMilliseconds  uint64
	RuntimeListener     string
	RuntimeListenPort   uint16
	RuntimeSNI          string
	RuntimeHTTPHost     string
	RuntimeProtocol     AppProtocol
	InboundTag          string
	Outcome             ConnectionOutcome
	FailureStage        FailureStage
	LossReason          LossReason
	LatencyMilliseconds uint64
	CompletenessStatus  CompletenessStatus
	ObservationKind     ObservationKind
}

type protectedEvent struct {
	event  ConnectionEvent
	source ProtectedSource
}

type EventBuffer struct {
	mu        sync.Mutex
	protector *SourceProtector
	pending   []protectedEvent
}

func NewEventBuffer(protector *SourceProtector) *EventBuffer {
	return &EventBuffer{protector: protector}
}

func (b *EventBuffer) Observe(observation Observation) bool {
	if observation.ObservedAt.IsZero() ||
		observation.UserID == 0 ||
		observation.NodeID == 0 ||
		!observation.SourceIP.IsValid() ||
		b.protector == nil {
		return false
	}
	source, err := b.protector.Protect(observation.SourceIP)
	if err != nil {
		return false
	}
	address, kind, err := normalizeDestination(observation.Destination.Address)
	if err != nil {
		return false
	}
	observationKind := ObservationKindDispatch
	completeness := observation.CompletenessStatus
	if observation.Outcome != "" || completeness != "" {
		observationKind = ObservationKindConnection
		completeness = normalizeCompleteness(completeness)
	}

	event := ConnectionEvent{
		ObservedAt:          observation.ObservedAt.UTC(),
		UserID:              observation.UserID,
		SourceRef:           source.Ref,
		DestinationAddress:  address,
		DestinationKind:     kind,
		DestinationPort:     observation.Destination.Port,
		Network:             normalizeNetwork(observation.Network),
		AppProtocol:         normalizeAppProtocol(observation.AppProtocol),
		SniffSource:         normalizeSniffSource(observation.SniffSource),
		SniffConfidence:     normalizeConfidence(observation.Confidence),
		UploadBytes:         observation.UploadBytes,
		DownloadBytes:       observation.DownloadBytes,
		ActiveMilliseconds:  observation.ActiveMillis,
		RuntimeListener:     observation.RuntimeListener,
		RuntimeListenPort:   observation.RuntimeListenPort,
		RuntimeSNI:          observation.RuntimeSNI,
		RuntimeHTTPHost:     observation.RuntimeHTTPHost,
		RuntimeProtocol:     normalizeAppProtocol(observation.RuntimeProtocol),
		InboundTag:          observation.InboundTag,
		Outcome:             normalizeConnectionOutcome(observation.Outcome),
		FailureStage:        normalizeFailureStage(observation.FailureStage),
		LossReason:          observation.LossReason,
		LatencyMilliseconds: observation.LatencyMilliseconds,
		CompletenessStatus:  completeness,
		ObservationKind:     observationKind,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) >= maxPendingEvents {
		return false
	}
	b.pending = append(b.pending, protectedEvent{event: event, source: source})
	return true
}

func (b *EventBuffer) Flush() Emission {
	b.mu.Lock()
	defer b.mu.Unlock()

	sources := make(map[string]SourceEnvelope)
	events := make([]ConnectionEvent, 0, maxEventsPerEmission)
	consumed := 0
	for _, pending := range b.pending {
		_, sourceIncluded := sources[pending.source.Ref]
		if len(events) >= maxEventsPerEmission ||
			(!sourceIncluded && len(sources) >= maxSourcesPerEmission) {
			break
		}
		if !sourceIncluded {
			sources[pending.source.Ref] = SourceEnvelope{
				SourceRef: pending.source.Ref,
				SourceIP:  pending.source.IP,
			}
		}
		events = append(events, pending.event)
		consumed++
	}
	if consumed == 0 {
		return Emission{}
	}
	b.pending = append([]protectedEvent(nil), b.pending[consumed:]...)

	sourceList := make([]SourceEnvelope, 0, len(sources))
	for _, source := range sources {
		sourceList = append(sourceList, source)
	}
	sort.Slice(sourceList, func(i, j int) bool {
		return sourceList[i].SourceRef < sourceList[j].SourceRef
	})
	return Emission{Sources: sourceList, Events: events}
}
