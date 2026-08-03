package core

import (
	"sync"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/telemetry"
)

type telemetryAdapter struct {
	users *UserMap
	nodes map[string]uint64
	sink  telemetry.Sink

	misconfiguredOnce sync.Once
	unknownUserOnce   sync.Once
	unknownNodeOnce   sync.Once
	sinkRejectedOnce  sync.Once
}

func newTelemetryAdapter(
	users *UserMap,
	nodes []*panel.NodeInfo,
	sink telemetry.Sink,
) *telemetryAdapter {
	nodeIDs := make(map[string]uint64, len(nodes))
	for _, node := range nodes {
		if node != nil && node.Id > 0 && node.Tag != "" {
			nodeIDs[node.Tag] = uint64(node.Id)
		}
	}
	return &telemetryAdapter{
		users: users,
		nodes: nodeIDs,
		sink:  sink,
	}
}

func (a *telemetryAdapter) ObserveRaw(raw telemetry.RawObservation) bool {
	if a == nil {
		return false
	}
	if a.users == nil || a.sink == nil {
		a.misconfiguredOnce.Do(func() {
			log.Warn("Telemetry observation dropped: adapter is unavailable")
		})
		return false
	}
	userID, ok := a.users.ResolveUser(raw.UserEmail)
	if !ok {
		a.unknownUserOnce.Do(func() {
			log.Warn("Telemetry observation dropped: user identity could not be resolved")
		})
		return false
	}
	nodeID, ok := a.nodes[raw.InboundTag]
	if !ok {
		a.unknownNodeOnce.Do(func() {
			log.Warn("Telemetry observation dropped: node identity could not be resolved")
		})
		return false
	}
	accepted := a.sink.Observe(telemetry.Observation{
		ObservedAt:          raw.ObservedAt,
		UserID:              userID,
		NodeID:              nodeID,
		SourceIP:            raw.SourceIP,
		Destination:         raw.Destination,
		Network:             raw.Network,
		AppProtocol:         raw.AppProtocol,
		SniffSource:         raw.SniffSource,
		Confidence:          raw.Confidence,
		UploadBytes:         raw.UploadBytes,
		DownloadBytes:       raw.DownloadBytes,
		ActiveMillis:        raw.ActiveMillis,
		RuntimeListener:     raw.RuntimeListener,
		RuntimeListenPort:   raw.RuntimeListenPort,
		RuntimeSNI:          raw.RuntimeSNI,
		RuntimeProtocol:     raw.RuntimeProtocol,
		InboundTag:          raw.InboundTag,
		Outcome:             raw.Outcome,
		FailureStage:        raw.FailureStage,
		LossReason:          raw.LossReason,
		LatencyMilliseconds: raw.LatencyMilliseconds,
		CompletenessStatus:  raw.CompletenessStatus,
	})
	if !accepted {
		a.sinkRejectedOnce.Do(func() {
			log.Warn("Telemetry observation dropped: collector rejected the event")
		})
	}
	return accepted
}

func (u *UserMap) ResolveUser(email string) (uint64, bool) {
	if u == nil || email == "" {
		return 0, false
	}
	u.mapLock.RLock()
	defer u.mapLock.RUnlock()
	userID := u.uidMap[email]
	if userID <= 0 {
		return 0, false
	}
	return uint64(userID), true
}
