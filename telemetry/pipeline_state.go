package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const pipelineStateVersion = 1

type pipelineControlState struct {
	CollectorEnabled bool   `json:"collector_enabled"`
	Mode             string `json:"mode"`
	ModeEpoch        uint64 `json:"mode_epoch"`
	ControlTTLMS     int64  `json:"control_ttl_ms"`
	ExpiresAtMS      int64  `json:"expires_at_ms"`
}

type pipelineStateDocument struct {
	Version        int                   `json:"version"`
	NodeID         uint64                `json:"node_id"`
	PendingDropped uint64                `json:"pending_dropped"`
	Control        *pipelineControlState `json:"control,omitempty"`
}

type persistentPipelineState struct {
	mu       sync.Mutex
	path     string
	document pipelineStateDocument
}

func openPersistentPipelineState(directory string, nodeID uint64) (*persistentPipelineState, error) {
	if directory == "" || nodeID == 0 {
		return nil, fmt.Errorf("pipeline state directory and node ID are required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create pipeline state directory: %w", err)
	}
	path := filepath.Join(directory, fmt.Sprintf("pipeline-state-%d.json", nodeID))
	state := &persistentPipelineState{
		path: path,
		document: pipelineStateDocument{
			Version: pipelineStateVersion,
			NodeID:  nodeID,
		},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pipeline state: %w", err)
	}
	if err := json.Unmarshal(data, &state.document); err != nil {
		return nil, fmt.Errorf("decode pipeline state: %w", err)
	}
	if state.document.Version != pipelineStateVersion || state.document.NodeID != nodeID {
		return nil, fmt.Errorf("pipeline state identity or version mismatch")
	}
	if control := state.document.Control; control != nil {
		if control.ModeEpoch == 0 || control.ControlTTLMS <= 0 ||
			(control.Mode != "off" && control.Mode != "observe" &&
				control.Mode != "auto_protect") ||
			(control.Mode == "off" && control.CollectorEnabled) {
			return nil, fmt.Errorf("persisted pipeline control is invalid")
		}
	}
	return state, nil
}

func (s *persistentPipelineState) initialControl() (ControlState, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	control := s.document.Control
	if control == nil {
		return ControlState{}, time.Time{}, false
	}
	return ControlState{
		CollectorEnabled: control.CollectorEnabled,
		Mode:             control.Mode,
		ModeEpoch:        control.ModeEpoch,
		ControlTTL:       time.Duration(control.ControlTTLMS) * time.Millisecond,
	}, time.UnixMilli(control.ExpiresAtMS), true
}

func (s *persistentPipelineState) saveControl(control ControlState, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.document.Control
	s.document.Control = &pipelineControlState{
		CollectorEnabled: control.CollectorEnabled,
		Mode:             control.Mode,
		ModeEpoch:        control.ModeEpoch,
		ControlTTLMS:     control.ControlTTL.Milliseconds(),
		ExpiresAtMS:      expiresAt.UnixMilli(),
	}
	if err := s.persistLocked(); err != nil {
		s.document.Control = previous
		return err
	}
	return nil
}

func (s *persistentPipelineState) addDropped(count uint64) error {
	if count == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.document.PendingDropped += count
	return s.persistLocked()
}

func (s *persistentPipelineState) takeDropped() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := s.document.PendingDropped
	if count == 0 {
		return 0, nil
	}
	s.document.PendingDropped = 0
	if err := s.persistLocked(); err != nil {
		s.document.PendingDropped = count
		return 0, err
	}
	return count, nil
}

func (s *persistentPipelineState) pendingDropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.document.PendingDropped
}

func (s *persistentPipelineState) persistLocked() error {
	data, err := json.Marshal(s.document)
	if err != nil {
		return fmt.Errorf("encode pipeline state: %w", err)
	}
	if err := atomicWriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("persist pipeline state: %w", err)
	}
	return nil
}
