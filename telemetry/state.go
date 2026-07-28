package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

const streamStateFilename = "stream-state.json"

type streamStateFile struct {
	Version      uint16 `json:"version"`
	NodeID       uint64 `json:"node_id"`
	StreamID     string `json:"stream_id"`
	NextSequence uint64 `json:"next_sequence"`
}

type streamState struct {
	mu           sync.Mutex
	path         string
	NodeID       uint64
	StreamID     uuid.UUID
	NextSequence uint64
}

func openStreamState(directory string, nodeID uint64) (*streamState, error) {
	if directory == "" || nodeID == 0 {
		return nil, fmt.Errorf("stream state directory and node ID are required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create stream state directory: %w", err)
	}
	path := filepath.Join(directory, streamStateFilename)
	data, err := os.ReadFile(path)
	if errorsIsNotExist(err) {
		streamID, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("generate stream ID: %w", err)
		}
		state := &streamState{
			path:         path,
			NodeID:       nodeID,
			StreamID:     streamID,
			NextSequence: 1,
		}
		if err := state.persistLocked(); err != nil {
			return nil, err
		}
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read stream state: %w", err)
	}
	var stored streamStateFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decode stream state: %w", err)
	}
	streamID, err := uuid.Parse(stored.StreamID)
	if err != nil || stored.Version != 1 || stored.NodeID != nodeID || stored.NextSequence == 0 {
		return nil, fmt.Errorf("stream state is invalid")
	}
	return &streamState{
		path:         path,
		NodeID:       nodeID,
		StreamID:     streamID,
		NextSequence: stored.NextSequence,
	}, nil
}

func (s *streamState) snapshot() (uuid.UUID, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.StreamID, s.NextSequence
}

func (s *streamState) advance(sequenceLast uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequenceLast < s.NextSequence {
		return fmt.Errorf("stream sequence cannot move backwards")
	}
	s.NextSequence = sequenceLast + 1
	if s.NextSequence == 0 {
		return fmt.Errorf("stream sequence overflow")
	}
	return s.persistLocked()
}

func (s *streamState) reconcile(queueSequenceLast uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if queueSequenceLast < s.NextSequence {
		return nil
	}
	if queueSequenceLast == ^uint64(0) {
		return fmt.Errorf("stream sequence overflow")
	}
	s.NextSequence = queueSequenceLast + 1
	return s.persistLocked()
}

func (s *streamState) persistLocked() error {
	data, err := json.Marshal(streamStateFile{
		Version:      1,
		NodeID:       s.NodeID,
		StreamID:     s.StreamID.String(),
		NextSequence: s.NextSequence,
	})
	if err != nil {
		return fmt.Errorf("encode stream state: %w", err)
	}
	return atomicWriteFile(s.path, data, 0o600)
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
