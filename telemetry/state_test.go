package telemetry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestStreamStatePersistsAndReconcilesQueueSequence(t *testing.T) {
	directory := t.TempDir()
	state, err := openStreamState(directory, 7)
	if err != nil {
		t.Fatalf("openStreamState() error = %v", err)
	}
	if state.StreamID == uuid.Nil || state.NextSequence != 1 {
		t.Fatalf("initial state = %#v", state)
	}
	streamID := state.StreamID
	if err := state.advance(9); err != nil {
		t.Fatalf("advance() error = %v", err)
	}

	reopened, err := openStreamState(directory, 7)
	if err != nil {
		t.Fatalf("reopen state error = %v", err)
	}
	if reopened.StreamID != streamID || reopened.NextSequence != 10 {
		t.Fatalf("reopened state = %#v", reopened)
	}
	if err := reopened.reconcile(15); err != nil {
		t.Fatalf("reconcile() error = %v", err)
	}
	if reopened.NextSequence != 16 {
		t.Fatalf("next sequence = %d, want 16", reopened.NextSequence)
	}

	info, err := os.Stat(filepath.Join(directory, streamStateFilename))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
}
