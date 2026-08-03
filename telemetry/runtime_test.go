package telemetry

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuntimeSeparatesSchemaV2StateFromLegacyStream(t *testing.T) {
	directory := t.TempDir()
	legacyState := []byte(`{"version":1,"node_id":7,"stream_id":"019faeac-29dd-7d8d-a543-432b1e9bf0b8","next_sequence":180738}`)
	if err := os.WriteFile(
		filepath.Join(directory, streamStateFilename),
		legacyState,
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(legacy state) error = %v", err)
	}
	legacyQueue := filepath.Join(directory, "queue")
	if err := os.Mkdir(legacyQueue, 0o700); err != nil {
		t.Fatalf("Mkdir(legacy queue) error = %v", err)
	}
	legacyRecord := filepath.Join(legacyQueue, "legacy-record.tq")
	if err := os.WriteFile(legacyRecord, []byte("legacy"), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy record) error = %v", err)
	}

	config := RuntimeConfig{
		NodeID:           7,
		APIKey:           "server-api-key",
		Endpoint:         "http://127.0.0.1:1/telemetry",
		InitialControl:   &ControlState{CollectorEnabled: true, Mode: "observe", ModeEpoch: 1, ControlTTL: time.Minute},
		QueueDirectory:   directory,
		QueueMaxBytes:    1024 * 1024,
		QueueMaxAge:      time.Hour,
		CollectorVersion: "test",
		BufferSize:       16,
		FlushInterval:    time.Second,
		RequestTimeout:   time.Second,
		RetryMin:         time.Second,
		RetryMax:         2 * time.Second,
		ShutdownTimeout:  time.Second,
	}
	pipeline, err := OpenRuntimePipeline(config)
	if err != nil {
		t.Fatalf("OpenRuntimePipeline() error = %v", err)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	v2Directory := filepath.Join(directory, schemaV2StateDirectory)
	v2State, err := openStreamState(v2Directory, 7)
	if err != nil {
		t.Fatalf("openStreamState(v2) error = %v", err)
	}
	legacyStream := uuid.MustParse("019faeac-29dd-7d8d-a543-432b1e9bf0b8")
	if v2State.StreamID == legacyStream || v2State.NextSequence != 1 {
		t.Fatalf("v2 state = %#v", v2State)
	}
	if pipeline.queue.config.Directory != filepath.Join(v2Directory, "queue") {
		t.Fatalf("v2 queue directory = %q", pipeline.queue.config.Directory)
	}
	reopened, err := OpenRuntimePipeline(config)
	if err != nil {
		t.Fatalf("OpenRuntimePipeline(reopen) error = %v", err)
	}
	if reopened.state.StreamID != v2State.StreamID ||
		reopened.state.NextSequence != v2State.NextSequence {
		t.Fatalf("reopened v2 state = %#v, want %#v", reopened.state, v2State)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close(reopened) error = %v", err)
	}
	gotLegacyState, err := os.ReadFile(filepath.Join(directory, streamStateFilename))
	if err != nil {
		t.Fatalf("ReadFile(legacy state) error = %v", err)
	}
	if !bytes.Equal(gotLegacyState, legacyState) {
		t.Fatalf("legacy state changed: %q", gotLegacyState)
	}
	if got, err := os.ReadFile(legacyRecord); err != nil || string(got) != "legacy" {
		t.Fatalf("legacy queue changed: data=%q err=%v", got, err)
	}
}
