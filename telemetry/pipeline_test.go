package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestPipelineQueuesSendsAndAcknowledgesBatch(t *testing.T) {
	received := make(chan Batch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
			return
		}
		var batch Batch
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("Unmarshal() error = %v", err)
			return
		}
		received <- batch
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"accepted":  len(batch.Events),
				"duplicate": false,
			},
		})
	}))
	defer server.Close()

	directory := t.TempDir()
	pipeline := newTestPipeline(t, directory, server.URL)
	pipeline.Start(context.Background())
	if !pipeline.Observe(Observation{
		ObservedAt:  time.Now().UTC().Add(-2 * time.Minute),
		UserID:      42,
		NodeID:      7,
		SourceIP:    netip.MustParseAddr("1.2.3.4"),
		Destination: Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP},
		Network:     NetworkTCP,
		AppProtocol: AppProtocolHTTP,
	}) {
		t.Fatal("Observe() rejected")
	}

	select {
	case batch := <-received:
		if batch.NodeID != 7 || len(batch.Events) != 1 || batch.SequenceFirst != 1 {
			t.Fatalf("batch = %#v", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not send batch")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := pipeline.queue.Peek(); err == ErrQueueEmpty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pipeline did not acknowledge queue record")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	state, err := openStreamState(directory, 7)
	if err != nil {
		t.Fatalf("openStreamState() error = %v", err)
	}
	if state.NextSequence != 2 {
		t.Fatalf("next sequence = %d, want 2", state.NextSequence)
	}
}

func TestPipelineLogsPermanentServerRejectionOnce(t *testing.T) {
	logger := log.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
	previousLevel := logger.GetLevel()
	previousOutput := logger.Out
	t.Cleanup(func() {
		logger.ReplaceHooks(previousHooks)
		logger.SetLevel(previousLevel)
		logger.SetOutput(previousOutput)
	})
	logger.SetLevel(log.WarnLevel)
	logger.SetOutput(io.Discard)
	hook := logtest.NewGlobal()

	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"code":"TELEMETRY_STREAM_SCHEMA_CONFLICT"}`)
	}))
	defer server.Close()

	pipeline := newTestPipeline(t, t.TempDir(), server.URL)
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: true,
		Mode:             "observe",
		ModeEpoch:        1,
		ControlTTL:       time.Minute,
	}); err != nil {
		t.Fatalf("ApplyControl() error = %v", err)
	}
	pipeline.Start(context.Background())
	observe := func() {
		t.Helper()
		if !pipeline.Observe(Observation{
			ObservedAt:         time.Now().UTC(),
			UserID:             42,
			NodeID:             7,
			SourceIP:           netip.MustParseAddr("1.2.3.4"),
			Destination:        Destination{Address: "1.1.1.1", Port: 443, Kind: DestinationIPv4},
			Network:            NetworkTCP,
			Outcome:            ConnectionOutcomeAccepted,
			FailureStage:       FailureStageNone,
			CompletenessStatus: CompletenessReady,
		}) {
			t.Fatal("Observe() rejected")
		}
	}

	observe()
	deadline := time.Now().Add(2 * time.Second)
	for pipeline.QuarantinedCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pipeline.QuarantinedCount() < 1 {
		t.Fatal("first permanently rejected batch was not quarantined")
	}
	observe()
	deadline = time.Now().Add(2 * time.Second)
	for pipeline.QuarantinedCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pipeline.QuarantinedCount() < 2 {
		t.Fatal("second permanently rejected batch was not quarantined")
	}
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	entries := hook.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("warning count = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Message != "Telemetry batch quarantined after permanent server rejection" ||
		entry.Data["node_id"] != uint64(7) ||
		entry.Data["status"] != http.StatusConflict ||
		entry.Data["code"] != "TELEMETRY_STREAM_SCHEMA_CONFLICT" {
		t.Fatalf("warning entry = %#v", entry)
	}
}

func newTestPipeline(t *testing.T, directory, endpoint string) *Pipeline {
	t.Helper()
	state, err := openStreamState(directory, 7)
	if err != nil {
		t.Fatalf("openStreamState() error = %v", err)
	}
	queue, err := OpenDiskQueue(QueueConfig{
		Directory:       filepath.Join(directory, "queue"),
		NodeID:          7,
		StreamID:        state.StreamID,
		WriteKeyVersion: 1,
		Keys:            map[uint16][]byte{1: bytes.Repeat([]byte{2}, 32)},
		MaxBytes:        1024 * 1024,
		MaxAge:          6 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDiskQueue() error = %v", err)
	}
	sender, err := NewSender(SenderConfig{
		Endpoint: endpoint,
		Timeout:  time.Second,
		NodeID:   7,
		APIKey:   "server-api-key",
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	pipeline, err := NewPipeline(PipelineConfig{
		NodeID:           7,
		CollectorVersion: "test",
		StateDirectory:   directory,
		BufferSize:       16,
		FlushInterval:    5 * time.Millisecond,
		RetryMin:         5 * time.Millisecond,
		RetryMax:         20 * time.Millisecond,
		ShutdownTimeout:  100 * time.Millisecond,
	}, NewEventBuffer(NewSourceProtector()), queue, sender)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}
	return pipeline
}

func TestManagerRoutesByNodeID(t *testing.T) {
	manager := &Manager{pipelines: map[uint64]*Pipeline{}}
	if manager.Observe(Observation{NodeID: 999}) {
		t.Fatal("Observe() accepted unknown node")
	}
}

func TestPipelineKeepsQueuedBatchWhenStatePersistFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	directory := t.TempDir()
	pipeline := newTestPipeline(t, directory, server.URL)
	pipeline.state.path = directory

	emission := Emission{
		Sources: []SourceEnvelope{{
			SourceRef: "source",
			SourceIP:  "1.2.3.4",
		}},
		Events: []ConnectionEvent{{
			ObservedAt:         time.Now().UTC(),
			UserID:             42,
			SourceRef:          "source",
			DestinationAddress: "example.com",
			DestinationKind:    DestinationDomain,
			DestinationPort:    443,
			Network:            NetworkTCP,
			AppProtocol:        AppProtocolTLS,
			ObservationKind:    ObservationKindDispatch,
		}},
	}
	if err := pipeline.enqueueEmission(emission); err != nil {
		t.Fatalf("enqueueEmission() error = %v", err)
	}
	if pipeline.StatePersistErrorCount() != 1 {
		t.Fatalf("state error count = %d, want 1", pipeline.StatePersistErrorCount())
	}
	if _, next := pipeline.state.snapshot(); next != 2 {
		t.Fatalf("next sequence = %d, want 2", next)
	}
	if _, err := pipeline.queue.Peek(); err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	_ = pipeline.Close()
}

func TestRetryAfterDelayHonorsServerBound(t *testing.T) {
	if got := retryAfterDelay("10", time.Second, 30*time.Second); got != 10*time.Second {
		t.Fatalf("retry delay = %s, want 10s", got)
	}
	if got := retryAfterDelay("120", time.Second, 30*time.Second); got != 30*time.Second {
		t.Fatalf("capped retry delay = %s, want 30s", got)
	}
}

func TestPipelineDropsPreviousEpochQueueWhenControlTurnsOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	directory := t.TempDir()
	pipeline := newTestPipeline(t, directory, server.URL)
	pipeline.ApplyControl(ControlState{
		CollectorEnabled: true,
		Mode:             "observe",
		ModeEpoch:        3,
		ControlTTL:       time.Minute,
	})
	emission := Emission{
		Sources: []SourceEnvelope{{SourceRef: "source", SourceIP: "1.2.3.4"}},
		Events: []ConnectionEvent{{
			ObservedAt:         time.Now().UTC(),
			UserID:             42,
			SourceRef:          "source",
			DestinationAddress: "example.com",
			DestinationKind:    DestinationDomain,
			DestinationPort:    443,
			Network:            NetworkTCP,
			Outcome:            ConnectionOutcomeAccepted,
			FailureStage:       FailureStageNone,
			CompletenessStatus: CompletenessReady,
			ObservationKind:    ObservationKindConnection,
		}},
	}
	if err := pipeline.enqueueEmission(emission); err != nil {
		t.Fatalf("enqueueEmission() error = %v", err)
	}
	if _, err := pipeline.queue.Peek(); err != nil {
		t.Fatalf("Peek() before Off error = %v", err)
	}

	pipeline.ApplyControl(ControlState{
		CollectorEnabled: false,
		Mode:             "off",
		ModeEpoch:        4,
		ControlTTL:       time.Minute,
	})
	if _, err := pipeline.queue.Peek(); err != ErrQueueEmpty {
		t.Fatalf("Peek() after Off error = %v, want ErrQueueEmpty", err)
	}
	if pipeline.Observe(Observation{NodeID: 7}) {
		t.Fatal("Observe() accepted while collector disabled")
	}
	_ = pipeline.Close()
}

func TestPipelineDropsLegacyQueueWhenFirstControlEnablesV2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	pipeline := newTestPipeline(t, t.TempDir(), server.URL)
	emission := Emission{
		Sources: []SourceEnvelope{{SourceRef: "source", SourceIP: "1.2.3.4"}},
		Events: []ConnectionEvent{{
			ObservedAt:         time.Now().UTC(),
			UserID:             42,
			SourceRef:          "source",
			DestinationAddress: "example.com",
			DestinationKind:    DestinationDomain,
			DestinationPort:    443,
			Network:            NetworkTCP,
			ObservationKind:    ObservationKindDispatch,
		}},
	}
	if err := pipeline.enqueueEmission(emission); err != nil {
		t.Fatalf("enqueueEmission() error = %v", err)
	}
	if _, err := pipeline.queue.Peek(); err != nil {
		t.Fatalf("Peek() before initial control error = %v", err)
	}
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: true,
		Mode:             "observe",
		ModeEpoch:        9,
		ControlTTL:       time.Minute,
	}); err != nil {
		t.Fatalf("ApplyControl() error = %v", err)
	}
	if _, err := pipeline.queue.Peek(); err != ErrQueueEmpty {
		t.Fatalf("Peek() after V2 control error = %v, want ErrQueueEmpty", err)
	}
	_ = pipeline.Close()
}

func TestPipelineRejectsStaleOrConflictingControlWithoutChangingState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	pipeline := newTestPipeline(t, t.TempDir(), server.URL)
	current := ControlState{
		CollectorEnabled: true,
		Mode:             "observe",
		ModeEpoch:        5,
		ControlTTL:       time.Minute,
	}
	if err := pipeline.ApplyControl(current); err != nil {
		t.Fatalf("ApplyControl(current) error = %v", err)
	}
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: false,
		Mode:             "off",
		ModeEpoch:        4,
		ControlTTL:       time.Minute,
	}); err == nil {
		t.Fatal("ApplyControl() accepted stale epoch")
	}
	if pipeline.control.ModeEpoch != 5 || pipeline.control.Mode != "observe" {
		t.Fatalf("control changed after stale epoch: %#v", pipeline.control)
	}
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: false,
		Mode:             "off",
		ModeEpoch:        5,
		ControlTTL:       time.Minute,
	}); err == nil {
		t.Fatal("ApplyControl() accepted conflicting state for current epoch")
	}
	if pipeline.control.ModeEpoch != 5 || pipeline.control.Mode != "observe" {
		t.Fatalf("control changed after conflict: %#v", pipeline.control)
	}
	_ = pipeline.Close()
}

func TestPipelinePersistsControlEpochAcrossRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	directory := t.TempDir()
	pipeline := newTestPipeline(t, directory, server.URL)
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: true,
		Mode:             "observe",
		ModeEpoch:        12,
		ControlTTL:       time.Hour,
	}); err != nil {
		t.Fatalf("ApplyControl() error = %v", err)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	pipeline = newTestPipeline(t, directory, server.URL)
	if pipeline.control.ModeEpoch != 12 || pipeline.control.Mode != "observe" {
		t.Fatalf("restored control = %#v", pipeline.control)
	}
	if err := pipeline.ApplyControl(ControlState{
		CollectorEnabled: false,
		Mode:             "off",
		ModeEpoch:        11,
		ControlTTL:       time.Hour,
	}); err == nil {
		t.Fatal("ApplyControl() accepted stale epoch after restart")
	}
	_ = pipeline.Close()
}

func TestPipelinePersistsPendingDropCountAcrossRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"accepted": 1, "duplicate": false},
		})
	}))
	defer server.Close()
	directory := t.TempDir()
	pipeline := newTestPipeline(t, directory, server.URL)
	pipeline.recordDropped(4)
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	pipeline = newTestPipeline(t, directory, server.URL)
	emission := Emission{
		Sources: []SourceEnvelope{{SourceRef: "source", SourceIP: "1.2.3.4"}},
		Events: []ConnectionEvent{{
			ObservedAt:         time.Now().UTC(),
			UserID:             42,
			SourceRef:          "source",
			DestinationAddress: "example.com",
			DestinationKind:    DestinationDomain,
			DestinationPort:    443,
			Network:            NetworkTCP,
			ObservationKind:    ObservationKindDispatch,
		}},
	}
	if err := pipeline.enqueueEmission(emission); err != nil {
		t.Fatalf("enqueueEmission() error = %v", err)
	}
	record, err := pipeline.queue.Peek()
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	var batch Batch
	if err := json.Unmarshal(record.Payload, &batch); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if batch.DroppedCountSincePreviousBatch != 4 {
		t.Fatalf("dropped count = %d, want 4", batch.DroppedCountSincePreviousBatch)
	}
	_ = pipeline.Close()
}
