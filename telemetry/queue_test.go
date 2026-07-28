package telemetry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDiskQueueEncryptsAndSurvivesReopen(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.MustParse("019fb0c0-2b0d-7e3c-b9bd-d2dc946d3325")
	recordID := uuid.MustParse("019fb0c6-ff80-7b22-9202-b7a6c11a6b88")
	key := bytes.Repeat([]byte{0x42}, 32)
	now := time.Date(2026, 7, 29, 5, 0, 0, 0, time.UTC)

	queue := openTestQueue(t, directory, streamID, key)
	payload := []byte(`{"secret":"sealed-source-and-telemetry"}`)
	if err := queue.Enqueue(QueueRecord{
		ID:            recordID,
		CreatedAt:     now,
		SequenceFirst: 1001,
		SequenceLast:  1002,
		Payload:       payload,
	}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	files, err := filepath.Glob(filepath.Join(directory, "*.tq"))
	if err != nil || len(files) != 1 {
		t.Fatalf("queue files = %v, error = %v", files, err)
	}
	onDisk, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if bytes.Contains(onDisk, payload) || bytes.Contains(onDisk, []byte("sealed-source")) {
		t.Fatalf("queue file contains plaintext: %q", onDisk)
	}

	queue = openTestQueue(t, directory, streamID, key)
	got, err := queue.Peek()
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if got.ID != recordID || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("Peek() = %#v", got)
	}
	if got.SequenceFirst != 1001 || got.SequenceLast != 1002 {
		t.Fatalf("sequence = %d..%d", got.SequenceFirst, got.SequenceLast)
	}
	if err := queue.Ack(recordID); err != nil {
		t.Fatalf("Ack() error = %v", err)
	}
	if _, err := queue.Peek(); err != ErrQueueEmpty {
		t.Fatalf("Peek() error = %v, want ErrQueueEmpty", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDiskQueueRejectsWrongKey(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.New()
	queue := openTestQueue(t, directory, streamID, bytes.Repeat([]byte{1}, 32))
	if err := queue.Enqueue(QueueRecord{
		ID:            uuid.New(),
		CreatedAt:     time.Now().UTC(),
		SequenceFirst: 1,
		SequenceLast:  1,
		Payload:       []byte("sensitive"),
	}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	queue = openTestQueue(t, directory, streamID, bytes.Repeat([]byte{2}, 32))
	if _, err := queue.Peek(); err == nil {
		t.Fatal("Peek() error = nil, want authentication failure")
	}
	_ = queue.Close()
}

func TestDiskQueueExpiresOldestRecords(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.New()
	queue := openTestQueue(t, directory, streamID, bytes.Repeat([]byte{3}, 32))
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	queue.now = func() time.Time { return now }
	if err := queue.Enqueue(QueueRecord{
		ID:            uuid.New(),
		CreatedAt:     now.Add(-7 * time.Hour),
		SequenceFirst: 1,
		SequenceLast:  1,
		Payload:       []byte("expired"),
	}); err != nil {
		t.Fatalf("Enqueue(expired) error = %v", err)
	}
	if _, err := queue.Peek(); !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("Peek() error = %v, want ErrQueueEmpty", err)
	}
	if queue.DroppedCount() != 1 {
		t.Fatalf("dropped count = %d, want 1", queue.DroppedCount())
	}
}

func TestDiskQueueConcurrentEnqueueHonorsMaxBytes(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.New()
	queue := openTestQueue(t, directory, streamID, bytes.Repeat([]byte{4}, 32))
	queue.config.MaxBytes = 700

	var wait sync.WaitGroup
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func(sequence uint64) {
			defer wait.Done()
			_ = queue.Enqueue(QueueRecord{
				ID:            uuid.New(),
				CreatedAt:     time.Now().UTC(),
				SequenceFirst: sequence,
				SequenceLast:  sequence,
				Payload:       bytes.Repeat([]byte{byte(sequence)}, 180),
			})
		}(uint64(i + 1))
	}
	wait.Wait()

	size, err := queue.size()
	if err != nil {
		t.Fatalf("size() error = %v", err)
	}
	if size > queue.config.MaxBytes {
		t.Fatalf("queue size = %d, max = %d", size, queue.config.MaxBytes)
	}
}

func openTestQueue(t *testing.T, directory string, streamID uuid.UUID, key []byte) *DiskQueue {
	t.Helper()
	queue, err := OpenDiskQueue(QueueConfig{
		Directory:       directory,
		NodeID:          7,
		StreamID:        streamID,
		WriteKeyVersion: 1,
		Keys:            map[uint16][]byte{1: key},
		MaxBytes:        1024 * 1024,
		MaxAge:          6 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDiskQueue() error = %v", err)
	}
	return queue
}
