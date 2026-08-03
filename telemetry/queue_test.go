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
	queue.now = func() time.Time { return now }
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
	queue.now = func() time.Time { return now }
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

func TestDiskQueueCanDropInvalidHeadWithoutBlockingLaterRecords(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.New()
	queue := openTestQueue(t, directory, streamID, bytes.Repeat([]byte{7}, 32))
	now := time.Now().UTC()
	for sequence := uint64(1); sequence <= 2; sequence++ {
		if err := queue.Enqueue(QueueRecord{
			ID:            uuid.New(),
			CreatedAt:     now,
			SequenceFirst: sequence,
			SequenceLast:  sequence,
			Payload:       []byte{byte(sequence)},
		}); err != nil {
			t.Fatalf("Enqueue(%d) error = %v", sequence, err)
		}
	}
	files, err := queue.filesLocked()
	if err != nil {
		t.Fatalf("filesLocked() error = %v", err)
	}
	if err := os.WriteFile(files[0], []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := queue.Peek(); !errors.Is(err, ErrQueueRecordInvalid) {
		t.Fatalf("Peek() error = %v, want ErrQueueRecordInvalid", err)
	}
	if err := queue.DropHead(); err != nil {
		t.Fatalf("DropHead() error = %v", err)
	}
	record, err := queue.Peek()
	if err != nil {
		t.Fatalf("Peek(second) error = %v", err)
	}
	if record.SequenceFirst != 2 {
		t.Fatalf("second sequence = %d, want 2", record.SequenceFirst)
	}
	if queue.DroppedCount() != 1 {
		t.Fatalf("dropped count = %d, want 1", queue.DroppedCount())
	}
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

func TestDiskQueueDropAllPersistsDroppedCountAcrossReopen(t *testing.T) {
	directory := t.TempDir()
	streamID := uuid.New()
	key := bytes.Repeat([]byte{8}, 32)
	queue := openTestQueue(t, directory, streamID, key)
	for index, sequences := range [][2]uint64{{1, 3}, {4, 5}} {
		if err := queue.Enqueue(QueueRecord{
			ID:            uuid.New(),
			CreatedAt:     time.Now().UTC(),
			SequenceFirst: sequences[0],
			SequenceLast:  sequences[1],
			Payload:       []byte("payload"),
		}); err != nil {
			t.Fatalf("Enqueue(%d) error = %v", index, err)
		}
	}
	if err := queue.DropAll(); err != nil {
		t.Fatalf("DropAll() error = %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	queue = openTestQueue(t, directory, streamID, key)
	if queue.DroppedCount() != 5 {
		t.Fatalf("dropped count after reopen = %d, want 5", queue.DroppedCount())
	}
	count, err := queue.TakeDroppedCount()
	if err != nil {
		t.Fatalf("TakeDroppedCount() error = %v", err)
	}
	if count != 5 {
		t.Fatalf("taken dropped count = %d, want 5", count)
	}
	_ = queue.Close()
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
