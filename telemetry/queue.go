package telemetry

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	queueFormatVersion uint16 = 1
	queueMagic                = "V2TQ"
)

var (
	ErrQueueEmpty         = errors.New("telemetry queue is empty")
	ErrQueueFull          = errors.New("telemetry queue is full")
	ErrQueueRecordInvalid = errors.New("telemetry queue record is invalid")
)

type QueueConfig struct {
	Directory       string
	NodeID          uint64
	StreamID        uuid.UUID
	WriteKeyVersion uint16
	Keys            map[uint16][]byte
	MaxBytes        int64
	MaxAge          time.Duration
}

type QueueRecord struct {
	ID            uuid.UUID
	CreatedAt     time.Time
	SequenceFirst uint64
	SequenceLast  uint64
	Payload       []byte
}

type DiskQueue struct {
	config      QueueConfig
	aeads       map[uint16]cipher.AEAD
	lock        *flock.Flock
	droppedPath string
	mu          sync.Mutex
	now         func() time.Time
	dropped     atomic.Uint64
}

type queueHeader struct {
	formatVersion uint16
	keyVersion    uint16
	nodeID        uint64
	streamID      uuid.UUID
	recordID      uuid.UUID
	createdAtMS   int64
	sequenceFirst uint64
	sequenceLast  uint64
}

func OpenDiskQueue(config QueueConfig) (*DiskQueue, error) {
	if config.Directory == "" {
		return nil, fmt.Errorf("queue directory is required")
	}
	if config.NodeID == 0 || config.StreamID == uuid.Nil {
		return nil, fmt.Errorf("queue node and stream IDs are required")
	}
	if config.WriteKeyVersion == 0 {
		return nil, fmt.Errorf("queue write key version is required")
	}
	if config.MaxBytes <= 0 || config.MaxAge <= 0 {
		return nil, fmt.Errorf("queue size and age bounds are required")
	}

	aeads := make(map[uint16]cipher.AEAD, len(config.Keys))
	for version, key := range config.Keys {
		if version == 0 {
			return nil, fmt.Errorf("queue key version is required")
		}
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("queue key version %d: %w", version, err)
		}
		aeads[version] = aead
	}
	if _, ok := aeads[config.WriteKeyVersion]; !ok {
		return nil, fmt.Errorf("queue write key version %d is unavailable", config.WriteKeyVersion)
	}

	if err := os.MkdirAll(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("create queue directory: %w", err)
	}
	if err := os.Chmod(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect queue directory: %w", err)
	}

	queueLock := flock.New(filepath.Join(config.Directory, ".lock"))
	locked, err := queueLock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock telemetry queue: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("telemetry queue is already open")
	}

	droppedPath := filepath.Join(config.Directory, ".dropped-count")
	droppedCount, err := loadDroppedCount(droppedPath)
	if err != nil {
		_ = queueLock.Unlock()
		return nil, err
	}
	queue := &DiskQueue{
		config:      config,
		aeads:       aeads,
		lock:        queueLock,
		droppedPath: droppedPath,
		now:         time.Now,
	}
	queue.dropped.Store(droppedCount)
	return queue, nil
}

func (q *DiskQueue) Enqueue(record QueueRecord) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if record.ID == uuid.Nil || record.CreatedAt.IsZero() {
		return fmt.Errorf("queue record ID and timestamp are required")
	}
	if record.SequenceFirst == 0 || record.SequenceLast < record.SequenceFirst {
		return fmt.Errorf("queue record sequence is invalid")
	}
	if len(record.Payload) == 0 {
		return fmt.Errorf("queue record payload is empty")
	}

	header := queueHeader{
		formatVersion: queueFormatVersion,
		keyVersion:    q.config.WriteKeyVersion,
		nodeID:        q.config.NodeID,
		streamID:      q.config.StreamID,
		recordID:      record.ID,
		createdAtMS:   record.CreatedAt.UTC().UnixMilli(),
		sequenceFirst: record.SequenceFirst,
		sequenceLast:  record.SequenceLast,
	}
	aad, err := marshalQueueAAD(header)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate queue nonce: %w", err)
	}
	ciphertext := q.aeads[header.keyVersion].Seal(nil, nonce, record.Payload, aad)

	var encoded bytes.Buffer
	encoded.Write(aad)
	encoded.Write(nonce)
	if err := binary.Write(&encoded, binary.BigEndian, uint32(len(ciphertext))); err != nil {
		return fmt.Errorf("encode queue ciphertext length: %w", err)
	}
	encoded.Write(ciphertext)

	if err := q.purgeExpiredLocked(); err != nil {
		return err
	}
	currentBytes, err := q.sizeLocked()
	if err != nil {
		return err
	}
	if int64(encoded.Len()) > q.config.MaxBytes {
		return ErrQueueFull
	}
	for currentBytes > q.config.MaxBytes-int64(encoded.Len()) {
		files, err := q.filesLocked()
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return ErrQueueFull
		}
		info, err := os.Stat(files[0])
		if err != nil {
			return fmt.Errorf("stat queue record: %w", err)
		}
		dropped := queueRecordEventCount(files[0])
		if err := os.Remove(files[0]); err != nil {
			return fmt.Errorf("drop oldest queue record: %w", err)
		}
		currentBytes -= info.Size()
		if err := q.addDroppedLocked(dropped); err != nil {
			return err
		}
	}

	name := fmt.Sprintf("%020d-%s.tq", record.SequenceFirst, record.ID.String())
	target := filepath.Join(q.config.Directory, name)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("queue record %s already exists", record.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect queue record: %w", err)
	}
	return atomicWriteFile(target, encoded.Bytes(), 0o600)
}

func (q *DiskQueue) Peek() (QueueRecord, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.purgeExpiredLocked(); err != nil {
		return QueueRecord{}, err
	}
	files, err := q.filesLocked()
	if err != nil {
		return QueueRecord{}, err
	}
	if len(files) == 0 {
		return QueueRecord{}, ErrQueueEmpty
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		return QueueRecord{}, fmt.Errorf("read queue record: %w", err)
	}
	header, nonce, ciphertext, aad, err := unmarshalQueueRecord(data)
	if err != nil {
		return QueueRecord{}, fmt.Errorf("%w: %v", ErrQueueRecordInvalid, err)
	}
	if header.nodeID != q.config.NodeID || header.streamID != q.config.StreamID {
		return QueueRecord{}, fmt.Errorf(
			"%w: owner mismatch",
			ErrQueueRecordInvalid,
		)
	}
	aead, ok := q.aeads[header.keyVersion]
	if !ok {
		return QueueRecord{}, fmt.Errorf(
			"%w: key version %d is unavailable",
			ErrQueueRecordInvalid,
			header.keyVersion,
		)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return QueueRecord{}, fmt.Errorf(
			"%w: authentication failed",
			ErrQueueRecordInvalid,
		)
	}
	return QueueRecord{
		ID:            header.recordID,
		CreatedAt:     time.UnixMilli(header.createdAtMS).UTC(),
		SequenceFirst: header.sequenceFirst,
		SequenceLast:  header.sequenceLast,
		Payload:       plaintext,
	}, nil
}

func (q *DiskQueue) DropHead() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, err := q.filesLocked()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return ErrQueueEmpty
	}
	dropped := queueRecordEventCount(files[0])
	if err := os.Remove(files[0]); err != nil {
		return fmt.Errorf("drop queue head: %w", err)
	}
	if err := q.addDroppedLocked(dropped); err != nil {
		return err
	}
	return syncDirectory(q.config.Directory)
}

func (q *DiskQueue) DropAll() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, err := q.filesLocked()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	for _, path := range files {
		dropped := queueRecordEventCount(path)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("drop queue record: %w", err)
		}
		if err := q.addDroppedLocked(dropped); err != nil {
			return err
		}
	}
	return syncDirectory(q.config.Directory)
}

func (q *DiskQueue) Ack(id uuid.UUID) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	matches, err := filepath.Glob(filepath.Join(q.config.Directory, "*-"+id.String()+".tq"))
	if err != nil {
		return fmt.Errorf("find queue record: %w", err)
	}
	if len(matches) != 1 {
		return fmt.Errorf("queue record %s not found", id)
	}
	if err := os.Remove(matches[0]); err != nil {
		return fmt.Errorf("remove queue record: %w", err)
	}
	return syncDirectory(q.config.Directory)
}

func (q *DiskQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.lock == nil {
		return nil
	}
	err := q.lock.Unlock()
	q.lock = nil
	return err
}

func (q *DiskQueue) DroppedCount() uint64 {
	return q.dropped.Load()
}

func (q *DiskQueue) TakeDroppedCount() (uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := q.dropped.Load()
	if count == 0 {
		return 0, nil
	}
	q.dropped.Store(0)
	if err := q.persistDroppedLocked(); err != nil {
		q.dropped.Store(count)
		return 0, err
	}
	return count, nil
}

func (q *DiskQueue) LastSequence() (uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, err := q.filesLocked()
	if err != nil {
		return 0, err
	}
	var last uint64
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read queue sequence: %w", err)
		}
		header, _, _, _, err := unmarshalQueueRecord(data)
		if err != nil {
			return 0, err
		}
		if header.sequenceLast > last {
			last = header.sequenceLast
		}
	}
	return last, nil
}

func (q *DiskQueue) filesLocked() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(q.config.Directory, "*.tq"))
	if err != nil {
		return nil, fmt.Errorf("list queue records: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func (q *DiskQueue) size() (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sizeLocked()
}

func (q *DiskQueue) sizeLocked() (int64, error) {
	files, err := q.filesLocked()
	if err != nil {
		return 0, err
	}
	var size int64
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return 0, fmt.Errorf("stat queue record: %w", err)
		}
		size += info.Size()
	}
	return size, nil
}

func (q *DiskQueue) purgeExpiredLocked() error {
	files, err := q.filesLocked()
	if err != nil {
		return err
	}
	cutoff := q.now().UTC().Add(-q.config.MaxAge)
	removed := false
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read queue record for expiry: %w", err)
		}
		header, _, _, _, err := unmarshalQueueRecord(data)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrQueueRecordInvalid, err)
		}
		if time.UnixMilli(header.createdAtMS).UTC().After(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("expire queue record: %w", err)
		}
		if err := q.addDroppedLocked(sequenceEventCount(header)); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(q.config.Directory)
	}
	return nil
}

func loadDroppedCount(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read queue dropped count: %w", err)
	}
	count, err := strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode queue dropped count: %w", err)
	}
	return count, nil
}

func queueRecordEventCount(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 1
	}
	header, _, _, _, err := unmarshalQueueRecord(data)
	if err != nil {
		return 1
	}
	return sequenceEventCount(header)
}

func sequenceEventCount(header queueHeader) uint64 {
	if header.sequenceFirst == 0 || header.sequenceLast < header.sequenceFirst {
		return 1
	}
	return header.sequenceLast - header.sequenceFirst + 1
}

func (q *DiskQueue) addDroppedLocked(count uint64) error {
	if count == 0 {
		return nil
	}
	q.dropped.Add(count)
	return q.persistDroppedLocked()
}

func (q *DiskQueue) persistDroppedLocked() error {
	data := []byte(strconv.FormatUint(q.dropped.Load(), 10) + "\n")
	if err := atomicWriteFile(q.droppedPath, data, 0o600); err != nil {
		return fmt.Errorf("persist queue dropped count: %w", err)
	}
	return nil
}

func marshalQueueAAD(header queueHeader) ([]byte, error) {
	var encoded bytes.Buffer
	encoded.WriteString(queueMagic)
	for _, value := range []any{
		header.formatVersion,
		header.keyVersion,
		header.nodeID,
	} {
		if err := binary.Write(&encoded, binary.BigEndian, value); err != nil {
			return nil, fmt.Errorf("encode queue header: %w", err)
		}
	}
	encoded.Write(header.streamID[:])
	encoded.Write(header.recordID[:])
	for _, value := range []any{
		header.createdAtMS,
		header.sequenceFirst,
		header.sequenceLast,
	} {
		if err := binary.Write(&encoded, binary.BigEndian, value); err != nil {
			return nil, fmt.Errorf("encode queue header: %w", err)
		}
	}
	return encoded.Bytes(), nil
}

func unmarshalQueueRecord(data []byte) (
	queueHeader,
	[]byte,
	[]byte,
	[]byte,
	error,
) {
	reader := bytes.NewReader(data)
	header := queueHeader{}
	magic := make([]byte, len(queueMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != queueMagic {
		return header, nil, nil, nil, fmt.Errorf("invalid queue record magic")
	}
	if err := binary.Read(reader, binary.BigEndian, &header.formatVersion); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue format: %w", err)
	}
	if header.formatVersion != queueFormatVersion {
		return header, nil, nil, nil, fmt.Errorf("unsupported queue format %d", header.formatVersion)
	}
	if err := binary.Read(reader, binary.BigEndian, &header.keyVersion); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue key version: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &header.nodeID); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue node ID: %w", err)
	}
	if _, err := io.ReadFull(reader, header.streamID[:]); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue stream ID: %w", err)
	}
	if _, err := io.ReadFull(reader, header.recordID[:]); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue record ID: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &header.createdAtMS); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue timestamp: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &header.sequenceFirst); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue first sequence: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &header.sequenceLast); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue last sequence: %w", err)
	}

	aadLength := len(data) - reader.Len()
	aad := append([]byte(nil), data[:aadLength]...)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue nonce: %w", err)
	}
	var ciphertextLength uint32
	if err := binary.Read(reader, binary.BigEndian, &ciphertextLength); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue ciphertext length: %w", err)
	}
	if ciphertextLength == 0 || uint64(ciphertextLength) != uint64(reader.Len()) {
		return header, nil, nil, nil, fmt.Errorf("invalid queue ciphertext length")
	}
	ciphertext := make([]byte, ciphertextLength)
	if _, err := io.ReadFull(reader, ciphertext); err != nil {
		return header, nil, nil, nil, fmt.Errorf("decode queue ciphertext: %w", err)
	}
	return header, nonce, ciphertext, aad, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) (retErr error) {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".telemetry-*.tmp")
	if err != nil {
		return fmt.Errorf("create queue temp file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if retErr != nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("protect queue temp file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write queue temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync queue temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close queue temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("commit queue record: %w", err)
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open queue directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync queue directory: %w", err)
	}
	return nil
}
