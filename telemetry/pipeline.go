package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type PipelineConfig struct {
	NodeID            uint64
	CollectorVersion  string
	ClassifierVersion string
	StateDirectory    string
	BufferSize        int
	FlushInterval     time.Duration
	RetryMin          time.Duration
	RetryMax          time.Duration
	ShutdownTimeout   time.Duration
}

type Pipeline struct {
	config         PipelineConfig
	queue          *DiskQueue
	sender         *Sender
	state          *streamState
	collector      *Collector
	wake           chan struct{}
	done           chan struct{}
	startOnce      sync.Once
	closeOnce      sync.Once
	cancel         context.CancelFunc
	pendingDropped atomic.Uint64
	quarantined    atomic.Uint64
	stateErrors    atomic.Uint64
	started        atomic.Bool
}

func NewPipeline(
	config PipelineConfig,
	aggregator *Aggregator,
	queue *DiskQueue,
	sender *Sender,
) (*Pipeline, error) {
	if config.NodeID == 0 ||
		config.CollectorVersion == "" ||
		config.ClassifierVersion == "" ||
		config.StateDirectory == "" {
		return nil, fmt.Errorf("pipeline identity and state directory are required")
	}
	if config.BufferSize <= 0 || config.FlushInterval <= 0 ||
		config.RetryMin <= 0 || config.RetryMax < config.RetryMin ||
		config.ShutdownTimeout <= 0 {
		return nil, fmt.Errorf("pipeline timing and buffer bounds are invalid")
	}
	if aggregator == nil || queue == nil || sender == nil {
		return nil, fmt.Errorf("pipeline dependencies are required")
	}
	if queue.config.NodeID != config.NodeID {
		return nil, fmt.Errorf("pipeline and queue node IDs differ")
	}
	state, err := openStreamState(config.StateDirectory, config.NodeID)
	if err != nil {
		return nil, err
	}
	if queue.config.StreamID != state.StreamID {
		return nil, fmt.Errorf("pipeline state and queue stream IDs differ")
	}
	lastSequence, err := queue.LastSequence()
	if err != nil {
		return nil, err
	}
	if err := state.reconcile(lastSequence); err != nil {
		return nil, err
	}

	pipeline := &Pipeline{
		config: config,
		queue:  queue,
		sender: sender,
		state:  state,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	collector, err := NewCollector(CollectorConfig{
		BufferSize:    config.BufferSize,
		FlushInterval: config.FlushInterval,
	}, aggregator, pipeline.enqueueEmission)
	if err != nil {
		return nil, err
	}
	pipeline.collector = collector
	return pipeline, nil
}

func (p *Pipeline) Start(parent context.Context) {
	p.startOnce.Do(func() {
		p.started.Store(true)
		ctx, cancel := context.WithCancel(parent)
		p.cancel = cancel
		p.collector.Start(ctx)
		go p.runSender(ctx)
	})
}

func (p *Pipeline) Observe(observation Observation) bool {
	if observation.NodeID != p.config.NodeID {
		return false
	}
	return p.collector.Observe(observation)
}

func (p *Pipeline) Close() error {
	var closeErr error
	p.closeOnce.Do(func() {
		p.collector.Close()
		if p.started.Load() {
			p.signalSender()
			deadline := time.Now().Add(p.config.ShutdownTimeout)
			for time.Now().Before(deadline) {
				if _, err := p.queue.Peek(); errors.Is(err, ErrQueueEmpty) {
					break
				}
				p.signalSender()
				time.Sleep(10 * time.Millisecond)
			}
		}
		if p.cancel != nil {
			p.cancel()
			<-p.done
		} else {
			close(p.done)
		}
		closeErr = p.queue.Close()
	})
	return closeErr
}

func (p *Pipeline) QuarantinedCount() uint64 {
	return p.quarantined.Load()
}

func (p *Pipeline) StatePersistErrorCount() uint64 {
	return p.stateErrors.Load()
}

func (p *Pipeline) enqueueEmission(emission Emission) error {
	streamID, sequenceFirst := p.state.snapshot()
	batchID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate telemetry batch ID: %w", err)
	}
	dropped := p.pendingDropped.Swap(0) +
		p.queue.TakeDroppedCount() +
		p.collector.dropped.Swap(0)
	batch, err := AssembleBatch(BatchParams{
		SchemaVersion:     1,
		BatchID:           batchID,
		NodeID:            p.config.NodeID,
		StreamID:          streamID,
		GeneratedAt:       time.Now().UTC(),
		CollectorVersion:  p.config.CollectorVersion,
		ClassifierVersion: p.config.ClassifierVersion,
		SequenceFirst:     sequenceFirst,
		DroppedCount:      dropped,
	}, emission)
	if err != nil {
		p.pendingDropped.Add(dropped + uint64(len(emission.Buckets)))
		return err
	}
	body, err := json.Marshal(batch)
	if err != nil {
		p.pendingDropped.Add(dropped + uint64(len(emission.Buckets)))
		return fmt.Errorf("marshal telemetry batch: %w", err)
	}
	if err := p.queue.Enqueue(QueueRecord{
		ID:            batchID,
		CreatedAt:     batch.GeneratedAt.Time,
		SequenceFirst: batch.SequenceFirst,
		SequenceLast:  batch.SequenceLast,
		Payload:       body,
	}); err != nil {
		p.pendingDropped.Add(dropped)
		return err
	}
	p.pendingDropped.Add(p.queue.TakeDroppedCount())
	if err := p.state.advance(batch.SequenceLast); err != nil {
		// The encrypted queue record is the recovery truth. In-memory state has
		// already advanced, and startup reconciles from queued sequence headers.
		p.stateErrors.Add(1)
	}
	p.signalSender()
	return nil
}

func (p *Pipeline) runSender(ctx context.Context) {
	defer close(p.done)
	backoff := p.config.RetryMin
	for {
		record, err := p.queue.Peek()
		if errors.Is(err, ErrQueueEmpty) {
			if !waitForWake(ctx, p.wake) {
				return
			}
			continue
		}
		if err != nil {
			if !waitForRetry(ctx, jitter(backoff)) {
				return
			}
			backoff = nextBackoff(backoff, p.config.RetryMax)
			continue
		}

		var batch Batch
		if err := json.Unmarshal(record.Payload, &batch); err != nil {
			if err := p.queue.Ack(record.ID); err == nil {
				p.quarantined.Add(1)
				backoff = p.config.RetryMin
				continue
			}
			if !waitForRetry(ctx, jitter(backoff)) {
				return
			}
			backoff = nextBackoff(backoff, p.config.RetryMax)
			continue
		}
		result, sendErr := p.sender.Send(ctx, record.Payload)
		if sendErr == nil {
			if !result.Duplicate && result.Accepted != uint32(len(batch.Buckets)) {
				sendErr = fmt.Errorf(
					"telemetry acknowledgement mismatch: accepted=%d buckets=%d",
					result.Accepted,
					len(batch.Buckets),
				)
			}
		}
		if sendErr == nil {
			if err := p.queue.Ack(record.ID); err == nil {
				backoff = p.config.RetryMin
				continue
			}
		}

		var responseErr *SendError
		if errors.As(sendErr, &responseErr) && !responseErr.Retryable {
			if err := p.queue.Ack(record.ID); err == nil {
				p.quarantined.Add(1)
				backoff = p.config.RetryMin
				continue
			}
		}
		delay := jitter(backoff)
		if errors.As(sendErr, &responseErr) {
			delay = retryAfterDelay(responseErr.RetryAfter, delay, p.config.RetryMax)
		}
		if !waitForRetry(ctx, delay) {
			return
		}
		backoff = nextBackoff(backoff, p.config.RetryMax)
	}
}

func (p *Pipeline) signalSender() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func waitForWake(ctx context.Context, wake <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func jitter(delay time.Duration) time.Duration {
	spread := delay / 5
	if spread <= 0 {
		return delay
	}
	return delay - spread + time.Duration(rand.Int64N(int64(spread*2)+1))
}

func retryAfterDelay(value string, local, maximum time.Duration) time.Duration {
	if value == "" {
		return local
	}
	var server time.Duration
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		server = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		server = time.Until(at)
	}
	if server <= local {
		return local
	}
	if server > maximum {
		return maximum
	}
	return server
}

type Manager struct {
	pipelines map[uint64]*Pipeline
}

func NewManager(pipelines ...*Pipeline) (*Manager, error) {
	manager := &Manager{pipelines: make(map[uint64]*Pipeline, len(pipelines))}
	for _, pipeline := range pipelines {
		if pipeline == nil {
			return nil, fmt.Errorf("telemetry pipeline is required")
		}
		if _, exists := manager.pipelines[pipeline.config.NodeID]; exists {
			return nil, fmt.Errorf("duplicate telemetry node %d", pipeline.config.NodeID)
		}
		manager.pipelines[pipeline.config.NodeID] = pipeline
	}
	return manager, nil
}

func (m *Manager) Start(ctx context.Context) {
	for _, pipeline := range m.pipelines {
		pipeline.Start(ctx)
	}
}

func (m *Manager) Observe(observation Observation) bool {
	pipeline := m.pipelines[observation.NodeID]
	return pipeline != nil && pipeline.Observe(observation)
}

func (m *Manager) Close() error {
	var errs []error
	for _, pipeline := range m.pipelines {
		if err := pipeline.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
