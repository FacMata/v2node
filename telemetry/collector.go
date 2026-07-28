package telemetry

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Sink interface {
	Observe(Observation) bool
}

type CollectorConfig struct {
	BufferSize    int
	FlushInterval time.Duration
}

type Collector struct {
	config     CollectorConfig
	aggregator *Aggregator
	emit       func(Emission) error
	input      chan Observation
	stop       chan struct{}
	done       chan struct{}
	lifecycle  sync.RWMutex
	started    bool
	closed     bool
	pending    Emission
	emitErrors atomic.Uint64
	dropped    atomic.Uint64
	closeOnce  sync.Once
}

func NewCollector(
	config CollectorConfig,
	aggregator *Aggregator,
	emit func(Emission) error,
) (*Collector, error) {
	if config.BufferSize <= 0 {
		return nil, fmt.Errorf("collector buffer size must be positive")
	}
	if config.FlushInterval <= 0 {
		return nil, fmt.Errorf("collector flush interval must be positive")
	}
	if aggregator == nil || emit == nil {
		return nil, fmt.Errorf("collector aggregator and emitter are required")
	}
	return &Collector{
		config:     config,
		aggregator: aggregator,
		emit:       emit,
		input:      make(chan Observation, config.BufferSize),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}, nil
}

func (c *Collector) Start(ctx context.Context) {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.started || c.closed {
		return
	}
	c.started = true
	go c.run(ctx)
}

func (c *Collector) Observe(observation Observation) bool {
	c.lifecycle.RLock()
	defer c.lifecycle.RUnlock()
	if c.closed {
		c.dropped.Add(1)
		return false
	}
	select {
	case c.input <- observation:
		return true
	default:
		c.dropped.Add(1)
		return false
	}
}

func (c *Collector) Close() {
	c.closeOnce.Do(func() {
		c.lifecycle.Lock()
		c.closed = true
		started := c.started
		c.lifecycle.Unlock()
		if !started {
			close(c.done)
			return
		}
		close(c.stop)
	})
	<-c.done
}

func (c *Collector) EmitErrorCount() uint64 {
	return c.emitErrors.Load()
}

func (c *Collector) DroppedObservationCount() uint64 {
	return c.dropped.Load()
}

func (c *Collector) run(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case observation := <-c.input:
			if !c.aggregator.Observe(observation) {
				c.dropped.Add(1)
			}
		case <-ticker.C:
			_ = c.flush(time.Now().UTC().Truncate(time.Minute))
		case <-ctx.Done():
			c.drainAndFlush()
			return
		case <-c.stop:
			c.drainAndFlush()
			return
		}
	}
}

func (c *Collector) drainAndFlush() {
	for {
		select {
		case observation := <-c.input:
			if !c.aggregator.Observe(observation) {
				c.dropped.Add(1)
			}
		default:
			for c.flush(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)) {
			}
			return
		}
	}
}

func (c *Collector) flush(cutoff time.Time) bool {
	if len(c.pending.Buckets) == 0 {
		c.pending = c.aggregator.FlushBefore(cutoff)
	}
	if len(c.pending.Buckets) == 0 {
		return false
	}
	if err := c.emit(c.pending); err != nil {
		c.emitErrors.Add(1)
		return false
	}
	c.pending = Emission{}
	return true
}
