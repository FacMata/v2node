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
	DropReporter  func(uint64)
}

type Collector struct {
	config CollectorConfig
	buffer interface {
		Observe(Observation) bool
		Flush() Emission
	}
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
	buffer interface {
		Observe(Observation) bool
		Flush() Emission
	},
	emit func(Emission) error,
) (*Collector, error) {
	if config.BufferSize <= 0 {
		return nil, fmt.Errorf("collector buffer size must be positive")
	}
	if config.FlushInterval <= 0 {
		return nil, fmt.Errorf("collector flush interval must be positive")
	}
	if buffer == nil || emit == nil {
		return nil, fmt.Errorf("collector buffer and emitter are required")
	}
	return &Collector{
		config: config,
		buffer: buffer,
		emit:   emit,
		input:  make(chan Observation, config.BufferSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
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
		c.recordDrop()
		return false
	}
	select {
	case c.input <- observation:
		return true
	default:
		c.recordDrop()
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
			if !c.buffer.Observe(observation) {
				c.recordDrop()
			}
		case <-ticker.C:
			for c.flush() {
			}
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
			if !c.buffer.Observe(observation) {
				c.recordDrop()
			}
		default:
			for c.flush() {
			}
			return
		}
	}
}

func (c *Collector) recordDrop() {
	c.dropped.Add(1)
	if c.config.DropReporter != nil {
		c.config.DropReporter(1)
	}
}

func (c *Collector) flush() bool {
	if len(c.pending.Events) == 0 {
		c.pending = c.buffer.Flush()
	}
	if len(c.pending.Events) == 0 {
		return false
	}
	if err := c.emit(c.pending); err != nil {
		c.emitErrors.Add(1)
		return false
	}
	c.pending = Emission{}
	return true
}
