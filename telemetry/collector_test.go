package telemetry

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectorObserveNeverBlocksWhenBufferIsFull(t *testing.T) {
	collector, err := NewCollector(CollectorConfig{
		BufferSize:    1,
		FlushInterval: time.Minute,
	}, NewEventBuffer(NewSourceProtector()), func(Emission) error { return nil })
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}

	observation := collectorTestObservation(time.Now())
	if !collector.Observe(observation) {
		t.Fatal("first Observe() rejected")
	}
	if collector.Observe(observation) {
		t.Fatal("second Observe() accepted despite full buffer")
	}
}

func TestCollectorFlushesRawEventsOffHotPath(t *testing.T) {
	emissions := make(chan Emission, 1)
	collector, err := NewCollector(CollectorConfig{
		BufferSize:    8,
		FlushInterval: 5 * time.Millisecond,
	}, NewEventBuffer(NewSourceProtector()), func(emission Emission) error {
		emissions <- emission
		return nil
	})
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector.Start(ctx)
	defer collector.Close()

	if !collector.Observe(collectorTestObservation(time.Now().Add(-2 * time.Minute))) {
		t.Fatal("Observe() rejected")
	}

	select {
	case emission := <-emissions:
		if len(emission.Events) != 1 {
			t.Fatalf("emission events = %d", len(emission.Events))
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not flush")
	}
}

func TestCollectorRetriesEmissionAfterEmitterFailure(t *testing.T) {
	var attempts atomic.Int32
	emissions := make(chan Emission, 1)
	collector, err := NewCollector(CollectorConfig{
		BufferSize:    8,
		FlushInterval: 5 * time.Millisecond,
	}, NewEventBuffer(NewSourceProtector()), func(emission Emission) error {
		if attempts.Add(1) == 1 {
			return errors.New("queue unavailable")
		}
		emissions <- emission
		return nil
	})
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	collector.Start(context.Background())
	defer collector.Close()

	if !collector.Observe(collectorTestObservation(time.Now().Add(-2 * time.Minute))) {
		t.Fatal("Observe() rejected")
	}
	select {
	case emission := <-emissions:
		if len(emission.Events) != 1 {
			t.Fatalf("emission events = %d", len(emission.Events))
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not retry failed emission")
	}
	if collector.EmitErrorCount() != 1 {
		t.Fatalf("emit error count = %d, want 1", collector.EmitErrorCount())
	}
}

func TestCollectorCannotStartOrObserveAfterClose(t *testing.T) {
	collector, err := NewCollector(CollectorConfig{
		BufferSize:    1,
		FlushInterval: time.Minute,
	}, NewEventBuffer(NewSourceProtector()), func(Emission) error { return nil })
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	collector.Close()
	collector.Start(context.Background())
	if collector.Observe(collectorTestObservation(time.Now())) {
		t.Fatal("Observe() accepted after Close()")
	}
}

func collectorTestObservation(at time.Time) Observation {
	return Observation{
		ObservedAt:  at,
		UserID:      42,
		NodeID:      7,
		SourceIP:    netip.MustParseAddr("1.2.3.4"),
		Destination: Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP},
		Network:     NetworkTCP,
		AppProtocol: AppProtocolHTTP,
	}
}
