package telemetry

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAggregatorCombinesProbeConnectionsByMinute(t *testing.T) {
	aggregator := newTestAggregator(t)
	start := time.Date(2026, 7, 29, 1, 2, 0, 0, time.UTC)
	base := Observation{
		ObservedAt:    start.Add(5 * time.Second),
		UserID:        42,
		NodeID:        7,
		SourceIP:      netip.MustParseAddr("1.2.3.4"),
		Destination:   Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP},
		Network:       NetworkTCP,
		AppProtocol:   AppProtocolHTTP,
		SniffSource:   SniffOriginal,
		Confidence:    ConfidenceHigh,
		UploadBytes:   100,
		DownloadBytes: 200,
		ActiveMillis:  400,
	}
	if !aggregator.Observe(base) {
		t.Fatal("Observe() rejected first connection")
	}
	base.ObservedAt = start.Add(30 * time.Second)
	base.UploadBytes = 300
	base.DownloadBytes = 500
	base.ActiveMillis = 600
	if !aggregator.Observe(base) {
		t.Fatal("Observe() rejected second connection")
	}

	emission := aggregator.FlushBefore(start.Add(time.Minute))

	if len(emission.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(emission.Sources))
	}
	if len(emission.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(emission.Buckets))
	}
	got := emission.Buckets[0]
	if got.ConnectionCount != 2 || got.UploadBytes != 400 || got.DownloadBytes != 700 {
		t.Fatalf("aggregate measures = %#v", got)
	}
	if got.ActiveMilliseconds != 1000 {
		t.Fatalf("active milliseconds = %d, want 1000", got.ActiveMilliseconds)
	}
	if got.ProbeSignature != "cloudflare_one_http" || got.DestinationClass != DestinationProbe {
		t.Fatalf("classification = %#v", got)
	}
}

func TestAggregatorFoldsUnknownDestinationsWithoutLeakingNames(t *testing.T) {
	aggregator := newTestAggregator(t)
	start := time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)

	for _, host := range []string{"one.example.com", "two.example.com", "one.example.com"} {
		if !aggregator.Observe(Observation{
			ObservedAt:  start.Add(10 * time.Second),
			UserID:      42,
			NodeID:      7,
			SourceIP:    netip.MustParseAddr("1.2.3.4"),
			Destination: Destination{Address: host, Port: 443, Kind: DestinationDomain, AppProtocol: AppProtocolTLS},
			Network:     NetworkTCP,
			AppProtocol: AppProtocolTLS,
			SniffSource: SniffTLSSNI,
			Confidence:  ConfidenceHigh,
		}) {
			t.Fatalf("Observe() rejected %s", host)
		}
	}

	emission := aggregator.FlushBefore(start.Add(time.Minute))
	if len(emission.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(emission.Buckets))
	}
	if emission.Buckets[0].UnknownDestinationCount != 2 {
		t.Fatalf("unknown destination count = %d, want 2", emission.Buckets[0].UnknownDestinationCount)
	}

	encoded, err := json.Marshal(emission)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"one.example.com", "two.example.com"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("emission leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestAggregatorCountsActualSourceTransitions(t *testing.T) {
	aggregator := newTestAggregator(t)
	start := time.Date(2026, 7, 29, 3, 0, 0, 0, time.UTC)
	observation := Observation{
		ObservedAt:  start.Add(time.Second),
		UserID:      42,
		NodeID:      7,
		SourceIP:    netip.MustParseAddr("1.2.3.4"),
		Destination: Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP},
		Network:     NetworkTCP,
		AppProtocol: AppProtocolHTTP,
	}
	aggregator.Observe(observation)
	observation.ObservedAt = start.Add(2 * time.Second)
	aggregator.Observe(observation)
	observation.ObservedAt = start.Add(3 * time.Second)
	observation.SourceIP = netip.MustParseAddr("5.6.7.8")
	aggregator.Observe(observation)

	emission := aggregator.FlushBefore(start.Add(time.Minute))
	var transitions uint32
	for _, bucket := range emission.Buckets {
		transitions += bucket.TransitionInCount
	}
	if transitions != 1 {
		t.Fatalf("transition count = %d, want 1", transitions)
	}
}

func TestAggregatorBucketIDIsStableAcrossSealingRandomness(t *testing.T) {
	start := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	observation := Observation{
		ObservedAt:  start.Add(time.Second),
		UserID:      42,
		NodeID:      7,
		SourceIP:    netip.MustParseAddr("1.2.3.4"),
		Destination: Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP},
		Network:     NetworkTCP,
		AppProtocol: AppProtocolHTTP,
	}

	first := newTestAggregator(t)
	first.Observe(observation)
	firstID := first.FlushBefore(start.Add(time.Minute)).Buckets[0].BucketID

	second := newTestAggregator(t)
	second.Observe(observation)
	secondID := second.FlushBefore(start.Add(time.Minute)).Buckets[0].BucketID

	if firstID == "" || firstID != secondID {
		t.Fatalf("bucket IDs = %q and %q", firstID, secondID)
	}
}

func TestAggregatorBoundsDimensionsPerUserMinute(t *testing.T) {
	aggregator := newTestAggregator(t)
	start := time.Date(2026, 7, 29, 4, 30, 0, 0, time.UTC)
	accepted := 0
	for port := 1; port <= maxDimensionRowsPerUserMinute+20; port++ {
		if aggregator.Observe(Observation{
			ObservedAt:  start,
			UserID:      42,
			NodeID:      7,
			SourceIP:    netip.MustParseAddr("1.2.3.4"),
			Destination: Destination{Address: "unknown.example", Port: uint16(port), Kind: DestinationDomain},
			Network:     NetworkTCP,
		}) {
			accepted++
		}
	}
	if accepted != maxDimensionRowsPerUserMinute {
		t.Fatalf("accepted = %d, want %d", accepted, maxDimensionRowsPerUserMinute)
	}
	emission := aggregator.FlushBefore(start.Add(time.Minute))
	if len(emission.Buckets) != maxDimensionRowsPerUserMinute {
		t.Fatalf("buckets = %d, want %d", len(emission.Buckets), maxDimensionRowsPerUserMinute)
	}
}

func TestAggregatorBoundsUnknownDistinctMemory(t *testing.T) {
	aggregator := newTestAggregator(t)
	start := time.Date(2026, 7, 29, 4, 45, 0, 0, time.UTC)
	for i := 0; i < int(maxUnknownDestinationsPerBucket)+20; i++ {
		aggregator.Observe(Observation{
			ObservedAt:  start,
			UserID:      42,
			NodeID:      7,
			SourceIP:    netip.MustParseAddr("1.2.3.4"),
			Destination: Destination{Address: "host-" + strconv.Itoa(i) + ".example", Port: 443, Kind: DestinationDomain},
			Network:     NetworkTCP,
		})
	}
	emission := aggregator.FlushBefore(start.Add(time.Minute))
	if got := emission.Buckets[0].UnknownDestinationCount; got != maxUnknownDestinationsPerBucket {
		t.Fatalf("unknown count = %d, want %d", got, maxUnknownDestinationsPerBucket)
	}
}

func newTestAggregator(t *testing.T) *Aggregator {
	t.Helper()
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	classifier, err := NewClassifier(Catalog{
		Version:    "2026-07-29.1",
		ValidUntil: now.Add(24 * time.Hour),
		Rules: []ProbeRule{{
			ID:         "cloudflare_one_http",
			Host:       "1.1.1.1",
			Ports:      []uint16{80},
			Protocols:  []AppProtocol{AppProtocolHTTP},
			Confidence: ConfidenceHigh,
		}},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}
	return NewAggregator(classifier, NewSourceProtector())
}
