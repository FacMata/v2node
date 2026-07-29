package telemetry

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	bucketDuration                         = time.Minute
	maxDimensionRowsPerUserMinute          = 64
	maxUnknownDestinationsPerBucket uint32 = 4096
	maxPendingBuckets                      = 32768
	maxBucketsPerEmission                  = 300
	maxSourcesPerEmission                  = 256
)

var bucketNamespace = uuid.MustParse("c6c71bb1-cf48-4422-abda-880ee6f4b3e6")

type Network string

const (
	NetworkUnknown Network = "unknown"
	NetworkTCP     Network = "tcp"
	NetworkUDP     Network = "udp"
)

type SniffSource string

const (
	SniffNone     SniffSource = "none"
	SniffOriginal SniffSource = "original"
	SniffHTTPHost SniffSource = "http_host"
	SniffTLSSNI   SniffSource = "tls_sni"
	SniffQUIC     SniffSource = "quic"
)

type Observation struct {
	ObservedAt    time.Time
	UserID        uint64
	NodeID        uint64
	SourceIP      netip.Addr
	Destination   Destination
	Network       Network
	AppProtocol   AppProtocol
	SniffSource   SniffSource
	Confidence    Confidence
	UploadBytes   uint64
	DownloadBytes uint64
	ActiveMillis  uint64
}

type Emission struct {
	Sources []SourceEnvelope `json:"sources"`
	Buckets []Bucket         `json:"buckets"`
}

type SourceEnvelope struct {
	SourceRef string `json:"source_ref"`
	SourceIP  string `json:"source_ip"`
}

type Bucket struct {
	BucketID                string           `json:"bucket_id"`
	Sequence                uint64           `json:"sequence"`
	BucketStart             MillisTime       `json:"bucket_start"`
	UserID                  uint64           `json:"user_id"`
	SourceRef               string           `json:"source_ref"`
	DestinationClass        DestinationClass `json:"destination_class"`
	ProbeSignature          string           `json:"probe_signature,omitempty"`
	ProbeConfidence         Confidence       `json:"probe_confidence"`
	DestinationKind         DestinationKind  `json:"destination_kind"`
	DestinationPort         uint16           `json:"destination_port"`
	UnknownDestinationCount uint32           `json:"unknown_destination_count"`
	Network                 Network          `json:"network"`
	AppProtocol             AppProtocol      `json:"app_protocol"`
	SniffSource             SniffSource      `json:"sniff_source"`
	SniffConfidence         Confidence       `json:"sniff_confidence"`
	ConnectionCount         uint32           `json:"connection_count"`
	UploadBytes             uint64           `json:"upload_bytes"`
	DownloadBytes           uint64           `json:"download_bytes"`
	ActiveMilliseconds      uint64           `json:"active_milliseconds"`
	TransitionInCount       uint32           `json:"transition_in_count"`
	NodeID                  uint64           `json:"-"`
	ClassifierVersion       string           `json:"-"`
}

type MillisTime struct {
	time.Time
}

func (t MillisTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(t.UTC().Format("2006-01-02T15:04:05.000Z"))), nil
}

type aggregateKey struct {
	nodeID            uint64
	userID            uint64
	bucketStart       time.Time
	sourceRef         string
	destinationClass  DestinationClass
	probeSignature    string
	probeConfidence   Confidence
	destinationKind   DestinationKind
	destinationPort   uint16
	network           Network
	appProtocol       AppProtocol
	sniffSource       SniffSource
	sniffConfidence   Confidence
	classifierVersion string
}

type accumulator struct {
	key                aggregateKey
	source             ProtectedSource
	connectionCount    uint32
	uploadBytes        uint64
	downloadBytes      uint64
	activeMilliseconds uint64
	transitionInCount  uint32
	unknownAddresses   map[string]struct{}
}

type transitionKey struct {
	nodeID uint64
	userID uint64
}

type transitionState struct {
	sourceRef string
	seenAt    time.Time
}

type Aggregator struct {
	mu          sync.Mutex
	classifier  *Classifier
	protector   *SourceProtector
	buckets     map[aggregateKey]*accumulator
	transitions map[transitionKey]transitionState
}

func NewAggregator(classifier *Classifier, protector *SourceProtector) *Aggregator {
	return &Aggregator{
		classifier:  classifier,
		protector:   protector,
		buckets:     make(map[aggregateKey]*accumulator),
		transitions: make(map[transitionKey]transitionState),
	}
}

func (a *Aggregator) Observe(observation Observation) bool {
	if observation.ObservedAt.IsZero() ||
		observation.UserID == 0 ||
		observation.NodeID == 0 ||
		!observation.SourceIP.IsValid() {
		return false
	}

	source, err := a.protector.Protect(observation.SourceIP)
	if err != nil {
		return false
	}
	classification := a.classifier.Classify(observation.Destination)
	bucketStart := observation.ObservedAt.UTC().Truncate(bucketDuration)
	key := aggregateKey{
		nodeID:            observation.NodeID,
		userID:            observation.UserID,
		bucketStart:       bucketStart,
		sourceRef:         source.Ref,
		destinationClass:  classification.Class,
		probeSignature:    classification.Signature,
		probeConfidence:   classification.Confidence,
		destinationKind:   classification.DestinationKind,
		destinationPort:   observation.Destination.Port,
		network:           normalizeNetwork(observation.Network),
		appProtocol:       normalizeAppProtocol(observation.AppProtocol),
		sniffSource:       normalizeSniffSource(observation.SniffSource),
		sniffConfidence:   normalizeConfidence(observation.Confidence),
		classifierVersion: classification.CatalogVersion,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	entry := a.buckets[key]
	if entry == nil {
		if len(a.buckets) >= maxPendingBuckets {
			return false
		}
		if a.dimensionCountLocked(key) >= maxDimensionRowsPerUserMinute {
			return false
		}
		entry = &accumulator{
			key:              key,
			source:           source,
			unknownAddresses: make(map[string]struct{}),
		}
		a.buckets[key] = entry
	}
	entry.connectionCount++
	entry.uploadBytes += observation.UploadBytes
	entry.downloadBytes += observation.DownloadBytes
	entry.activeMilliseconds += observation.ActiveMillis
	if classification.Class == DestinationOther && classification.NormalizedAddress != "" {
		if uint32(len(entry.unknownAddresses)) < maxUnknownDestinationsPerBucket {
			entry.unknownAddresses[classification.NormalizedAddress] = struct{}{}
		}
	}

	tKey := transitionKey{nodeID: observation.NodeID, userID: observation.UserID}
	if previous, ok := a.transitions[tKey]; !ok || !observation.ObservedAt.Before(previous.seenAt) {
		if ok && previous.sourceRef != source.Ref {
			entry.transitionInCount++
		}
		a.transitions[tKey] = transitionState{
			sourceRef: source.Ref,
			seenAt:    observation.ObservedAt,
		}
	}

	return true
}

func (a *Aggregator) dimensionCountLocked(candidate aggregateKey) int {
	count := 0
	for key := range a.buckets {
		if key.nodeID == candidate.nodeID &&
			key.userID == candidate.userID &&
			key.bucketStart.Equal(candidate.bucketStart) {
			count++
		}
	}
	return count
}

func (a *Aggregator) FlushBefore(cutoff time.Time) Emission {
	cutoff = cutoff.UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	sources := make(map[string]SourceEnvelope)
	buckets := make([]Bucket, 0)
	for key, entry := range a.buckets {
		if key.bucketStart.Add(bucketDuration).After(cutoff) {
			continue
		}
		_, sourceAlreadyIncluded := sources[key.sourceRef]
		if len(buckets) >= maxBucketsPerEmission ||
			(!sourceAlreadyIncluded && len(sources) >= maxSourcesPerEmission) {
			continue
		}
		sources[key.sourceRef] = SourceEnvelope{
			SourceRef: key.sourceRef,
			SourceIP:  entry.source.IP,
		}
		buckets = append(buckets, entry.bucket())
		delete(a.buckets, key)
	}

	sourceList := make([]SourceEnvelope, 0, len(sources))
	for _, source := range sources {
		sourceList = append(sourceList, source)
	}
	sort.Slice(sourceList, func(i, j int) bool {
		return sourceList[i].SourceRef < sourceList[j].SourceRef
	})
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].BucketStart.Equal(buckets[j].BucketStart.Time) {
			return buckets[i].BucketID < buckets[j].BucketID
		}
		return buckets[i].BucketStart.Before(buckets[j].BucketStart.Time)
	})

	return Emission{Sources: sourceList, Buckets: buckets}
}

func (a *accumulator) bucket() Bucket {
	bucket := Bucket{
		BucketStart:        MillisTime{Time: a.key.bucketStart},
		UserID:             a.key.userID,
		NodeID:             a.key.nodeID,
		SourceRef:          a.key.sourceRef,
		DestinationClass:   a.key.destinationClass,
		ProbeSignature:     a.key.probeSignature,
		ProbeConfidence:    a.key.probeConfidence,
		DestinationKind:    a.key.destinationKind,
		DestinationPort:    a.key.destinationPort,
		Network:            a.key.network,
		AppProtocol:        a.key.appProtocol,
		SniffSource:        a.key.sniffSource,
		SniffConfidence:    a.key.sniffConfidence,
		ConnectionCount:    a.connectionCount,
		UploadBytes:        a.uploadBytes,
		DownloadBytes:      a.downloadBytes,
		ActiveMilliseconds: a.activeMilliseconds,
		TransitionInCount:  a.transitionInCount,
		ClassifierVersion:  a.key.classifierVersion,
	}
	if a.key.destinationClass == DestinationOther {
		bucket.UnknownDestinationCount = uint32(len(a.unknownAddresses))
	}
	bucket.BucketID = deterministicBucketID(bucket)
	return bucket
}

func deterministicBucketID(bucket Bucket) string {
	name := strings.Join([]string{
		strconv.FormatUint(bucket.NodeID, 10),
		strconv.FormatUint(bucket.UserID, 10),
		strconv.FormatInt(bucket.BucketStart.UnixMilli(), 10),
		bucket.SourceRef,
		string(bucket.DestinationClass),
		bucket.ProbeSignature,
		string(bucket.DestinationKind),
		strconv.FormatUint(uint64(bucket.DestinationPort), 10),
		string(bucket.Network),
		string(bucket.AppProtocol),
		string(bucket.SniffSource),
		bucket.ClassifierVersion,
	}, "|")
	return uuid.NewSHA1(bucketNamespace, []byte(name)).String()
}

func normalizeNetwork(network Network) Network {
	switch network {
	case NetworkTCP, NetworkUDP:
		return network
	default:
		return NetworkUnknown
	}
}

func normalizeAppProtocol(protocol AppProtocol) AppProtocol {
	switch protocol {
	case AppProtocolHTTP, AppProtocolTLS, AppProtocolQUIC:
		return protocol
	default:
		return AppProtocolUnknown
	}
}

func normalizeSniffSource(source SniffSource) SniffSource {
	switch source {
	case SniffOriginal, SniffHTTPHost, SniffTLSSNI, SniffQUIC:
		return source
	default:
		return SniffNone
	}
}

func normalizeConfidence(confidence Confidence) Confidence {
	switch confidence {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return confidence
	default:
		return ConfidenceUnknown
	}
}
