package telemetry

import (
	"testing"
	"time"
)

func TestClassifierMatchesCloudflareHTTPProbe(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	classifier, err := NewClassifier(Catalog{
		Version:    "2026-07-29.1",
		ValidUntil: now.Add(time.Hour),
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

	got := classifier.Classify(Destination{
		Address:     "1.1.1.1",
		Port:        80,
		Kind:        DestinationIPv4,
		AppProtocol: AppProtocolHTTP,
	})

	if got.Class != DestinationProbe {
		t.Fatalf("Classify() class = %q, want %q", got.Class, DestinationProbe)
	}
	if got.Signature != "cloudflare_one_http" {
		t.Fatalf("Classify() signature = %q", got.Signature)
	}
	if got.Confidence != ConfidenceHigh {
		t.Fatalf("Classify() confidence = %q, want %q", got.Confidence, ConfidenceHigh)
	}
}

func TestClassifierKeepsGenericGoogleLowConfidence(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	classifier, err := NewClassifier(Catalog{
		Version:    "2026-07-29.1",
		ValidUntil: now.Add(time.Hour),
		Rules: []ProbeRule{{
			ID:         "google_generic_probe_like",
			Host:       "www.google.com",
			Ports:      []uint16{443},
			Protocols:  []AppProtocol{AppProtocolTLS},
			Confidence: ConfidenceLow,
		}},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}

	got := classifier.Classify(Destination{
		Address:     "WWW.GOOGLE.COM.",
		Port:        443,
		Kind:        DestinationDomain,
		AppProtocol: AppProtocolTLS,
	})

	if got.Signature != "google_generic_probe_like" || got.Confidence != ConfidenceLow {
		t.Fatalf("Classify() = %#v", got)
	}
}

func TestClassifierExpiresToUnknown(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	classifier, err := NewClassifier(Catalog{
		Version:    "2026-07-28.1",
		ValidUntil: now.Add(-time.Second),
		Rules: []ProbeRule{{
			ID:         "cloudflare_connectivity",
			Host:       "cp.cloudflare.com",
			Confidence: ConfidenceHigh,
		}},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}

	got := classifier.Classify(Destination{
		Address: "cp.cloudflare.com",
		Kind:    DestinationDomain,
	})

	if got.Class != DestinationUnknown {
		t.Fatalf("Classify() class = %q, want %q", got.Class, DestinationUnknown)
	}
}

func TestClassifierSuffixRequiresLabelBoundary(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	classifier, err := NewClassifier(Catalog{
		Version:    "2026-07-29.1",
		ValidUntil: now.Add(time.Hour),
		Rules: []ProbeRule{{
			ID:          "gstatic_connectivity",
			Host:        "gstatic.com",
			MatchSuffix: true,
			Confidence:  ConfidenceHigh,
		}},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}

	matched := classifier.Classify(Destination{
		Address: "connectivitycheck.gstatic.com",
		Kind:    DestinationDomain,
	})
	if matched.Signature != "gstatic_connectivity" {
		t.Fatalf("valid subdomain did not match: %#v", matched)
	}

	notMatched := classifier.Classify(Destination{
		Address: "evilgstatic.com",
		Kind:    DestinationDomain,
	})
	if notMatched.Class != DestinationOther {
		t.Fatalf("non-boundary suffix class = %q, want %q", notMatched.Class, DestinationOther)
	}
}

func TestClassifierRejectsUnsafeCatalogRules(t *testing.T) {
	now := time.Now()
	tests := []ProbeRule{
		{ID: "duplicate", Host: "safe.example", Confidence: ConfidenceHigh},
		{ID: "duplicate", Host: "other.example", Confidence: ConfidenceHigh},
		{ID: "uppercase", Host: "SAFE.EXAMPLE", Confidence: ConfidenceHigh},
		{ID: "bad host", Host: "-bad.example", Confidence: ConfidenceHigh},
		{ID: "bad_protocol", Host: "safe.example", Protocols: []AppProtocol{"smtp"}, Confidence: ConfidenceHigh},
		{ID: "bad_confidence", Host: "safe.example", Confidence: "certain"},
	}
	for _, rule := range tests[1:] {
		rules := []ProbeRule{rule}
		if rule.ID == "duplicate" {
			rules = tests[:2]
		}
		if _, err := NewClassifier(Catalog{
			Version:    "v1",
			ValidUntil: now.Add(time.Hour),
			Rules:      rules,
		}, func() time.Time { return now }); err == nil {
			t.Fatalf("NewClassifier() accepted unsafe rule %#v", rule)
		}
	}
}
