package telemetry

import (
	"testing"
	"time"
)

func TestRuntimeCatalogClassifiesKnownProbeTargetsAsLowConfidence(t *testing.T) {
	classifier, err := NewClassifier(runtimeCatalog(), time.Now)
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}

	tests := []struct {
		name        string
		destination Destination
		signature   string
	}{
		{"gstatic http", Destination{Address: "www.gstatic.com", Port: 80, Kind: DestinationDomain, AppProtocol: AppProtocolHTTP}, "gstatic_http"},
		{"gstatic https", Destination{Address: "www.gstatic.com", Port: 443, Kind: DestinationDomain, AppProtocol: AppProtocolTLS}, "gstatic_https"},
		{"cloudflare one http", Destination{Address: "1.1.1.1", Port: 80, Kind: DestinationIPv4, AppProtocol: AppProtocolHTTP}, "cloudflare_one_http"},
		{"cloudflare one https", Destination{Address: "1.1.1.1", Port: 443, Kind: DestinationIPv4, AppProtocol: AppProtocolTLS}, "cloudflare_one_https"},
		{"cloudflare captive http", Destination{Address: "cp.cloudflare.com", Port: 80, Kind: DestinationDomain, AppProtocol: AppProtocolHTTP}, "cloudflare_captive_http"},
		{"cloudflare captive https", Destination{Address: "cp.cloudflare.com", Port: 443, Kind: DestinationDomain, AppProtocol: AppProtocolTLS}, "cloudflare_captive_https"},
		{"android connectivity http", Destination{Address: "connectivitycheck.gstatic.com", Port: 80, Kind: DestinationDomain, AppProtocol: AppProtocolHTTP}, "android_connectivity_http"},
		{"android connectivity https", Destination{Address: "connectivitycheck.gstatic.com", Port: 443, Kind: DestinationDomain, AppProtocol: AppProtocolTLS}, "android_connectivity_https"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifier.Classify(test.destination)
			if got.Class != DestinationProbe {
				t.Fatalf("Classify() class = %q, want %q", got.Class, DestinationProbe)
			}
			if got.Signature != test.signature {
				t.Fatalf("Classify() signature = %q, want %q", got.Signature, test.signature)
			}
			if got.Confidence != ConfidenceLow {
				t.Fatalf("Classify() confidence = %q, want %q", got.Confidence, ConfidenceLow)
			}
			if got.CatalogVersion != "builtin-v3" {
				t.Fatalf("Classify() catalog = %q, want builtin-v3", got.CatalogVersion)
			}
		})
	}
}

func TestRuntimeCatalogDoesNotBroadenProbeRules(t *testing.T) {
	classifier, err := NewClassifier(runtimeCatalog(), time.Now)
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}

	tests := []Destination{
		{
			Address:     "cdn.gstatic.com",
			Port:        443,
			Kind:        DestinationDomain,
			AppProtocol: AppProtocolTLS,
		},
		{
			Address:     "cp.cloudflare.com",
			Port:        80,
			Kind:        DestinationDomain,
			AppProtocol: AppProtocolTLS,
		},
		{
			Address:     "1.1.1.2",
			Port:        443,
			Kind:        DestinationIPv4,
			AppProtocol: AppProtocolTLS,
		},
		{
			Address:     "connectivitycheck.gstatic.com",
			Port:        8443,
			Kind:        DestinationDomain,
			AppProtocol: AppProtocolTLS,
		},
	}

	for _, destination := range tests {
		got := classifier.Classify(destination)
		if got.Class == DestinationProbe {
			t.Fatalf("Classify(%#v) unexpectedly matched probe", destination)
		}
	}
}
