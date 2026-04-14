package lightgbm

import (
	"testing"

	"github.com/sagernet/sing-box/common/smart"
)

// TestPrepareFeaturesLength verifies the feature vector always has MaxFeatureSize dims.
func TestPrepareFeaturesLength(t *testing.T) {
	inputs := []*smart.ModelInput{
		{},
		{Success: 10, Failure: 2, ConnectTime: 123, Latency: 45, IsTCP: true},
		{Success: 100, UploadTotal: 10.5, DownloadTotal: 200.0, DestPort: 443, Host: "youtube.com"},
		{Success: 5, IsUDP: true, DestIP: "1.1.1.1", DestIPASN: "AS13335 cloudflare", DestPort: 53},
	}
	for i, in := range inputs {
		features := PrepareFeatures(in)
		if len(features) != MaxFeatureSize {
			t.Errorf("case %d: expected %d features, got %d", i, MaxFeatureSize, len(features))
		}
	}
}

func TestExtractASNFeature(t *testing.T) {
	// mihomo parity: name-keyword match takes precedence; numeric fallback
	// requires the string to START with digits (regex ^(\d+)).
	cases := map[string]int{
		"":                      0,
		"AS13335 cloudflare":    6,  // cloudflare keyword wins
		"AS15169 google llc":    1,  // google keyword wins
		"200 some unknown":      50, // pure digits → 200 < 1000
		"50000 smallprovider":   53, // 50000 in [50000, 150000)
		"999999 future":         54, // >= 150000
	}
	for input, want := range cases {
		got := extractASNFeature(input)
		if got != want {
			t.Errorf("extractASNFeature(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestExtractDomainTypeFeature(t *testing.T) {
	// mihomo parity: IPv4 literal is detected FIRST (returns 1), even if it
	// would also match DNS keywords like 1.1.1.1.
	cases := map[string]int{
		"":                    0,
		"1.1.1.1":             1, // IPv4 literal short-circuits to 1
		"dns.google":          6, // DNS keyword (not IPv4)
		"www.youtube.com":     2, // streaming
		"steam.com":           3, // game
		"zoom.us":             4, // communication
		"api.stripe.com":      5, // api
		"example.gov":         14,
		"example.edu":         15,
	}
	for input, want := range cases {
		got := extractDomainTypeFeature(input)
		if got != want {
			t.Errorf("extractDomainTypeFeature(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestExtractPortFeature(t *testing.T) {
	cases := map[uint16]int{
		0:     20, // system port range
		22:    1,  // SSH
		53:    36, // DNS service port override
		443:   7,  // HTTPS (checked via wellKnownPorts after dns/api/game/comm)
		25565: 30, // Minecraft (gameSpecificPorts)
		8080:  35, // API service port
	}
	for port, want := range cases {
		got := extractPortFeature(port)
		if got != want {
			t.Errorf("extractPortFeature(%d) = %d, want %d", port, got, want)
		}
	}
}

func TestHashStringToFloatDeterministic(t *testing.T) {
	a := hashStringToFloat("example.com", 1000)
	b := hashStringToFloat("example.com", 1000)
	if a != b {
		t.Errorf("hash not deterministic: %v vs %v", a, b)
	}
	if a < 1 || a > 1000 {
		t.Errorf("hash out of range [1,1000]: %v", a)
	}
	if z := hashStringToFloat("", 1000); z != 0 {
		t.Errorf("empty string should hash to 0, got %v", z)
	}
}

func TestPredictWeightFallback(t *testing.T) {
	// nil model must fall back to CalculateWeight without panicking
	var m *WeightModel
	input := &smart.ModelInput{Success: 10, Failure: 2, ConnectTime: 100, Latency: 50}
	_, predicted := m.PredictWeight(input, 1.0)
	if predicted {
		t.Errorf("nil model should not return predicted=true")
	}
}

func TestCollectorDefaultSize(t *testing.T) {
	dc, err := NewDataCollector("/tmp/test_collector.csv", 0)
	if err != nil {
		t.Fatalf("NewDataCollector: %v", err)
	}
	if dc.sizeLimit != DefaultCollectorSizeMB*1024*1024 {
		t.Errorf("default size limit mismatch: %d vs %d", dc.sizeLimit, DefaultCollectorSizeMB*1024*1024)
	}
}
