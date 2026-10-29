package lightgbm

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/smart"
)

func TestModelPredicts(t *testing.T) {
	model := NewWeightModel(filepath.Join("testdata", "named_v4.txt"))
	if err := model.Load(); err != nil {
		t.Fatal(err)
	}
	if !model.IsLoaded() || model.Features() == 0 {
		t.Fatal("model not loaded")
	}
	input := &smart.ModelInput{
		Success: 12, Failure: 1, ConnectTime: 80, Latency: 120,
		UploadTotal: 0.2, HistoryUploadTotal: 3, DownloadTotal: 4, HistoryDownloadTotal: 40,
		MaxuploadRate: 120, MaxdownloadRate: 2400, ConnectionDuration: 1.5, HistoryConnectionDuration: 2,
		IsTCP: true, Host: "*.example.com", DestIP: "93.184.216.34", DestPort: 443,
		DestIPASN: "15133 EdgeCast", DestGeoIP: []string{"US"}, ExitRegion: "jp",
	}
	weight, _ := model.PredictWeight(input, 1)
	if weight <= 0 {
		t.Fatalf("weight %v", weight)
	}
	if w, _ := model.PredictWeight(&smart.ModelInput{Success: 1}, 1); w != 0 {
		t.Fatal("prediction below the minimum sample count")
	}
}

func TestFeatureLayout(t *testing.T) {
	features := prepareFeatures(&smart.ModelInput{Success: 3, IsUDP: true, ExitRegion: "hk", DestPort: 53})
	if len(features) != MaxFeatureSize {
		t.Fatalf("%d features", len(features))
	}
	if features[0] != 3 || features[15] != 1 || features[16] != 0 {
		t.Fatalf("counters %v", features[:17])
	}
	if features[30] == 0 {
		t.Fatal("exit region not encoded")
	}
	if features[22] != 7 {
		t.Fatalf("DNS port feature %v", features[22])
	}
}

func TestMissingModel(t *testing.T) {
	model := NewWeightModel(filepath.Join(t.TempDir(), "Model.bin"))
	if model.Load() == nil || model.IsLoaded() {
		t.Fatal("missing model loaded")
	}
	weight, predicted := model.PredictWeight(&smart.ModelInput{Success: 5, Failure: 1, ConnectTime: 100, Latency: 100}, 1)
	if predicted || weight <= 0 {
		t.Fatalf("fallback weight %v %v", weight, predicted)
	}
}
