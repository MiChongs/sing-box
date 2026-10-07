package lightgbm

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/smart"
	"github.com/vernesong/leaves"
)

// vernesongNames is the 30-feature layout of vernesong/mihomo's models.
var vernesongNames = strings.Fields(`success failure connect_time latency upload_mb
	history_upload_mb maxuploadrate_kb history_maxuploadrate_kb download_mb
	history_download_mb maxdownloadrate_kb history_maxdownloadrate_kb duration_minutes
	history_duration_minutes last_used_seconds is_udp is_tcp loss_rate cumul_loss_rate
	asn_feature country_feature address_feature port_feature traffic_ratio traffic_density
	connection_type_feature asn_hash host_hash ip_hash geoip_hash`)

func TestResolveLayout(t *testing.T) {
	order := getDefaultFeatureOrder()
	identity := func(n int) []int {
		layout := make([]int, n)
		for i := range layout {
			layout[i] = i
		}
		return layout
	}
	names := func(n int, name func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = name(i)
		}
		return out
	}
	vernesong := append(identity(12),
		slotLastDuration, slotHistoryDuration, 13, 14, 15, slotLossRate, slotCumulLossRate)
	for slot := 16; slot <= 26; slot++ {
		vernesong = append(vernesong, slot)
	}

	for _, tc := range []struct {
		name      string
		names     []string
		nFeatures int
		want      []int
		wantErr   string
	}{
		{"mihomo 27", names(27, func(i int) string { return order[i] }), 27, identity(27), ""},
		{"vernesong 30", vernesongNames, 30, vernesong, ""},
		{"unnamed columns", names(27, func(i int) string { return "Column_" + string(rune('0'+i%10)) }), 27, identity(27), ""},
		{"no names", nil, MaxFeatureSize, identity(MaxFeatureSize), ""},
		{"too many unnamed", nil, MaxFeatureSize + 1, nil, "unnamed features"},
		{"unknown name", []string{"success", "rtt_p99"}, 2, nil, "rtt_p99"},
		{"count mismatch", []string{"success"}, 2, nil, "feature_names lists 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveLayout(tc.names, tc.nFeatures)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("layout = %v, want %v", got, tc.want)
			}
		})
	}
}

// Golden predictions from LightGBM 4.7.0 (Booster.predict, raw_score=True)
// for the models in testdata.
var (
	namedProbes = [][]float64{
		slices.Repeat([]float64{0.5}, 30),
		func() []float64 {
			x := make([]float64, 30)
			for i := range x {
				x[i] = math.Pow(-1, float64(i)) * float64(i) / 10
			}
			return x
		}(),
		slices.Repeat([]float64{math.NaN()}, 30),
	}
	namedGolden  = []float64{0.7883870450329946, 0.987646903317297, 0.9030489803983697}
	linearProbes = [][]float64{{0.3, -1.2, 0.7}, {-2.0, 0.5, -0.1}, {math.NaN(), 1.0, 2.0}}
	linearGolden = []float64{0.7542679784148616, -0.5917109664584459, 0.3364483779142915}
)

// TestV4ModelsMatchLightGBM: version=v4 text models, including linear
// trees, predict exactly what LightGBM itself does.
func TestV4ModelsMatchLightGBM(t *testing.T) {
	for _, tc := range []struct {
		file   string
		probes [][]float64
		golden []float64
	}{
		{"named_v4.txt", namedProbes, namedGolden},
		{"linear_v4.txt", linearProbes, linearGolden},
	} {
		model, err := leaves.LGEnsembleFromFile(filepath.Join("testdata", tc.file), false)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for i, probe := range tc.probes {
			if got := model.PredictSingle(probe, 0); math.Abs(got-tc.golden[i]) > 1e-12 {
				t.Errorf("%s probe %d: got %v, want %v", tc.file, i, got, tc.golden[i])
			}
		}
	}
}

// TestWeightModelNamedLayout: a model naming the vernesong layout gets each
// input from the matching catalog feature, scaled by its transforms.
func TestWeightModelNamedLayout(t *testing.T) {
	m := NewWeightModel(filepath.Join("testdata", "named_v4.txt"))
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	input := &smart.ModelInput{
		Success: 40, Failure: 2, ConnectTime: 90, Latency: 150,
		ConnectionDuration: 3, LastConnectionDuration: 0.5,
		LossRate: 0.02, CumulLossRate: 0.01,
		IsTCP: true, DestPort: 443, Host: "example.com",
	}
	features := layoutFeatures(input, m.layout)
	legacy := PrepareFeatures(input)
	order := getDefaultFeatureOrder()
	legacyIndex := make(map[string]int, len(order))
	for i, name := range order {
		legacyIndex[name] = i
	}
	for i, name := range vernesongNames {
		var want float64
		switch name {
		case "duration_minutes":
			want = math.Log1p(input.LastConnectionDuration)
		case "history_duration_minutes":
			want = math.Log1p(input.ConnectionDuration)
		case "loss_rate":
			want = input.LossRate
		case "cumul_loss_rate":
			want = input.CumulLossRate
		default:
			want = legacy[legacyIndex[name]]
		}
		if features[i] != want {
			t.Errorf("input %d (%s) = %v, want %v", i, name, features[i], want)
		}
	}

	scaled := m.transforms.ApplyTransforms(features)
	for idx, want := range map[int]float64{
		0:  (features[0] - 10) / 20,
		2:  (features[2] - 4) / 2,
		12: (features[12] - 0.5) / 0.25,
		3:  features[3],
	} {
		if scaled[idx] != want {
			t.Errorf("scaled input %d = %v, want %v", idx, scaled[idx], want)
		}
	}
	got, predicted, _ := m.PredictWeight(input, 2)
	if want := m.model.PredictSingle(scaled, 0) * 2; !predicted || got != want {
		t.Fatalf("PredictWeight = %v (predicted %v), want %v", got, predicted, want)
	}
}

func TestWeightModelRejectsUnusable(t *testing.T) {
	named, err := os.ReadFile(filepath.Join("testdata", "named_v4.txt"))
	if err != nil {
		t.Fatal(err)
	}
	linear, err := os.ReadFile(filepath.Join("testdata", "linear_v4.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		content []byte
		wantErr string
	}{
		{"unknown features", linear, "cannot compute: a, b, c"},
		{"transforms order mismatch", []byte(strings.Replace(string(named), "\n0=success\n", "\n0=failure\n", 1)), `names feature 0 "failure"`},
		{"transform index out of range", []byte(strings.Replace(string(named), "std_features=2,12", "std_features=2,30", 1)), "invalid transforms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "model.bin")
			if err := os.WriteFile(path, named, 0o644); err != nil {
				t.Fatal(err)
			}
			m := NewWeightModel(path)
			if err := m.Load(); err != nil {
				t.Fatal(err)
			}
			layout := m.layout

			// A rejected replacement keeps the loaded model in place.
			if err := os.WriteFile(path, tc.content, 0o644); err != nil {
				t.Fatal(err)
			}
			err := m.Load()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if !errors.Is(m.LoadError(), err) || !m.IsLoaded() || !slices.Equal(m.layout, layout) {
				t.Fatalf("after rejection: loadErr=%v loaded=%v layout changed=%v", m.LoadError(), m.IsLoaded(), !slices.Equal(m.layout, layout))
			}
		})
	}

	// A missing file is not a rejection, even after an earlier one.
	path := filepath.Join(t.TempDir(), "model.bin")
	if err := os.WriteFile(path, linear, 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewWeightModel(path)
	if err := m.Load(); err == nil || m.LoadError() == nil {
		t.Fatal("unusable model accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); !errors.Is(err, fs.ErrNotExist) || m.LoadError() != nil {
		t.Fatalf("missing file: err=%v loadErr=%v", err, m.LoadError())
	}
}
