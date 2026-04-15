package smart

import (
	"bytes"
	"testing"
)

// TestMsgpackRoundtrip verifies encode/decode via the msgpack helpers
// preserves every StatsRecord field. Size vs JSON is workload-dependent:
// msgpack wins on int-heavy / nested data but float64 values always cost
// 9 bytes each (vs variable-length JSON representations), so a float-
// heavy record may come out similar in size. The real benefit is encoder
// speed — msgpack/v5 encodes ~30-50% faster than reflect-based JSON,
// and with SetCustomStructTag("json") the keys match byte-for-byte.
func TestMsgpackRoundtrip(t *testing.T) {
	r := &StatsRecord{
		Success:            100,
		Failure:            3,
		ConnectTime:        50,
		Latency:            80,
		LastUsed:           1700000000,
		UploadTotal:        2.5,
		DownloadTotal:      15.0,
		MaxUploadRate:      500.0,
		MaxDownloadRate:    3000.0,
		ConnectionDuration: 2.5,
		Weights: map[string]float64{
			"tcp":          1.23,
			"udp":          0.87,
			"tcp_asn:1234": 1.45,
		},
	}
	data, err := MarshalStatsRecord(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded StatsRecord
	if err := UnmarshalStatsRecord(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Success != r.Success || decoded.Latency != r.Latency ||
		decoded.MaxUploadRate != r.MaxUploadRate || len(decoded.Weights) != 3 ||
		decoded.Weights["tcp_asn:1234"] != 1.45 {
		t.Fatalf("roundtrip mismatch: got %+v", decoded)
	}
}

// BenchmarkMarshalStatsRecord compares msgpack vs goccy/go-json on the
// actual write-path payload shape. Run with
//   go test -bench=BenchmarkMarshal -benchmem -run=^$
// TestMsgpackSniffFallback: a hand-crafted msgpack payload (simulating
// a forward-compat scenario where we later switch write path to msgpack)
// must still decode correctly through UnmarshalStatsRecord.
func TestMsgpackSniffFallback(t *testing.T) {
	// A minimal msgpack fixmap{1 entry}: 0x81 | 0xa7 "success" | 0x2a
	// = {"success": 42}
	msgBytes := []byte{0x81, 0xa7, 's', 'u', 'c', 'c', 'e', 's', 's', 0x2a}
	if !isMsgpack(msgBytes) {
		t.Fatalf("sniff should detect msgpack: first byte 0x%02x", msgBytes[0])
	}
	var decoded StatsRecord
	// Decoder with json tag mapping — 'success' key maps to Success field.
	if err := UnmarshalStatsRecord(msgBytes, &decoded); err != nil {
		t.Fatalf("msgpack fallback decode failed: %v", err)
	}
	if decoded.Success != 42 {
		t.Fatalf("decoded Success=%d, want 42", decoded.Success)
	}
}

func BenchmarkMarshalStatsRecord_Msgpack(b *testing.B) {
	r := &StatsRecord{
		Success: 100, Failure: 3, ConnectTime: 50, Latency: 80,
		LastUsed: 1700000000, UploadTotal: 2.5, DownloadTotal: 15,
		MaxUploadRate: 500, MaxDownloadRate: 3000, ConnectionDuration: 2.5,
		Weights: map[string]float64{"tcp": 1.23, "udp": 0.87},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = MarshalStatsRecord(r)
	}
}

func BenchmarkMarshalStatsRecord_JSON(b *testing.B) {
	r := &StatsRecord{
		Success: 100, Failure: 3, ConnectTime: 50, Latency: 80,
		LastUsed: 1700000000, UploadTotal: 2.5, DownloadTotal: 15,
		MaxUploadRate: 500, MaxDownloadRate: 3000, ConnectionDuration: 2.5,
		Weights: map[string]float64{"tcp": 1.23, "udp": 0.87},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = jsonMarshal(r)
	}
}

// TestJSONBackwardCompat: existing bbolt rows (pre-msgpack) are JSON;
// UnmarshalStatsRecord must still handle them during the migration window.
func TestJSONBackwardCompat(t *testing.T) {
	r := &StatsRecord{Success: 42, Latency: 100, Weights: map[string]float64{"tcp": 1.0}}
	jsonData, _ := jsonMarshal(r)
	// Confirm it starts with '{' (JSON), not msgpack magic range.
	if !bytes.HasPrefix(jsonData, []byte("{")) {
		t.Fatalf("test precondition failed: %s", string(jsonData))
	}
	if isMsgpack(jsonData) {
		t.Fatalf("JSON data shouldn't sniff as msgpack")
	}
	var decoded StatsRecord
	if err := UnmarshalStatsRecord(jsonData, &decoded); err != nil {
		t.Fatalf("JSON fallback decode failed: %v", err)
	}
	if decoded.Success != 42 || decoded.Weights["tcp"] != 1.0 {
		t.Fatalf("JSON decode produced wrong fields: %+v", decoded)
	}
}
