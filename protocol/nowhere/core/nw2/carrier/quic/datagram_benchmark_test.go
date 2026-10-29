package quic

import (
	"context"
	"errors"
	"testing"
)

var benchmarkSendBytes int

func BenchmarkPMTURetry(b *testing.B) {
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		runPMTURetryBenchmark(b, payload)
	}
}

func runPMTURetryBenchmark(tb testing.TB, payload []byte) {
	tb.Helper()
	prober := NewDatagramProber(func() int { return 1500 })
	calls := 0
	err := SendUDPData(
		context.Background(),
		func(_ context.Context, frame []byte) error {
			calls++
			if calls == 1 {
				return &DatagramTooLargeError{MaxDatagramSize: 1200, Cause: errors.New("path shrink")}
			}
			benchmarkSendBytes += len(frame)
			return nil
		},
		prober,
		1,
		func() uint32 { return 1 },
		payload,
	)
	if err != nil {
		tb.Fatal(err)
	}
}

func TestPMTURetryAllocationCeiling(t *testing.T) {
	payload := make([]byte, 1400)
	allocs := testing.AllocsPerRun(50, func() {
		runPMTURetryBenchmark(t, payload)
	})
	t.Logf("PMTU retry allocations/op = %.1f", allocs)
	if allocs > 7 {
		t.Fatalf("PMTU retry allocations/op = %.1f, ceiling 7", allocs)
	}
}
