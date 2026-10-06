package wire

import "testing"

var (
	benchmarkDatagramFrame []byte
	benchmarkDatagramCount int
)

func BenchmarkUDPData(b *testing.B) {
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		frame, err := EncodeUDPData(1, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkDatagramFrame = frame
	}
}

func BenchmarkUDP64KiBFragmentation(b *testing.B) {
	payload := make([]byte, UDPPacketMax)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		count := 0
		err := EncodeUDPDataFragmentsYield(1, uint32(i)+1, payload, 1200, func(frame []byte) error {
			benchmarkDatagramFrame = frame
			count++
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
		benchmarkDatagramCount = count
	}
}

func TestDatagramAllocationCeilings(t *testing.T) {
	payload := make([]byte, 1200)
	dataAllocs := testing.AllocsPerRun(100, func() {
		frame, err := EncodeUDPData(1, payload)
		if err != nil {
			t.Fatal(err)
		}
		benchmarkDatagramFrame = frame
	})
	if dataAllocs > 2 {
		t.Fatalf("DATA allocations/op = %.1f, ceiling 2", dataAllocs)
	}

	payload = make([]byte, UDPPacketMax)
	fragmentAllocs := testing.AllocsPerRun(20, func() {
		err := EncodeUDPDataFragmentsYield(1, 1, payload, 1200, func(frame []byte) error {
			benchmarkDatagramFrame = frame
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	// 56 owned output frames plus conservative cross-version headroom.
	if fragmentAllocs > 61.6 {
		t.Fatalf("64 KiB fragmentation allocations/op = %.1f, ceiling 61.6", fragmentAllocs)
	}
}
