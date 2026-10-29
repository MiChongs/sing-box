package memstat

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInuseMatchesMemStats(t *testing.T) {
	runtime.GC()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	expected := memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased
	inuse := Inuse()
	require.NotZero(t, inuse)
	require.InEpsilon(t, float64(expected), float64(inuse), 0.1)
}

func BenchmarkInuse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Inuse()
	}
}

func BenchmarkReadMemStats(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
	}
}
