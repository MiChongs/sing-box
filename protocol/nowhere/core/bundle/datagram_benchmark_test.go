package bundle

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

var benchmarkFlows []*quicDatagramFlow

func BenchmarkQUIC64Flows(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		flows := make([]*quicDatagramFlow, 64)
		for index := range flows {
			flows[index] = newQUICDatagramFlow(nil, wire.FlowID(index+1))
			flows[index].markReady()
		}
		benchmarkFlows = flows
	}
}

func BenchmarkQUICQueueFull(b *testing.B) {
	flow := newQUICDatagramFlow(nil, 1)
	flow.markReady()
	payload := []byte("packet")
	for i := 0; i < cap(flow.packets); i++ {
		if !flow.enqueue(payload, nil) {
			b.Fatal("failed to prefill queue")
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if flow.enqueue(payload, nil) {
			b.Fatal("full queue accepted packet")
		}
	}
}

func TestQUICQueueAllocationCeilings(t *testing.T) {
	flowAllocs := testing.AllocsPerRun(20, func() {
		flows := make([]*quicDatagramFlow, 64)
		for index := range flows {
			flows[index] = newQUICDatagramFlow(nil, wire.FlowID(index+1))
			flows[index].markReady()
		}
		benchmarkFlows = flows
	})
	t.Logf("64-flow allocations/op = %.1f", flowAllocs)
	if flowAllocs > 282.7 {
		t.Fatalf("64-flow allocations/op = %.1f, ceiling 282.7", flowAllocs)
	}

	flow := newQUICDatagramFlow(nil, 1)
	flow.markReady()
	for i := 0; i < cap(flow.packets); i++ {
		flow.enqueue(nil, nil)
	}
	fullAllocs := testing.AllocsPerRun(100, func() {
		if flow.enqueue(nil, nil) {
			t.Fatal("full queue accepted packet")
		}
	})
	t.Logf("queue-full allocations/op = %.1f", fullAllocs)
	if fullAllocs > 1 {
		t.Fatalf("queue-full allocations/op = %.1f, ceiling 1", fullAllocs)
	}
}
