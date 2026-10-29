package memstat

import "runtime/metrics"

var inuseMetrics = [...]string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/heap/free:bytes",
	"/memory/classes/heap/stacks:bytes",
}

// Inuse reports StackInuse + HeapInuse + HeapIdle - HeapReleased without the
// stop-the-world pause of runtime.ReadMemStats, so status endpoints polled
// every second do not stall every goroutine.
func Inuse() uint64 {
	var samples [len(inuseMetrics)]metrics.Sample
	for i, name := range inuseMetrics {
		samples[i].Name = name
	}
	metrics.Read(samples[:])
	var inuse uint64
	for _, sample := range samples {
		if sample.Value.Kind() == metrics.KindUint64 {
			inuse += sample.Value.Uint64()
		}
	}
	return inuse
}
