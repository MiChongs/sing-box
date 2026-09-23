package group

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

// Hot-path object pools for PickOutbound / fillProxies.
//
// Every dial walks through fillProxies → a handful of same-shape temporary
// maps (rankMap, delayMap, proxyByName, inNamed). On a 600-node group with
// 1 kQPS these allocate ~4 MB/s of short-lived map buckets, which shows up
// as GC STW jitter in production traces.
//
// Pooling the backing maps + clear()-on-return (Go 1.21+) lets us reuse
// the same buckets across dials. We never pool across packages — every
// Get/Put pair lives within a single function scope so there is no risk
// of a stale map leaking to a concurrent caller.
//
// Map pools store pointers-to-maps; pool.Get returns an already-cleared
// map ready to fill. The Put side must clear before releasing so the next
// caller gets an empty map with the existing bucket capacity.

var (
	stringFloatMapPool = sync.Pool{
		New: func() any {
			m := make(map[string]float64, 64)
			return &m
		},
	}
	stringUint16MapPool = sync.Pool{
		New: func() any {
			m := make(map[string]uint16, 64)
			return &m
		},
	}
	stringOutboundMapPool = sync.Pool{
		New: func() any {
			m := make(map[string]adapter.Outbound, 64)
			return &m
		},
	}
	stringBoolMapPool = sync.Pool{
		New: func() any {
			m := make(map[string]bool, 64)
			return &m
		},
	}
)

// getStringFloatMap returns a cleared map[string]float64 from the pool.
// Caller must call putStringFloatMap with the same pointer when done.
func getStringFloatMap() *map[string]float64 {
	return stringFloatMapPool.Get().(*map[string]float64)
}

func putStringFloatMap(m *map[string]float64) {
	if m == nil {
		return
	}
	clear(*m)
	stringFloatMapPool.Put(m)
}

func getStringUint16Map() *map[string]uint16 {
	return stringUint16MapPool.Get().(*map[string]uint16)
}

func putStringUint16Map(m *map[string]uint16) {
	if m == nil {
		return
	}
	clear(*m)
	stringUint16MapPool.Put(m)
}

func getStringOutboundMap() *map[string]adapter.Outbound {
	return stringOutboundMapPool.Get().(*map[string]adapter.Outbound)
}

func putStringOutboundMap(m *map[string]adapter.Outbound) {
	if m == nil {
		return
	}
	clear(*m)
	stringOutboundMapPool.Put(m)
}

func getStringBoolMap() *map[string]bool {
	return stringBoolMapPool.Get().(*map[string]bool)
}

func putStringBoolMap(m *map[string]bool) {
	if m == nil {
		return
	}
	clear(*m)
	stringBoolMapPool.Put(m)
}
