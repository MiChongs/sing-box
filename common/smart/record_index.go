package smart

import (
	"sync"
	"sync/atomic"

	"github.com/puzpuzpuz/xsync/v3"
)

// The record index mirrors recordCache per (config, group) so node-level
// lookups (LookupAnyAtomicRecord, on every dial) and per-group walks
// (IterateAtomicRecords) no longer scan every cached key of every group.
// A record joins the index right before it is offered to recordCache and
// leaves through the cache's onRemove hook once ristretto evicts, rejects
// or replaces it, so the index tracks what the cache actually holds.

type recordScope struct {
	config, group string
}

type recordGroupIndex struct {
	mu    sync.RWMutex
	nodes map[string]*nodeRecords
}

type nodeRecords struct {
	// latest is the node's most recently created or used record — the one
	// LookupAnyAtomicRecord answers with.
	latest atomic.Pointer[AtomicStatsRecord]
	recs   map[*AtomicStatsRecord]struct{}
}

var recordIndex = xsync.NewMapOf[recordScope, *recordGroupIndex]()

func newRecordGroupIndex() *recordGroupIndex {
	return &recordGroupIndex{nodes: make(map[string]*nodeRecords)}
}

// indexRecord adds a freshly created record and makes it its node's latest.
func indexRecord(rec *AtomicStatsRecord) {
	gi, _ := recordIndex.LoadOrCompute(recordScope{rec.config, rec.group}, newRecordGroupIndex)
	gi.mu.Lock()
	n := gi.nodes[rec.node]
	if n == nil {
		n = &nodeRecords{recs: make(map[*AtomicStatsRecord]struct{}, 4)}
		gi.nodes[rec.node] = n
	}
	n.recs[rec] = struct{}{}
	n.latest.Store(rec)
	gi.mu.Unlock()
}

// touchRecord marks an indexed record as its node's latest. Records the
// index no longer holds (already evicted) are left out.
func touchRecord(rec *AtomicStatsRecord) {
	gi, ok := recordIndex.Load(recordScope{rec.config, rec.group})
	if !ok {
		return
	}
	gi.mu.RLock()
	if n := gi.nodes[rec.node]; n != nil && n.latest.Load() != rec {
		if _, held := n.recs[rec]; held {
			n.latest.Store(rec)
		}
	}
	gi.mu.RUnlock()
}

// unindexRecord is recordCache's onRemove hook.
func unindexRecord(rec *AtomicStatsRecord) {
	if rec == nil {
		return
	}
	gi, ok := recordIndex.Load(recordScope{rec.config, rec.group})
	if !ok {
		return
	}
	gi.mu.Lock()
	if n := gi.nodes[rec.node]; n != nil {
		delete(n.recs, rec)
		if len(n.recs) == 0 {
			delete(gi.nodes, rec.node)
		} else if n.latest.Load() == rec {
			for other := range n.recs {
				n.latest.Store(other)
				break
			}
		}
	}
	gi.mu.Unlock()
}

// latestRecord returns the node's latest cached record, or nil.
func latestRecord(group, config, node string) *AtomicStatsRecord {
	gi, ok := recordIndex.Load(recordScope{config, group})
	if !ok {
		return nil
	}
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	if n := gi.nodes[node]; n != nil {
		return n.latest.Load()
	}
	return nil
}

// groupRecords snapshots every indexed record of one group.
func groupRecords(group, config string) []*AtomicStatsRecord {
	gi, ok := recordIndex.Load(recordScope{config, group})
	if !ok {
		return nil
	}
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	var out []*AtomicStatsRecord
	for _, n := range gi.nodes {
		for rec := range n.recs {
			out = append(out, rec)
		}
	}
	return out
}
