package smart

import (
	"sync"
	"sync/atomic"
)

// Engine holds the evidence shared by every Smart group in the process:
// global/family cells, site cells and exact-target cells, plus the incumbent
// history. Groups are views onto it keyed by their tag, so a reload that
// keeps a group's tag keeps its evidence.
type Engine struct {
	aggregate *Table
	site      *Table
	exact     *Table
	history   *history
	names     *interner
	blocks    *Blocks
	tick      atomic.Uint64

	access sync.Mutex
	groups map[uint32]*Group
}

func NewEngine() *Engine {
	return &Engine{
		aggregate: NewTable(aggregateCapacity),
		site:      NewTable(siteCapacity),
		exact:     NewTable(exactCapacity),
		history:   newHistory(historyCapacity),
		names:     newInterner(),
		blocks:    NewBlocks(),
		groups:    make(map[uint32]*Group),
	}
}

var defaultEngine = sync.OnceValue(NewEngine)

// Default returns the process-wide engine.
func Default() *Engine { return defaultEngine() }

// Blocks returns the host status records.
func (e *Engine) Blocks() *Blocks { return e.blocks }

// NodeID interns a node tag.
func (e *Engine) NodeID(tag string) uint32 { return e.names.id(tag) }

// NodeName resolves an interned node id.
func (e *Engine) NodeName(id uint32) string { return e.names.name(id) }

// Group returns the group view for tag, creating it on first use.
func (e *Engine) Group(tag string) *Group {
	id := e.names.id(tag)
	e.access.Lock()
	defer e.access.Unlock()
	g := e.groups[id]
	if g == nil {
		g = newGroup(e, id, tag)
		e.groups[id] = g
	}
	return g
}

// ForgetGroup drops every cell and incumbent of a group (flush).
func (e *Engine) ForgetGroup(tag string) FlushStats {
	id, ok := e.names.lookup(tag)
	if !ok {
		return FlushStats{}
	}
	match := func(k Key, _ *Cell) bool { return k.Group == id }
	stats := FlushStats{
		Aggregate: e.aggregate.DeleteFunc(match),
		Site:      e.site.DeleteFunc(match),
		Exact:     e.exact.DeleteFunc(match),
	}
	e.history.deleteGroup(id)
	stats.Blocks = e.blocks.ForgetGroup(id)
	e.access.Lock()
	if g := e.groups[id]; g != nil {
		g.resetState()
	}
	e.access.Unlock()
	return stats
}

// ForgetNodes drops the cells of group members that are no longer members.
func (e *Engine) ForgetNodes(group uint32, keep func(node uint32) bool) {
	match := func(k Key, _ *Cell) bool { return k.Group == group && !keep(k.Node) }
	e.aggregate.DeleteFunc(match)
	e.site.DeleteFunc(match)
	e.exact.DeleteFunc(match)
	e.blocks.ForgetNodes(group, keep)
}

// FlushStats counts the cells a flush removed.
type FlushStats struct {
	Aggregate int `json:"aggregate"`
	Site      int `json:"site"`
	Exact     int `json:"exact"`
	Blocks    int `json:"blocks"`
}

// CacheStats describes the evidence tables.
type CacheStats struct {
	Aggregate        int    `json:"aggregate"`
	AggregateEvicted uint64 `json:"aggregateEvicted"`
	Site             int    `json:"site"`
	SiteEvicted      uint64 `json:"siteEvicted"`
	Exact            int    `json:"exact"`
	ExactEvicted     uint64 `json:"exactEvicted"`
}

func (e *Engine) CacheStats() CacheStats {
	return CacheStats{
		Aggregate:        e.aggregate.Len(),
		AggregateEvicted: e.aggregate.Evicted(),
		Site:             e.site.Len(),
		SiteEvicted:      e.site.Evicted(),
		Exact:            e.exact.Len(),
		ExactEvicted:     e.exact.Evicted(),
	}
}

func (e *Engine) table(layer Layer) *Table {
	switch layer {
	case LayerSite:
		return e.site
	case LayerExact:
		return e.exact
	default:
		return e.aggregate
	}
}
