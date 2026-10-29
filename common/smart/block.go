package smart

import (
	"sync"
	"sync/atomic"
	"time"
)

// BlockCode is why a node is blocked for a target (vernesong/mihomo host
// status codes). A lower code is stronger and is not overwritten by a
// weaker one.
type BlockCode uint8

const (
	BlockNone BlockCode = iota
	// BlockManual: blocked through the API; kept until flushed.
	BlockManual
	// BlockAnswer: the target did not answer a probe through the node.
	BlockAnswer
	// BlockError: consecutive connection errors; the engine's failure
	// streak handles it, the code is kept for records and the API.
	BlockError
	// BlockLowWeight: the connection quality fell below AllowedWeight.
	BlockLowWeight
	// BlockLoss: repeated TCP retransmission strikes.
	BlockLoss
	// BlockStalled: the node sent data but never received any.
	BlockStalled
)

var blockCodeNames = [...]string{"", "manual", "answer", "error", "lowWeight", "loss", "stalled"}

func (c BlockCode) String() string {
	if int(c) < len(blockCodeNames) {
		return blockCodeNames[c]
	}
	return "unknown"
}

const (
	blockDefaultTTL    = 24 * time.Hour
	blockUDPTTL        = 3 * time.Minute
	blockStalledTTL    = 2 * time.Minute
	blockRetryAfter    = 4 * time.Hour
	blockStrikeWindow  = 5 * time.Minute
	blockStrikeLimit   = 2
	blockViewTTL       = 30 * time.Second
	blockRecordExpired = 7 * 24 * time.Hour
)

// countsTowardHost reports whether a code counts toward declaring the host
// itself broken: errors, low weight and loss do; manual, answer and stalled
// are per-node evidence.
func countsTowardHost(code BlockCode) bool {
	return code == BlockError || code == BlockLowWeight || code == BlockLoss
}

// NodeBlock is one node's block state in one host record.
type NodeBlock struct {
	Code          BlockCode
	Until         int64 // unix seconds, 0 = permanent
	FailCount     int
	Confirmations int
	Host          string // answer: the original host, for rechecks
}

// HostStatus is the block record of one target key (wildcard host or service
// key, network scoped).
type HostStatus struct {
	LastFailure int64
	LastCheck   int64
	Nodes       map[uint32]*NodeBlock

	// cached read view
	viewAt      int64
	viewLimit   int
	viewNodes   map[uint32]BlockCode
	viewBlocked bool
	dirty       bool
}

type blockKey struct {
	group uint32
	scope uint64
	udp   bool
}

// Blocks keeps the host status records of every group.
type Blocks struct {
	access  sync.RWMutex
	records map[blockKey]*HostStatus
	names   map[blockKey]string
	// group-wide blocks: manual API blocks and stability (MAD) blocks
	groupAccess sync.RWMutex
	group       map[uint32]map[uint32]GroupBlock
	groupCount  atomic.Int64
}

// GroupBlock blocks a node for the whole group until a deadline.
type GroupBlock struct {
	Until  int64 // unix seconds
	Reason string
}

func NewBlocks() *Blocks {
	return &Blocks{
		records: make(map[blockKey]*HostStatus),
		names:   make(map[blockKey]string),
		group:   make(map[uint32]map[uint32]GroupBlock),
	}
}

func (b *Blocks) record(key blockKey, name string, create bool) *HostStatus {
	b.access.RLock()
	hs := b.records[key]
	b.access.RUnlock()
	if hs != nil || !create {
		return hs
	}
	b.access.Lock()
	defer b.access.Unlock()
	if hs = b.records[key]; hs == nil {
		hs = &HostStatus{Nodes: make(map[uint32]*NodeBlock)}
		b.records[key] = hs
		b.names[key] = name
	}
	return hs
}

// BlockUpdate is one judged connection outcome for a host record.
type BlockUpdate struct {
	Group   uint32
	Key     string
	UDP     bool
	Node    uint32
	Failure bool
	Checked bool
	Code    BlockCode
	TTL     time.Duration
	Host    string
	// MaxFailedTimes is the error streak that blocks (code 3); HostLimit the
	// number of blocking nodes beyond which the host itself is broken.
	MaxFailedTimes int
	HostLimit      int
}

// Update applies one judgement and reports whether it newly blocked the node
// (and the host is not judged broken as a whole).
func (b *Blocks) Update(u BlockUpdate, now time.Time) bool {
	if !u.Checked || u.Key == "" {
		return false
	}
	if u.Failure && u.Code == BlockAnswer && u.Host == "" {
		return false
	}
	if u.UDP && u.TTL == 0 {
		u.TTL = blockUDPTTL
	}
	ttl := u.TTL
	if ttl <= 0 {
		ttl = blockDefaultTTL
	}
	hs := b.record(blockKey{u.Group, HashString(u.Key), u.UDP}, u.Key, true)
	b.access.Lock()
	defer b.access.Unlock()
	nowUnix := now.Unix()
	hs.expireLocked(nowUnix)
	oldLast := hs.LastFailure
	entry := hs.Nodes[u.Node]
	save := func(failed bool) bool {
		hs.LastCheck = nowUnix
		hs.dirty = true
		hs.viewAt = 0
		if hs.blockingCount(nowUnix) > max(u.HostLimit, 1) {
			return false
		}
		return failed
	}
	// A reachable judgement clears everything but a manual block.
	if !u.Failure && u.Code == BlockNone {
		if entry != nil && entry.Code != BlockManual {
			delete(hs.Nodes, u.Node)
		}
		return save(false)
	}
	recent := oldLast != 0 && nowUnix-oldLast <= int64(blockStrikeWindow/time.Second)
	// The first loss strike only counts.
	if u.Failure && u.Code == BlockLoss {
		count := 1
		if recent && entry != nil && entry.Code == BlockLoss && entry.Until == -1 {
			count = entry.FailCount + 1
		}
		if count < blockStrikeLimit {
			if entry == nil || entry.Code == BlockLoss {
				hs.Nodes[u.Node] = &NodeBlock{Code: BlockLoss, Until: -1, FailCount: count, Confirmations: confirmationsOf(entry)}
			}
			hs.LastFailure = nowUnix
			return save(false)
		}
	}
	if entry != nil && entry.Until != -1 && entry.Code != BlockNone && entry.Code < u.Code {
		// Keep the stronger record.
		return save(false)
	}
	if !u.Failure && u.Code != BlockError {
		return save(false)
	}
	hs.LastFailure = nowUnix
	failed := false
	next := &NodeBlock{Code: u.Code, Host: u.Host}
	switch u.Code {
	case BlockManual:
		next.Until = 0
		failed = true
	case BlockAnswer:
		count := 1
		if entry != nil && entry.Code == BlockAnswer {
			count = entry.FailCount + 1
		}
		if oldLast != 0 && nowUnix-oldLast > int64(blockRetryAfter/time.Second) {
			count = 1
		}
		next.FailCount = count
		answerTTL := ttl
		switch {
		case count == 2:
			answerTTL = 15 * time.Minute
		case count == 3:
			answerTTL = time.Hour
		case count == 4:
			answerTTL = 4 * time.Hour
		case count > 4:
			answerTTL = 24 * time.Hour
		}
		next.Until = nowUnix + int64(answerTTL/time.Second)
		failed = true
	case BlockError:
		count := 1
		if recent && entry != nil && entry.Code == BlockError {
			count = entry.FailCount + 1
		}
		if count < max(u.MaxFailedTimes, 1) {
			next.FailCount = count
			next.Until = -1
			hs.Nodes[u.Node] = next
			return save(false)
		}
		next.Until = nowUnix + int64(ttl/time.Second)
		failed = true
	case BlockLoss:
		if entry != nil && entry.Code == BlockLoss && entry.Until > nowUnix {
			return save(false)
		}
		conf := confirmationsOf(entry) + 1
		lossTTL := ttl
		if u.TTL <= 0 {
			switch {
			case conf == 1:
				lossTTL = 15 * time.Minute
			case conf == 2:
				lossTTL = time.Hour
			case conf == 3:
				lossTTL = 4 * time.Hour
			default:
				lossTTL = 24 * time.Hour
			}
		}
		next.Confirmations = conf
		next.Until = nowUnix + int64(lossTTL/time.Second)
		failed = true
	default:
		next.Until = nowUnix + int64(ttl/time.Second)
		failed = true
	}
	hs.Nodes[u.Node] = next
	return save(failed)
}

func confirmationsOf(e *NodeBlock) int {
	if e == nil || e.Code != BlockLoss {
		return 0
	}
	return e.Confirmations
}

// active reports whether the entry blocks now. Until -1 marks a pending
// strike or error count that does not block yet.
func (e *NodeBlock) active(now int64) bool {
	return e.Until == 0 || e.Until > now
}

func (hs *HostStatus) expireLocked(now int64) {
	for node, e := range hs.Nodes {
		switch {
		case e.Code == BlockManual:
		case e.Until == -1:
			if hs.LastFailure != 0 && now-hs.LastFailure > int64(blockRetryAfter/time.Second) {
				delete(hs.Nodes, node)
			}
		case e.Until <= now:
			if e.Code == BlockLoss && hs.LastFailure != 0 && now-hs.LastFailure <= int64(blockRetryAfter/time.Second) {
				// Keep the confirmation ladder while failures continue.
				e.Until = -1
				e.FailCount = 0
				continue
			}
			delete(hs.Nodes, node)
		}
	}
}

func (hs *HostStatus) blockingCount(now int64) int {
	n := 0
	for _, e := range hs.Nodes {
		if e.Until != -1 && e.active(now) && countsTowardHost(e.Code) {
			n++
		}
	}
	return n
}

// Lookup returns the active block codes of a target, merging the extra keys
// (the service key and its UDP scope), and whether the primary key's host is
// broken as a whole. The returned map is shared and read-only.
func (b *Blocks) Lookup(group uint32, key string, udp bool, hostLimit int, extras []string, now time.Time) (map[uint32]BlockCode, bool) {
	nowUnix := now.Unix()
	nodes, blocked := b.view(blockKey{group, HashString(key), udp}, hostLimit, nowUnix)
	var merged map[uint32]BlockCode
	for _, extra := range extras {
		if extra == "" || extra == key {
			continue
		}
		extraNodes, _ := b.view(blockKey{group, HashString(extra), udp}, hostLimit, nowUnix)
		if len(extraNodes) == 0 {
			continue
		}
		if merged == nil {
			merged = make(map[uint32]BlockCode, len(nodes)+len(extraNodes))
			for n, c := range nodes {
				merged[n] = c
			}
		}
		for n, c := range extraNodes {
			if old, ok := merged[n]; !ok || c < old {
				merged[n] = c
			}
		}
	}
	if merged != nil {
		return merged, blocked
	}
	return nodes, blocked
}

func (b *Blocks) view(key blockKey, hostLimit int, now int64) (map[uint32]BlockCode, bool) {
	hs := b.record(key, "", false)
	if hs == nil {
		return nil, false
	}
	b.access.RLock()
	if hs.viewAt != 0 && hs.viewLimit == hostLimit && now-hs.viewAt < int64(blockViewTTL/time.Second) {
		nodes, blocked := hs.viewNodes, hs.viewBlocked
		b.access.RUnlock()
		return nodes, blocked
	}
	b.access.RUnlock()
	b.access.Lock()
	defer b.access.Unlock()
	nodes := make(map[uint32]BlockCode)
	for node, e := range hs.Nodes {
		if e.Until != -1 && e.active(now) {
			nodes[node] = e.Code
		}
	}
	hs.viewNodes = nodes
	hs.viewBlocked = hs.blockingCount(now) > max(hostLimit, 1)
	hs.viewLimit = hostLimit
	hs.viewAt = now
	return hs.viewNodes, hs.viewBlocked
}

// BlockGroupNode blocks node for the whole group until the deadline.
func (b *Blocks) BlockGroupNode(group, node uint32, until time.Time, reason string) {
	b.groupAccess.Lock()
	defer b.groupAccess.Unlock()
	m := b.group[group]
	if m == nil {
		m = make(map[uint32]GroupBlock)
		b.group[group] = m
	}
	if _, exists := m[node]; !exists {
		b.groupCount.Add(1)
	}
	m[node] = GroupBlock{Until: until.Unix(), Reason: reason}
}

// UnblockGroupNode lifts a group-wide block.
func (b *Blocks) UnblockGroupNode(group, node uint32) {
	b.groupAccess.Lock()
	defer b.groupAccess.Unlock()
	if _, exists := b.group[group][node]; exists {
		delete(b.group[group], node)
		b.groupCount.Add(-1)
	}
}

// GroupBlocked reports a node's active group-wide block.
func (b *Blocks) GroupBlocked(group, node uint32, now time.Time) (GroupBlock, bool) {
	if b.groupCount.Load() == 0 {
		return GroupBlock{}, false
	}
	b.groupAccess.RLock()
	defer b.groupAccess.RUnlock()
	e, ok := b.group[group][node]
	if !ok || e.Until <= now.Unix() {
		return GroupBlock{}, false
	}
	return e, true
}

// GroupBlocks returns the active group-wide blocks of a group.
func (b *Blocks) GroupBlocks(group uint32, now time.Time) map[uint32]GroupBlock {
	b.groupAccess.Lock()
	defer b.groupAccess.Unlock()
	out := make(map[uint32]GroupBlock)
	for node, e := range b.group[group] {
		if e.Until > now.Unix() {
			out[node] = e
		} else {
			delete(b.group[group], node)
			b.groupCount.Add(-1)
		}
	}
	return out
}

// HostEntry is one host record for the API and persistence.
type HostEntry struct {
	Key         string
	UDP         bool
	LastFailure int64
	Nodes       map[uint32]NodeBlock
	Blocked     bool
}

// Hosts lists the active host records of a group.
func (b *Blocks) Hosts(group uint32, hostLimit int, now time.Time) []HostEntry {
	nowUnix := now.Unix()
	b.access.Lock()
	defer b.access.Unlock()
	var out []HostEntry
	for key, hs := range b.records {
		if key.group != group {
			continue
		}
		hs.expireLocked(nowUnix)
		if len(hs.Nodes) == 0 {
			continue
		}
		entry := HostEntry{Key: b.names[key], UDP: key.udp, LastFailure: hs.LastFailure, Nodes: make(map[uint32]NodeBlock, len(hs.Nodes))}
		for node, e := range hs.Nodes {
			entry.Nodes[node] = *e
		}
		entry.Blocked = hs.blockingCount(nowUnix) > max(hostLimit, 1)
		out = append(out, entry)
	}
	return out
}

// Restore loads a persisted host record.
func (b *Blocks) Restore(group uint32, entry HostEntry) {
	hs := b.record(blockKey{group, HashString(entry.Key), entry.UDP}, entry.Key, true)
	b.access.Lock()
	defer b.access.Unlock()
	hs.LastFailure = max(hs.LastFailure, entry.LastFailure)
	for node, e := range entry.Nodes {
		copied := e
		hs.Nodes[node] = &copied
	}
	hs.viewAt = 0
}

// ForgetGroup drops every record of a group.
func (b *Blocks) ForgetGroup(group uint32) int {
	b.access.Lock()
	removed := 0
	for key := range b.records {
		if key.group == group {
			delete(b.records, key)
			delete(b.names, key)
			removed++
		}
	}
	b.access.Unlock()
	b.groupAccess.Lock()
	removed += len(b.group[group])
	b.groupCount.Add(-int64(len(b.group[group])))
	delete(b.group, group)
	b.groupAccess.Unlock()
	return removed
}

// ForgetNodes drops the records of nodes that left a group.
func (b *Blocks) ForgetNodes(group uint32, keep func(uint32) bool) {
	b.access.Lock()
	for key, hs := range b.records {
		if key.group != group {
			continue
		}
		for node := range hs.Nodes {
			if !keep(node) {
				delete(hs.Nodes, node)
			}
		}
		hs.viewAt = 0
	}
	b.access.Unlock()
	b.groupAccess.Lock()
	for node := range b.group[group] {
		if !keep(node) {
			delete(b.group[group], node)
			b.groupCount.Add(-1)
		}
	}
	b.groupAccess.Unlock()
}

// Cleanup drops records idle for a week and empty records.
func (b *Blocks) Cleanup(now time.Time) {
	nowUnix := now.Unix()
	b.access.Lock()
	defer b.access.Unlock()
	for key, hs := range b.records {
		hs.expireLocked(nowUnix)
		if len(hs.Nodes) == 0 || (hs.LastFailure != 0 && nowUnix-hs.LastFailure > int64(blockRecordExpired/time.Second)) {
			delete(b.records, key)
			delete(b.names, key)
		}
	}
}
