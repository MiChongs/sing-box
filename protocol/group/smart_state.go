package group

import (
	"encoding/json"
	"math"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/smart"
)

// nodeLoadCounter counts the active connections per member tag.
type nodeLoadCounter struct {
	counts sync.Map // string -> *atomic.Int64
}

func newNodeLoadCounter() *nodeLoadCounter {
	return &nodeLoadCounter{}
}

func (n *nodeLoadCounter) inc(tag string) {
	if tag == "" {
		return
	}
	c, ok := n.counts.Load(tag)
	if !ok {
		c, _ = n.counts.LoadOrStore(tag, new(atomic.Int64))
	}
	c.(*atomic.Int64).Add(1)
}

func (n *nodeLoadCounter) dec(tag string) {
	if c, ok := n.counts.Load(tag); ok {
		c.(*atomic.Int64).Add(-1)
	}
}

func (n *nodeLoadCounter) get(tag string) int64 {
	if c, ok := n.counts.Load(tag); ok {
		return c.(*atomic.Int64).Load()
	}
	return 0
}

func (n *nodeLoadCounter) prune(tags []string) {
	n.counts.Range(func(key, value any) bool {
		if !slices.Contains(tags, key.(string)) && value.(*atomic.Int64).Load() <= 0 {
			n.counts.Delete(key)
		}
		return true
	})
}

// smartFlood suppresses learning while failures flood in: smartFloodThreshold
// failures in a row, each within smartFloodWindow of the previous, mean the
// network is down rather than the nodes (mihomo suppressStats).
type smartFlood struct {
	suppressed atomic.Bool
	count      atomic.Int64
	last       atomic.Int64
}

// failure records one failure and reports whether learning is suppressed.
func (f *smartFlood) failure(now time.Time) (suppressed, started bool) {
	nowNano := now.UnixNano()
	if nowNano-f.last.Swap(nowNano) > int64(smartFloodWindow) {
		f.count.Store(0)
	}
	if f.count.Add(1) >= smartFloodThreshold && f.suppressed.CompareAndSwap(false, true) {
		return true, true
	}
	return f.suppressed.Load(), false
}

func (f *smartFlood) success() {
	f.count.Store(0)
	f.suppressed.Store(false)
}

func (f *smartFlood) reset() { f.success() }

// smartNodeHealth is one member's health check record.
type smartNodeHealth struct {
	alive     bool
	checked   bool
	delay     uint16
	checkedAt time.Time
	delays    []uint16 // last smartDelayHistory probes, 0xFFFF for failures
	grade     int      // MAD threshold grade
	failures  int      // consecutive failed probes
}

const (
	smartDelayHistory  = 10
	smartProbeFailed   = 0xFFFF
	smartProbeParallel = 10
)

type smartHealth struct {
	access sync.RWMutex
	nodes  map[string]*smartNodeHealth
	// dead is a read-only snapshot of the members whose last checks
	// failed, so the dial path reads liveness without a lock.
	dead atomic.Pointer[map[string]struct{}]
}

func (h *smartHealth) init() {
	h.nodes = make(map[string]*smartNodeHealth)
}

// publishLocked rebuilds the dead snapshot.
func (h *smartHealth) publishLocked() {
	dead := make(map[string]struct{})
	for tag, n := range h.nodes {
		if n.checked && !n.alive {
			dead[tag] = struct{}{}
		}
	}
	h.dead.Store(&dead)
}

func (h *smartHealth) reset() {
	h.access.Lock()
	defer h.access.Unlock()
	for _, n := range h.nodes {
		n.checked = false
		n.alive = true
		n.failures = 0
	}
	h.publishLocked()
}

func (h *smartHealth) prune(st *smartGroupState) {
	h.access.Lock()
	defer h.access.Unlock()
	for tag := range h.nodes {
		if st.find(tag) == nil {
			delete(h.nodes, tag)
		}
	}
	h.publishLocked()
}

// alive reports whether the last health check of tag passed; an unchecked
// member is alive.
func (h *smartHealth) alive(tag string) bool {
	dead := h.dead.Load()
	if dead == nil || len(*dead) == 0 {
		return true
	}
	_, isDead := (*dead)[tag]
	return !isDead
}

func (h *smartHealth) delay(tag string) uint16 {
	h.access.RLock()
	defer h.access.RUnlock()
	if n := h.nodes[tag]; n != nil && n.checked && n.alive {
		return n.delay
	}
	return 0
}

func (h *smartHealth) record(tag string, delay uint16, ok bool, now time.Time) {
	h.access.Lock()
	defer h.access.Unlock()
	n := h.nodes[tag]
	if n == nil {
		n = &smartNodeHealth{}
		h.nodes[tag] = n
	}
	wasDead := n.checked && !n.alive
	n.checked = true
	n.checkedAt = now
	sample := uint16(smartProbeFailed)
	if ok {
		n.alive = true
		n.delay = delay
		n.failures = 0
		sample = delay
	} else {
		n.failures++
		// One failed check of a working member may be the test URL; the
		// second in a row takes it out.
		if n.failures >= 2 || !n.alive {
			n.alive = false
		}
	}
	n.delays = append(n.delays, sample)
	if len(n.delays) > smartDelayHistory {
		n.delays = n.delays[len(n.delays)-smartDelayHistory:]
	}
	if wasDead != !n.alive {
		h.publishLocked()
	}
}

func (h *smartHealth) snapshot(tag string) (smartNodeHealth, bool) {
	h.access.RLock()
	defer h.access.RUnlock()
	n := h.nodes[tag]
	if n == nil {
		return smartNodeHealth{}, false
	}
	copied := *n
	copied.delays = slices.Clone(n.delays)
	return copied, true
}

// madMetrics is mihomo's calcMADMetrics: whether the latest delays are an
// anomaly, whether the node is unstable, and the threshold grade.
func madMetrics(delays []uint16) (anomaly, unstable bool, grade int) {
	const (
		scale             = 1.4826
		defaultK          = 2.5
		smallK            = 3.5
		cvThreshold       = 0.6
		minSamples        = 3
		sentinelThreshold = 0.5
	)
	gradeOf := func(t float64) int {
		switch {
		case t <= 500:
			return 1
		case t <= 1000:
			return 2
		case t <= 2000:
			return 3
		}
		return 4
	}
	n := len(delays)
	if n == 0 {
		return false, false, 0
	}
	recent := min(3, n)
	recentSentinels := 0
	for _, d := range delays[n-recent:] {
		if d == smartProbeFailed {
			recentSentinels++
		}
	}
	var filtered []float64
	for _, d := range delays {
		if d != smartProbeFailed {
			filtered = append(filtered, float64(d))
		}
	}
	m := len(filtered)
	if m == 0 {
		return true, true, 0
	}
	unstable = float64(recentSentinels)/float64(recent) > sentinelThreshold
	last := delays[n-1]
	if m < minSamples {
		return last == smartProbeFailed, unstable, 0
	}
	sorted := slices.Clone(filtered)
	sort.Float64s(sorted)
	median := medianOf(sorted)
	deviations := make([]float64, m)
	for i, v := range sorted {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)
	mad := medianOf(deviations)
	prevAbove := func(threshold float64) bool {
		return n >= 2 && delays[n-2] != smartProbeFailed && float64(delays[n-2]) > threshold
	}
	if mad == 0 {
		var mean float64
		for _, v := range filtered {
			mean += v
		}
		mean /= float64(m)
		var variance float64
		for _, v := range filtered {
			variance += (v - mean) * (v - mean)
		}
		threshold := mean + 2*math.Sqrt(variance/float64(m))
		anomaly = last == smartProbeFailed || (float64(last) > threshold && prevAbove(threshold))
		return anomaly, unstable, gradeOf(threshold)
	}
	k := defaultK
	if m < 10 {
		k = smallK
	}
	threshold := median + k*scale*mad
	anomaly = last == smartProbeFailed || (float64(last) > threshold && prevAbove(threshold))
	if !unstable && median > 0 {
		unstable = scale*mad/median >= cvThreshold
	}
	return anomaly, unstable, gradeOf(threshold)
}

func medianOf(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func smartTestHost(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Group records persisted by the store.
const (
	smartRecordPin  = "pin"
	smartRecordExit = "exit"
)

func (s *Smart) putRecord(kind, key string, value []byte) {
	if s.store == nil {
		return
	}
	if err := s.store.PutRecord(s.Tag(), kind, key, value); err != nil {
		s.logger.Debug("persist ", kind, ": ", err)
	}
}

func (s *Smart) deleteRecord(kind, key string) {
	if s.store == nil {
		return
	}
	_ = s.store.DeleteRecord(s.Tag(), kind, key)
}

type smartExitRecord struct {
	smart.ExitInfo
	Failed int64 `json:"failed,omitempty"`
}

func (s *Smart) loadExit(node string) (smart.ExitInfo, int64, bool) {
	if s.store == nil {
		return smart.ExitInfo{}, 0, false
	}
	raw := s.store.Records(s.Tag(), smartRecordExit)[node]
	if raw == nil {
		return smart.ExitInfo{}, 0, false
	}
	var record smartExitRecord
	if json.Unmarshal(raw, &record) != nil {
		return smart.ExitInfo{}, 0, false
	}
	return record.ExitInfo, record.Failed, true
}

func (s *Smart) saveExit(node string, info smart.ExitInfo, failed int64) {
	raw, err := json.Marshal(smartExitRecord{ExitInfo: info, Failed: failed})
	if err == nil {
		s.putRecord(smartRecordExit, node, raw)
	}
}

// restore loads the persisted evidence, blocks and pin of the members.
func (s *Smart) restore() {
	if s.store == nil {
		return
	}
	st := s.state.Load()
	member := func(tag string) bool { return st.find(tag) != nil }
	loaded, err := s.store.LoadGroup(s.group, member)
	if err != nil {
		s.logger.Warn("load smart evidence: ", err)
	} else if loaded > 0 {
		s.logger.Debug("restored ", loaded, " evidence cells")
	}
	if raw := s.store.Records(s.Tag(), smartRecordPin)[""]; len(raw) > 0 {
		tag := string(raw)
		if st.find(tag) != nil {
			s.pin.Store(&tag)
			s.logger.Info("restored manual pin [", tag, "]")
		} else {
			s.deleteRecord(smartRecordPin, "")
		}
	}
	for node := range s.store.Records(s.Tag(), smartRecordExit) {
		if !member(node) {
			s.deleteRecord(smartRecordExit, node)
		}
	}
}

// pruneStoredGroups drops the persisted data of Smart groups that are no
// longer configured.
func (s *Smart) pruneStoredGroups() {
	if s.store == nil || s.outboundMgr == nil {
		return
	}
	keep := make(map[string]bool)
	for _, ob := range s.outboundMgr.Outbounds() {
		if _, isSmart := ob.(*Smart); isSmart {
			keep[ob.Tag()] = true
		}
	}
	if err := s.store.PruneGroups(keep); err != nil {
		s.logger.Debug("prune stored groups: ", err)
	}
}

// persist saves the durable evidence of the group.
func (s *Smart) persist() {
	if s.store == nil {
		return
	}
	if err := s.store.SaveGroup(s.group); err != nil {
		s.logger.Warn("save smart evidence: ", err)
	}
}
