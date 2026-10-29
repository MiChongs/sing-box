package group

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/smart"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// smartRankingSnapshot is a cached ranking; its identity changes on every
// refresh.
type smartRankingSnapshot struct {
	ranking []smart.NodeRank
	at      time.Time
}

// smartRankingTTL is how long a computed ranking is served.
const smartRankingTTL = 30 * time.Second

type smartRankingCache struct {
	access   sync.Mutex
	snapshot atomic.Pointer[smartRankingSnapshot]
}

var smartRankings sync.Map // group tag -> *smartRankingCache

func (s *Smart) rankingCache() *smartRankingCache {
	cache, _ := smartRankings.LoadOrStore(s.Tag(), new(smartRankingCache))
	return cache.(*smartRankingCache)
}

// WeightRanking returns the members ranked by learned quality (mihomo node
// ranking) with the comprehensive score behind it.
func (s *Smart) WeightRanking(refresh bool) ([]smart.NodeRank, error) {
	snapshot := s.loadRankingSnapshot()
	if refresh || snapshot == nil || time.Since(snapshot.at) > smartRankingTTL {
		snapshot = s.refreshRanking()
	}
	if snapshot == nil {
		return nil, E.New("no members")
	}
	return snapshot.ranking, nil
}

func (s *Smart) loadRankingSnapshot() *smartRankingSnapshot {
	snapshot := s.rankingCache().snapshot.Load()
	if snapshot == nil || time.Since(snapshot.at) > smartRankingTTL {
		return s.refreshRanking()
	}
	return snapshot
}

func (s *Smart) refreshRanking() *smartRankingSnapshot {
	st := s.state.Load()
	if st == nil {
		return nil
	}
	cache := s.rankingCache()
	cache.access.Lock()
	defer cache.access.Unlock()
	if snapshot := cache.snapshot.Load(); snapshot != nil && time.Since(snapshot.at) < time.Second {
		return snapshot
	}
	now := time.Now()
	members := make([]smart.RankMember, len(st.outbounds))
	for i, tag := range st.tags {
		_, blocked := s.blocks.GroupBlocked(s.group.ID(), st.nodes[i], now)
		members[i] = smart.RankMember{
			Name:     tag,
			Node:     st.nodes[i],
			Priority: s.priority.Factor(tag),
			Alive:    s.health.alive(tag) && !blocked,
		}
	}
	snapshot := &smartRankingSnapshot{ranking: s.group.Ranking(members, smart.NetworkTCP), at: now}
	cache.snapshot.Store(snapshot)
	return snapshot
}

// RecomputeWeights drops the cached ranking.
func (s *Smart) RecomputeWeights() {
	s.refreshRanking()
}

// groupBlockedTags returns the members blocked for the whole group.
func (s *Smart) groupBlockedTags() map[string]bool {
	blocks := s.blocks.GroupBlocks(s.group.ID(), time.Now())
	if len(blocks) == 0 {
		return nil
	}
	out := make(map[string]bool, len(blocks))
	for node := range blocks {
		out[s.engine.NodeName(node)] = true
	}
	return out
}

// isBreakerOpen reports whether tag is excluded by its failure streak.
func (s *Smart) isBreakerOpen(tag string) bool {
	return s.group.NodeFailing(s.engine.NodeID(tag), smart.NetworkTCP)
}

// isTargetDebargoed reports whether tag is blocked or failing for a target
// key.
func (s *Smart) isTargetDebargoed(target, tag string) bool {
	node := s.engine.NodeID(tag)
	codes, broken := s.blocks.Lookup(s.group.ID(), target, false, int(s.hostFailLimit.Load()), nil, time.Now())
	if code, ok := codes[node]; ok && (!broken || code == smart.BlockManual) {
		return true
	}
	return s.group.KeyFailing(target, node, smart.NetworkTCP)
}

// isTargetSuspicious reports whether tag is under exit suspicion or
// answered a target key much slower than before.
func (s *Smart) isTargetSuspicious(target, tag string) bool {
	return s.exitWatch.Suspected(target, tag) || s.group.KeyDegraded(target, s.engine.NodeID(tag), smart.NetworkTCP)
}

// targetQualities returns the learned connection quality of every member
// for the connection's service.
func (s *Smart) targetQualities(meta *smartDialMeta, isUDP bool) map[string]float64 {
	st := s.state.Load()
	if st == nil {
		return nil
	}
	ctx := meta.scoreContext
	if isUDP {
		ctx.Network = smart.NetworkUDP
	} else {
		ctx.Network = smart.NetworkTCP
	}
	qualities := s.group.TargetQuality(&ctx, st.nodes)
	out := make(map[string]float64, len(qualities))
	for node, q := range qualities {
		out[s.engine.NodeName(node)] = q
	}
	return out
}

// regionProbeSlots bounds the concurrent smart-loadbalance region probes.
var regionProbeSlots = make(chan struct{}, 4)

// enqueueRegionProbe runs a region probe in the background when a slot is
// free, within the probe budget.
func (s *Smart) enqueueRegionProbe(run func(ctx context.Context)) bool {
	select {
	case regionProbeSlots <- struct{}{}:
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(s.taskContext(), 2*time.Second)
	s.tasks.Add(1)
	go func() {
		defer s.tasks.Done()
		defer func() { <-regionProbeSlots }()
		defer cancel()
		run(ctx)
	}()
	return true
}

// MarkBlocked blocks a member for the whole group until duration passes.
func (s *Smart) MarkBlocked(tag string, duration time.Duration) error {
	if s.state.Load().find(tag) == nil {
		return E.New("node not a member of this group: ", tag)
	}
	if duration <= 0 {
		duration = DefaultBlockDuration
	}
	s.blocks.BlockGroupNode(s.group.ID(), s.engine.NodeID(tag), time.Now().Add(duration), "manual")
	s.refreshRanking()
	s.logger.Info("node ", tag, " blocked for ", duration)
	return nil
}

// UnblockNode lifts a group-wide block.
func (s *Smart) UnblockNode(tag string) {
	s.blocks.UnblockGroupNode(s.group.ID(), s.engine.NodeID(tag))
}

// BlockConnection marks the node that carried a connection blocked for its
// target, permanently until flushed (mihomo DELETE /connections/smart/{id}).
// It returns false when the connection was not carried by this group.
func (s *Smart) BlockConnection(destination M.Socksaddr, host, ruleTarget, tag string) bool {
	node := s.engine.NodeID(tag)
	if s.state.Load().find(tag) == nil {
		return false
	}
	meta := &smartDialMeta{host: strings.ToLower(host), destPort: destination.Port, ruleTarget: ruleTarget}
	if destination.IsIP() {
		meta.resolvedIPs = []netip.Addr{destination.Addr}
	}
	s.completeMeta(meta)
	failed := s.markNodeFailure(meta, node, true, smart.BlockManual, 0)
	s.afterBlock(meta, node, failed, true, smart.BlockManual)
	return true
}

// ClearSelectionResult reports what ClearSelection released.
type ClearSelectionResult struct {
	Group       string `json:"group"`
	PreviousPin string `json:"previous_pin,omitempty"`
	Now         string `json:"now,omitempty"`
	Interrupted bool   `json:"interrupted"`
}

// ClearSelection releases the manual pin (and a smart-loadbalance region
// lock) and returns the group to automatic selection.
func (s *Smart) ClearSelection() ClearSelectionResult {
	result := ClearSelectionResult{Group: s.Tag(), PreviousPin: s.PinnedTag()}
	if result.PreviousPin == "" && s.balance != nil {
		result.PreviousPin = s.balance.lockDisplay()
	}
	s.SelectOutbound("")
	result.Interrupted = s.interruptExternalConnections
	s.refreshRanking()
	result.Now = s.Now()
	return result
}

// FlushStore drops every piece of learned state of the group: evidence,
// incumbents, blocks, exit records and persisted records.
func (s *Smart) FlushStore() (smart.FlushStats, error) {
	stats := s.engine.ForgetGroup(s.Tag())
	var err error
	if s.store != nil {
		err = s.store.FlushGroup(s.Tag())
	}
	s.pin.Store(nil)
	s.health.reset()
	if st := s.state.Load(); st != nil {
		s.group.SetMembers(st.nodes)
	}
	if s.balance != nil {
		s.balance.reset()
	}
	s.refreshRanking()
	return stats, err
}

// Diagnostic describes the group's selection state for the API.
func (s *Smart) Diagnostic() map[string]any {
	st := s.state.Load()
	now := time.Now()
	type memberInfo struct {
		Name        string  `json:"name"`
		Alive       bool    `json:"alive"`
		Delay       uint16  `json:"delay,omitempty"`
		Grade       int     `json:"stabilityGrade,omitempty"`
		Blocked     string  `json:"blocked,omitempty"`
		BlockedTill int64   `json:"blockedUntil,omitempty"`
		Load        int64   `json:"load"`
		Priority    float64 `json:"priority"`
		ExitRegion  string  `json:"exitRegion,omitempty"`
		ExitASN     string  `json:"exitAsn,omitempty"`
	}
	var members []memberInfo
	if st != nil {
		for i, tag := range st.tags {
			info := memberInfo{Name: tag, Alive: s.health.alive(tag), Delay: s.health.delay(tag), Load: s.nodeLoad.get(tag), Priority: s.priority.Factor(tag)}
			if h, ok := s.health.snapshot(tag); ok {
				info.Grade = h.grade
			}
			if block, ok := s.blocks.GroupBlocked(s.group.ID(), st.nodes[i], now); ok {
				info.Blocked, info.BlockedTill = block.Reason, block.Until
			}
			exit := s.exitWatch.Info(tag)
			info.ExitRegion, info.ExitASN = exit.Region, exit.ASN
			members = append(members, info)
		}
	}
	type hostInfo struct {
		Key     string            `json:"key"`
		UDP     bool              `json:"udp,omitempty"`
		Blocked bool              `json:"hostBlocked,omitempty"`
		Nodes   map[string]string `json:"nodes"`
	}
	var hosts []hostInfo
	for _, host := range s.blocks.Hosts(s.group.ID(), int(s.hostFailLimit.Load()), now) {
		info := hostInfo{Key: host.Key, UDP: host.UDP, Blocked: host.Blocked, Nodes: make(map[string]string)}
		for node, block := range host.Nodes {
			if block.Until == -1 {
				continue
			}
			info.Nodes[s.engine.NodeName(node)] = block.Code.String()
		}
		if len(info.Nodes) > 0 {
			hosts = append(hosts, info)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Key < hosts[j].Key })
	diag := map[string]any{
		"name":            s.Tag(),
		"type":            s.Type(),
		"now":             s.Now(),
		"fixed":           s.FixedSelection(),
		"testUrl":         s.testURL,
		"members":         members,
		"selection":       s.group.Stats(),
		"filtered":        s.group.Filtered(),
		"cache":           s.engine.CacheStats(),
		"hosts":           hosts,
		"hostFailLimit":   s.hostFailLimit.Load(),
		"floodSuppressed": s.flood.suppressed.Load(),
		"asnClaims":       s.keys.claimCount(),
		"connections":     s.conns.count(),
		"preferAsn":       s.preferASN,
		"useLightGBM":     s.useLightGBM,
		"lightgbmLoaded":  s.model.IsLoaded(),
		"collectData":     s.collectData,
	}
	if s.collector != nil {
		diag["collectedSamples"] = s.collector.Written()
	}
	return diag
}

// PeekNetwork returns the member a new connection of network would use.
func (s *Smart) PeekNetwork(network string) string {
	if ob := s.Selected(N.NetworkName(network)); ob != nil {
		return ob.Tag()
	}
	return ""
}
