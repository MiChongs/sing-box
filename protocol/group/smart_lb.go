package group

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/geodb"
	"github.com/sagernet/sing-box/common/smart"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/publicsuffix"
)

// smart-loadbalance: the Smart learning engine with region pools and
// per-connection distribution.
//
// A plain Smart group concentrates traffic on the best node (it is an
// improved urltest). A smart-loadbalance group keeps every piece of Smart's
// learning — weights, breakers, liveness, persistence, LightGBM — but uses
// it to decide two different things per connection:
//
//  1. Which region serves the connection. Members are sorted into region
//     pools (rules, node names, exit probes); the region mode picks the pool
//     (learned per target, by destination country, by priority, or locked
//     from the Clash API), so a site keeps one exit country.
//  2. Which node of the pool carries it. Connections are spread across every
//     good node of the pool by the balance strategy, weighted by the learned
//     quality and the live connection count, instead of piling onto one.
//
// The selection plugs into selectProxiesTracedOpts, so dialWithRetry,
// hedging, breakers and stats recording are shared with Smart unchanged.

const (
	balanceStrategySmart              = "smart"
	balanceStrategyLeastConnections   = "least-connections"
	balanceStrategyRoundRobin         = "round-robin"
	balanceStrategyWeightedRoundRobin = "weighted-round-robin"
	balanceStrategyWeightedRandom     = "weighted-random"
	balanceStrategyRandom             = "random"
	balanceStrategyConsistentHashing  = "consistent-hashing"

	balanceAffinityNone       = "none"
	balanceAffinityTarget     = "target"
	balanceAffinitySite       = "site"
	balanceAffinitySource     = "source"
	balanceAffinitySourceSite = "source-site"

	regionModeAuto        = "auto"
	regionModeDestination = "destination"
	regionModePriority    = "priority"
	regionModeOff         = "off"

	regionFallbackAuto     = "auto"
	regionFallbackPriority = "priority"
	regionFallbackNone     = "none"

	regionUnknownKeep    = "keep"
	regionUnknownExclude = "exclude"

	exitDetectFallback = "fallback"
	exitDetectPrefer   = "prefer"
	exitDetectOff      = "off"

	subgroupMembersRegions = "regions"
	subgroupMembersNodes   = "nodes"

	defaultBalanceAffinityTTL = 10 * time.Minute
	defaultBalanceMinQuality  = 0.5
	defaultRegionSticky       = 30 * time.Minute
	defaultRegionSwitchMargin = 0.25
	defaultExitURL            = "https://www.cloudflare.com/cdn-cgi/trace"
	defaultExitTTL            = 24 * time.Hour
	defaultExitTimeout        = 8 * time.Second
	defaultExitConcurrency    = 4
	defaultRegionProbeEvery   = 10 * time.Minute
	defaultRegionProbeTargets = 6
	defaultRegionProbeRegions = 5
	defaultSubgroupTag        = "{group}-{region}"

	// regionReevaluateInterval bounds how often a remembered region is
	// re-scored against the others; between checks it is used as is.
	regionReevaluateInterval = 30 * time.Second
	// regionScoreTopK is how many of a region's best nodes its score
	// averages: a pool is as good as the few nodes that carry most traffic.
	regionScoreTopK = 3
	// balanceFallbackRegions / PerRegion / Slots bound the cross-region
	// failover tail appended after the primary pool: the best nodes of up
	// to two fallback regions, three nodes in all.
	balanceFallbackRegions   = 2
	balanceFallbackPerRegion = 2
	balanceFallbackSlots     = 3
	// regionHealthCacheTTL bounds how stale the per-region healthy-node
	// counts used for region eligibility may be.
	regionHealthCacheTTL = time.Second
	// balanceSmartSpread is how far above the cheapest node a node's cost
	// may be and still share the draw in the smart strategy.
	balanceSmartSpread = 1.10
	// balanceMemoLimit caps the region and affinity memories.
	balanceMemoLimit = 16384
)

func normaliseBalanceStrategy(raw string) (string, bool) {
	switch strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-"), " ", "-") {
	case "", balanceStrategySmart, "auto", "adaptive":
		return balanceStrategySmart, true
	case balanceStrategyLeastConnections, "least-connection", "least-conn", "lc", "least-loaded":
		return balanceStrategyLeastConnections, true
	case balanceStrategyRoundRobin, "rr":
		return balanceStrategyRoundRobin, true
	case balanceStrategyWeightedRoundRobin, "wrr", "weighted-rr":
		return balanceStrategyWeightedRoundRobin, true
	case balanceStrategyWeightedRandom, "wr":
		return balanceStrategyWeightedRandom, true
	case balanceStrategyRandom:
		return balanceStrategyRandom, true
	case balanceStrategyConsistentHashing, "consistent-hash", "chash", "hash", "rendezvous":
		return balanceStrategyConsistentHashing, true
	}
	return "", false
}

func normaliseBalanceAffinity(raw string) (string, bool) {
	switch strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-"), " ", "-") {
	case "", balanceAffinityNone, "off":
		return balanceAffinityNone, true
	case balanceAffinityTarget, "host":
		return balanceAffinityTarget, true
	case balanceAffinitySite, "domain":
		return balanceAffinitySite, true
	case balanceAffinitySource, "src", "client":
		return balanceAffinitySource, true
	case balanceAffinitySourceSite, "session", "sticky-sessions":
		return balanceAffinitySourceSite, true
	}
	return "", false
}

func normaliseRegionMode(raw string) (string, bool) {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-") {
	case "", regionModeAuto, "smart":
		return regionModeAuto, true
	case regionModeDestination, "dest", "geo", "geoip":
		return regionModeDestination, true
	case regionModePriority, "order", "ordered":
		return regionModePriority, true
	case regionModeOff, "none", "global", "disabled":
		return regionModeOff, true
	}
	return "", false
}

func normaliseRegionFallback(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", regionFallbackAuto:
		return regionFallbackAuto, true
	case regionFallbackPriority:
		return regionFallbackPriority, true
	case regionFallbackNone, "off", "fail":
		return regionFallbackNone, true
	}
	return "", false
}

// balanceRequest carries a region view's constraints from a smart-region
// outbound into its group's dial path.
type balanceRequest struct {
	group     string
	via       string // tag of the smart-region outbound making the dial
	region    string
	fallback  bool
	pin       string
	onSuccess func(tag string)
}

type balanceRequestKey struct{}

func contextWithBalanceRequest(ctx context.Context, request *balanceRequest) context.Context {
	return context.WithValue(ctx, balanceRequestKey{}, request)
}

type regionRule struct {
	region    string
	match     *regexp.Regexp
	outbounds map[string]struct{}
}

type regionMeta struct {
	name string
	icon string
}

type regionInfo struct {
	code    string
	members []adapter.Outbound
}

// regionSnapshot is the immutable member → region assignment for one
// member snapshot of the group.
type regionSnapshot struct {
	state    *smartGroupState
	regions  map[string]*regionInfo
	codes    []string          // display / tie-break order
	regionOf map[string]string // node tag → region code
	sourceOf map[string]string // node tag → "rule" | "name" | "exit" | "unknown"
	excluded []string          // unclassified members dropped by unknown=exclude
}

func (snap *regionSnapshot) members(code string) []adapter.Outbound {
	if snap == nil {
		return nil
	}
	if info := snap.regions[code]; info != nil {
		return info.members
	}
	return nil
}

type regionHealth struct {
	snap   *regionSnapshot
	at     int64
	counts map[string]int
}

type regionMemoEntry struct {
	code      string
	lastUse   int64
	checkedAt int64
}

type affinityEntry struct {
	tag     string
	lastUse int64
}

type rankMapCache struct {
	snap *smartRankingSnapshot
	m    map[string]float64
}

type smartBalance struct {
	s *Smart

	// configured values; the strategy, affinity and mode can be switched
	// at runtime through the Clash API.
	configStrategy string
	configAffinity string
	configMode     string
	strategy       atomic.Pointer[string]
	affinity       atomic.Pointer[string]
	mode           atomic.Pointer[string]

	affinityTTL     time.Duration
	maxNodes        int
	minQuality      float64
	maxConnsPerNode int64

	priority      []string
	priorityIndex map[string]int
	allow         map[string]struct{}
	deny          map[string]struct{}
	weights       map[string]float64
	fallback      string
	minNodes      int
	sticky        time.Duration
	switchMargin  float64
	unknown       string
	rules         []regionRule
	meta          map[string]regionMeta
	destMap       map[string][]string
	destTLD       bool
	destResolve   bool
	destCache     *xsync.MapOf[string, destinationCacheEntry]
	detectName    bool

	exit  exitDetectConfig
	probe regionProbeConfig
	sub   subgroupConfig

	lock atomic.Pointer[string]

	regions      atomic.Pointer[regionSnapshot]
	rebuildMu    sync.Mutex
	healthTCP    atomic.Pointer[regionHealth]
	healthUDP    atomic.Pointer[regionHealth]
	rankCache    atomic.Pointer[rankMapCache]
	country      atomic.Pointer[geodb.Database]
	countryMu    sync.Mutex
	regionMemo   *xsync.MapOf[string, regionMemoEntry]
	affinityMemo *xsync.MapOf[string, affinityEntry]
	pending      *xsync.MapOf[string, *atomic.Int64]
	rrCounters   *xsync.MapOf[string, *atomic.Uint64]
	wrrMu        sync.Mutex
	wrrState     map[string]map[string]float64
	regionLast   *xsync.MapOf[string, string]
	lastRegion   atomic.Pointer[string]

	exitGeo      *xsync.MapOf[string, exitGeoEntry]
	exitInflight *xsync.MapOf[string, struct{}]
	exitSem      chan struct{}

	probes       *xsync.MapOf[string, *regionProbeStat]
	probeTargets *xsync.MapOf[string, *regionProbeTarget]

	membersChanged providerUpdateCheckScheduler
	subgroups      subgroupState
}

func newSmartBalance(s *Smart, balanceOptions option.SmartBalanceOptions, regionOptions option.SmartRegionOptions) (*smartBalance, error) {
	b := &smartBalance{
		s:            s,
		affinityTTL:  time.Duration(balanceOptions.AffinityTTL),
		maxNodes:     balanceOptions.MaxNodes,
		minQuality:   balanceOptions.MinQuality,
		minNodes:     regionOptions.MinNodes,
		sticky:       time.Duration(regionOptions.Sticky),
		switchMargin: regionOptions.SwitchMargin,
		weights:      make(map[string]float64),
		meta:         make(map[string]regionMeta),
		destMap:      make(map[string][]string),
		destTLD:      !regionOptions.Destination.DisableTLD,
		destResolve:  !regionOptions.Destination.DisableResolve,
		destCache:    xsync.NewMapOf[string, destinationCacheEntry](),
		detectName:   !regionOptions.Detect.DisableName,
		regionMemo:   xsync.NewMapOf[string, regionMemoEntry](),
		affinityMemo: xsync.NewMapOf[string, affinityEntry](),
		pending:      xsync.NewMapOf[string, *atomic.Int64](),
		rrCounters:   xsync.NewMapOf[string, *atomic.Uint64](),
		wrrState:     make(map[string]map[string]float64),
		regionLast:   xsync.NewMapOf[string, string](),
		exitGeo:      xsync.NewMapOf[string, exitGeoEntry](),
		exitInflight: xsync.NewMapOf[string, struct{}](),
		probes:       xsync.NewMapOf[string, *regionProbeStat](),
		probeTargets: xsync.NewMapOf[string, *regionProbeTarget](),
	}
	var ok bool
	if b.configStrategy, ok = normaliseBalanceStrategy(balanceOptions.Strategy); !ok {
		return nil, E.New("unknown balance strategy: ", balanceOptions.Strategy)
	}
	if b.configAffinity, ok = normaliseBalanceAffinity(balanceOptions.Affinity); !ok {
		return nil, E.New("unknown balance affinity: ", balanceOptions.Affinity)
	}
	if b.configMode, ok = normaliseRegionMode(regionOptions.Mode); !ok {
		return nil, E.New("unknown region mode: ", regionOptions.Mode)
	}
	if b.fallback, ok = normaliseRegionFallback(regionOptions.Fallback); !ok {
		return nil, E.New("unknown region fallback: ", regionOptions.Fallback)
	}
	b.setStrategy(b.configStrategy)
	b.setAffinity(b.configAffinity)
	b.setMode(b.configMode)
	b.lock.Store(new(string))

	if b.affinityTTL <= 0 {
		b.affinityTTL = defaultBalanceAffinityTTL
	}
	if b.minQuality <= 0 {
		b.minQuality = defaultBalanceMinQuality
	} else if b.minQuality > 1 {
		return nil, E.New("balance.min_quality must be within (0, 1]")
	}
	if b.maxNodes < 0 {
		return nil, E.New("balance.max_nodes must not be negative")
	}
	if balanceOptions.MaxConnectionsPerNode < 0 {
		return nil, E.New("balance.max_connections_per_node must not be negative")
	}
	b.maxConnsPerNode = int64(balanceOptions.MaxConnectionsPerNode)
	if b.minNodes <= 0 {
		b.minNodes = 1
	}
	if b.sticky <= 0 {
		b.sticky = defaultRegionSticky
	}
	if b.switchMargin <= 0 {
		b.switchMargin = defaultRegionSwitchMargin
	}

	b.priorityIndex = make(map[string]int)
	for _, raw := range regionOptions.Priority {
		code := normaliseRegionCode(raw)
		if code == "" {
			continue
		}
		if _, dup := b.priorityIndex[code]; dup {
			continue
		}
		b.priorityIndex[code] = len(b.priority)
		b.priority = append(b.priority, code)
	}
	if b.configMode == regionModePriority && len(b.priority) == 0 {
		return nil, E.New("region.mode priority requires region.priority")
	}
	b.allow = regionCodeSet(regionOptions.Allow)
	b.deny = regionCodeSet(regionOptions.Deny)
	for raw, weight := range regionOptions.Weights {
		code := normaliseRegionCode(raw)
		if code == "" {
			continue
		}
		if weight <= 0 || math.IsInf(weight, 0) || math.IsNaN(weight) {
			return nil, E.New("region.weights[", raw, "] must be a positive number")
		}
		b.weights[code] = weight
	}
	for raw, targets := range regionOptions.Destination.Map {
		country := normaliseRegionCode(raw)
		if country == "" {
			continue
		}
		for _, target := range targets {
			if code := normaliseRegionCode(target); code != "" {
				b.destMap[country] = append(b.destMap[country], code)
			}
		}
	}

	switch unknown := strings.TrimSpace(regionOptions.Unknown); strings.ToLower(unknown) {
	case "", regionUnknownKeep:
		b.unknown = regionUnknownKeep
	case regionUnknownExclude, "drop":
		b.unknown = regionUnknownExclude
	default:
		b.unknown = normaliseRegionCode(unknown)
	}

	for i, rule := range regionOptions.Rules {
		code := normaliseRegionCode(rule.Region)
		if code == "" {
			return nil, E.New("region.rules[", i, "]: missing region")
		}
		if rule.Name != "" || rule.Icon != "" {
			current := b.meta[code]
			if rule.Name != "" {
				current.name = rule.Name
			}
			if rule.Icon != "" {
				current.icon = rule.Icon
			}
			b.meta[code] = current
		}
		if rule.Match == nil && len(rule.Outbounds) == 0 {
			continue
		}
		compiled := regionRule{region: code, match: (*regexp.Regexp)(rule.Match)}
		if len(rule.Outbounds) > 0 {
			compiled.outbounds = make(map[string]struct{}, len(rule.Outbounds))
			for _, tag := range rule.Outbounds {
				compiled.outbounds[tag] = struct{}{}
			}
		}
		b.rules = append(b.rules, compiled)
	}

	var err error
	if b.exit, err = newExitDetectConfig(regionOptions.Detect); err != nil {
		return nil, err
	}
	b.exitSem = make(chan struct{}, b.exit.concurrency)
	b.probe = newRegionProbeConfig(regionOptions.Probe)
	if b.sub, err = newSubgroupConfig(regionOptions.Outbounds); err != nil {
		return nil, err
	}
	return b, nil
}

func regionCodeSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, raw := range values {
		if code := normaliseRegionCode(raw); code != "" {
			set[code] = struct{}{}
		}
	}
	return set
}

func (b *smartBalance) currentStrategy() string { return *b.strategy.Load() }
func (b *smartBalance) currentAffinity() string { return *b.affinity.Load() }
func (b *smartBalance) currentMode() string     { return *b.mode.Load() }
func (b *smartBalance) currentLock() string     { return *b.lock.Load() }

func (b *smartBalance) setStrategy(v string) { b.strategy.Store(&v) }
func (b *smartBalance) setAffinity(v string) { b.affinity.Store(&v) }
func (b *smartBalance) setMode(v string)     { b.mode.Store(&v) }
func (b *smartBalance) setLock(v string)     { b.lock.Store(&v) }

// regionName returns the display names of a region: a rule-configured name
// wins over the built-in Chinese name; custom regions fall back to the code.
func (b *smartBalance) regionName(code string) (name, nameEn, icon string) {
	zh, en := regionDisplayNames(code)
	name, nameEn = zh, en
	if meta, ok := b.meta[code]; ok {
		if meta.name != "" {
			name = meta.name
		}
		icon = meta.icon
	}
	if name == "" {
		name = code
	}
	if nameEn == "" {
		nameEn = name
	}
	return
}

func (b *smartBalance) allowed(code string) bool {
	if _, denied := b.deny[code]; denied {
		return false
	}
	if b.allow != nil {
		_, ok := b.allow[code]
		return ok
	}
	return true
}

// ── Member classification ──────────────────────────────────────────────────

// displayName strips the "<provider>/" prefix provider members carry, so a
// provider called "jp-sub" does not make every member Japanese.
func (b *smartBalance) displayName(tag string) string {
	for _, providerTag := range b.s.providerTags {
		if strings.HasPrefix(tag, providerTag+"/") {
			return tag[len(providerTag)+1:]
		}
	}
	return tag
}

// classify returns the region of a member and the evidence used.
func (b *smartBalance) classify(ob adapter.Outbound) (code, source string) {
	tag := ob.Tag()
	name := b.displayName(tag)
	for _, rule := range b.rules {
		if rule.outbounds != nil {
			if _, ok := rule.outbounds[tag]; ok {
				return rule.region, "rule"
			}
			if _, ok := rule.outbounds[name]; ok {
				return rule.region, "rule"
			}
		}
		if rule.match != nil && (rule.match.MatchString(name) || rule.match.MatchString(tag)) {
			return rule.region, "rule"
		}
	}
	exit, hasExit := b.freshExit(tag)
	if hasExit && b.exit.mode == exitDetectPrefer {
		return exit, "exit"
	}
	if b.detectName {
		if code := classifyRegionByName(name); code != "" {
			return code, "name"
		}
	}
	if hasExit && b.exit.mode == exitDetectFallback {
		return exit, "exit"
	}
	return "", "unknown"
}

// snapshot returns the region assignment for the current member list,
// rebuilding it when the members changed since it was computed.
func (b *smartBalance) snapshot() *regionSnapshot {
	state := b.s.state.Load()
	if snap := b.regions.Load(); snap != nil && snap.state == state {
		return snap
	}
	return b.rebuild()
}

func (b *smartBalance) rebuild() *regionSnapshot {
	b.rebuildMu.Lock()
	defer b.rebuildMu.Unlock()
	state := b.s.state.Load()
	snap := &regionSnapshot{
		state:    state,
		regions:  make(map[string]*regionInfo),
		regionOf: make(map[string]string),
		sourceOf: make(map[string]string),
	}
	if state != nil {
		for _, ob := range state.outbounds {
			if ob == nil {
				continue
			}
			code, source := b.classify(ob)
			if code == "" {
				switch b.unknown {
				case regionUnknownKeep:
					code = regionUnknown
				case regionUnknownExclude:
					snap.excluded = append(snap.excluded, ob.Tag())
					snap.sourceOf[ob.Tag()] = source
					continue
				default:
					code = b.unknown
				}
			}
			info := snap.regions[code]
			if info == nil {
				info = &regionInfo{code: code}
				snap.regions[code] = info
			}
			info.members = append(info.members, ob)
			snap.regionOf[ob.Tag()] = code
			snap.sourceOf[ob.Tag()] = source
		}
	}
	for code := range snap.regions {
		snap.codes = append(snap.codes, code)
	}
	sort.Slice(snap.codes, func(i, j int) bool {
		a, c := snap.codes[i], snap.codes[j]
		if (a == regionUnknown) != (c == regionUnknown) {
			return c == regionUnknown
		}
		pa, oka := b.priorityIndex[a]
		pc, okc := b.priorityIndex[c]
		if oka != okc {
			return oka
		}
		if oka && pa != pc {
			return pa < pc
		}
		la, lc := len(snap.regions[a].members), len(snap.regions[c].members)
		if la != lc {
			return la > lc
		}
		return a < c
	})
	b.regions.Store(snap)
	b.healthTCP.Store(nil)
	b.healthUDP.Store(nil)
	return snap
}

// onMembersChanged runs after every member-list change: re-sort the
// regions now, then refresh in the background.
func (b *smartBalance) onMembersChanged() {
	b.rebuild()
	b.scheduleRefresh()
}

// scheduleRefresh coalesces background refreshes: re-sort the members (exit
// results may have changed since), probe the exits of members that need
// it, and bring the generated region outbounds in line.
func (b *smartBalance) scheduleRefresh() {
	if !b.s.started.Load() {
		return
	}
	b.membersChanged.Schedule(func() {
		snap := b.rebuild()
		b.scheduleExitDetection(snap, false)
		b.syncSubgroups()
	})
}

// ── Health and quality ─────────────────────────────────────────────────────

func (b *smartBalance) blockedNodes() map[string]bool {
	if b.s.store == nil {
		return nil
	}
	blocked, _ := b.s.store.GetBlockedNodes(b.s.Tag(), smartConfigName)
	return blocked
}

func (b *smartBalance) nodeHealthy(ob adapter.Outbound, isUDP bool, blocked map[string]bool) bool {
	tag := ob.Tag()
	return !blocked[tag] && b.nodeAlive(tag) && (!isUDP || b.s.supportsUDP(ob))
}

// nodeAlive is isAlive without its freshness rule. Health checks pause while
// the group is idle, so after a quiet spell every probe result is older than
// 3 × interval; isAlive reads that as dead. Plain Smart survives because
// fillProxies falls back to every member, but a group that reads "stale" as
// "dead" would have no node left to dial — and since only a successful dial
// ends the idle state, it would stay that way. Stale is unknown, not dead:
// an open breaker, a known-dead mark or a failed probe still count.
func (b *smartBalance) nodeAlive(tag string) bool {
	s := b.s
	if s.isBreakerOpen(tag) {
		return false
	}
	if deadAt, dead := s.knownDead.Load(tag); dead && time.Since(deadAt) < knownDeadTTL {
		return false
	}
	if s.history != nil {
		if h := s.history.LoadURLTestHistory(tag); h != nil && h.Delay == 0 {
			return false
		}
	}
	return true
}

// healthyCounts returns the number of healthy members per region, cached
// for regionHealthCacheTTL: eligibility checks run on every dial and a
// second-old view is precise enough for them.
func (b *smartBalance) healthyCounts(snap *regionSnapshot, isUDP bool) map[string]int {
	slot := &b.healthTCP
	if isUDP {
		slot = &b.healthUDP
	}
	now := time.Now().UnixNano()
	if cached := slot.Load(); cached != nil && cached.snap == snap && now-cached.at < int64(regionHealthCacheTTL) {
		return cached.counts
	}
	blocked := b.blockedNodes()
	counts := make(map[string]int, len(snap.regions))
	for code, info := range snap.regions {
		n := 0
		for _, ob := range info.members {
			if b.nodeHealthy(ob, isUDP, blocked) {
				n++
			}
		}
		counts[code] = n
	}
	slot.Store(&regionHealth{snap: snap, at: now, counts: counts})
	return counts
}

func (b *smartBalance) rankMap() map[string]float64 {
	mem := b.s.loadRankingSnapshot()
	if mem == nil {
		return nil
	}
	if cached := b.rankCache.Load(); cached != nil && cached.snap == mem {
		return cached.m
	}
	m := make(map[string]float64, len(mem.ranking))
	for _, rank := range mem.ranking {
		if rank.Weight > 0 {
			m[rank.Name] = rank.Weight
		}
	}
	b.rankCache.Store(&rankMapCache{snap: mem, m: m})
	return m
}

// balanceScorer scores nodes for one request. Quality is on the scale of
// the Smart weight store (≈ 0 … 1.2): the learned weight for this target
// when there is one, else the node's overall weight, else a value derived
// from its URL-test delay, else a neutral prior so untested nodes still get
// traffic.
type balanceScorer struct {
	b       *smartBalance
	target  string
	weights map[string]float64
	rank    map[string]float64
}

func (b *smartBalance) newScorer(meta *smartDialMeta, isUDP bool) *balanceScorer {
	sc := &balanceScorer{b: b, rank: b.rankMap()}
	if meta == nil {
		return sc
	}
	sc.target = meta.smartTarget
	if b.s.store != nil && meta.smartTarget != "" {
		if names, weights, err := b.s.store.GetBestProxyForTarget(b.s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); err == nil {
			sc.weights = make(map[string]float64, len(names))
			for i, name := range names {
				if i < len(weights) {
					sc.weights[name] = weights[i]
				}
			}
		}
	}
	return sc
}

const balanceNeutralQuality = 0.55

// baseQuality returns the quality and whether it is a learned weight. Learned
// weights (per destination, and the overall ranking averaged from them)
// already include the policy_priority factor — recordStats passes it to
// CalculateWeight — so only the delay-derived and neutral values still need
// it.
func (sc *balanceScorer) baseQuality(tag string) (quality float64, targetWeak, learned bool) {
	if w, ok := sc.weights[tag]; ok {
		return w, w < smart.AllowedWeight, true
	}
	if w, ok := sc.rank[tag]; ok {
		return w * 0.9, false, true
	}
	if history := sc.b.s.history; history != nil {
		if h := history.LoadURLTestHistory(tag); h != nil && h.Delay > 0 {
			return 0.4 + 0.4*300/(300+float64(h.Delay)), false, false
		}
	}
	return balanceNeutralQuality, false, false
}

func (sc *balanceScorer) quality(tag string) (float64, bool) {
	q, weak, learned := sc.baseQuality(tag)
	if !learned {
		q *= sc.b.s.getPriorityFactor(tag)
	}
	if q <= 0 {
		q = 0.01
	}
	return q, weak
}

// regionScore is the mean quality of the region's best regionScoreTopK
// healthy members, with a small bonus for pool depth (more nodes share the
// load), the configured region weight and the active-probe factor.
func (b *smartBalance) regionScore(code string, snap *regionSnapshot, sc *balanceScorer, isUDP bool, blocked map[string]bool, probeFactors map[string]float64) float64 {
	members := snap.members(code)
	qualities := make([]float64, 0, len(members))
	for _, ob := range members {
		if !b.nodeHealthy(ob, isUDP, blocked) {
			continue
		}
		q, weak := sc.quality(ob.Tag())
		if weak {
			q *= 0.5
		}
		qualities = append(qualities, q)
	}
	if len(qualities) == 0 {
		return 0
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(qualities)))
	k := min(regionScoreTopK, len(qualities))
	sum := 0.0
	for _, q := range qualities[:k] {
		sum += q
	}
	score := sum / float64(k)
	score *= 1 + 0.05*math.Min(math.Log2(float64(len(qualities))), 4)
	if weight, ok := b.weights[code]; ok {
		score *= weight
	}
	if factor, ok := probeFactors[code]; ok {
		score *= factor
	}
	return score
}

// ── Region decision ────────────────────────────────────────────────────────

type regionDecision struct {
	order  []string // region codes, primary first; "" is the all-members pool
	source string
}

func (b *smartBalance) decideRegions(meta *smartDialMeta, snap *regionSnapshot, isUDP bool, sc *balanceScorer) regionDecision {
	counts := b.healthyCounts(snap, isUDP)
	eligible := func(code string) bool {
		return b.allowed(code) && counts[code] >= b.minNodes
	}
	usable := func(code string) bool { return counts[code] > 0 }
	var request *balanceRequest
	if meta != nil {
		request = meta.balance
	}

	var (
		blocked      map[string]bool
		blockedReady bool
		probeFactors map[string]float64
		scores       map[string]float64
	)
	score := func(code string) float64 {
		if scores == nil {
			if !blockedReady {
				blocked, blockedReady = b.blockedNodes(), true
			}
			probeFactors = b.probeFactors(sc.target)
			scores = make(map[string]float64, len(snap.codes))
		}
		if v, ok := scores[code]; ok {
			return v
		}
		v := b.regionScore(code, snap, sc, isUDP, blocked, probeFactors)
		scores[code] = v
		return v
	}
	pickBest := func(skip string, accept func(string) bool) string {
		var (
			bestCode  string
			bestScore = -1.0
		)
		for _, code := range snap.codes {
			if code == skip || !accept(code) {
				continue
			}
			if v := score(code); v > bestScore {
				bestCode, bestScore = code, v
			}
		}
		return bestCode
	}
	// best is the best eligible region; when no region reaches min_nodes,
	// the best allowed region with any healthy node rather than none.
	best := func(skip string) string {
		if code := pickBest(skip, eligible); code != "" {
			return code
		}
		return pickBest(skip, func(code string) bool { return b.allowed(code) && usable(code) })
	}
	finish := func(primary, source string, allowFallback bool) regionDecision {
		if primary == "" {
			return regionDecision{source: source}
		}
		order := []string{primary}
		if !allowFallback || b.fallback == regionFallbackNone {
			return regionDecision{order: order, source: source}
		}
		seen := map[string]bool{primary: true}
		if b.fallback == regionFallbackPriority {
			for _, code := range b.priority {
				if !seen[code] && eligible(code) {
					seen[code] = true
					order = append(order, code)
				}
			}
			return regionDecision{order: order, source: source}
		}
		rest := make([]string, 0, len(snap.codes))
		for _, code := range snap.codes {
			if !seen[code] && eligible(code) {
				rest = append(rest, code)
			}
		}
		sort.SliceStable(rest, func(i, j int) bool { return score(rest[i]) > score(rest[j]) })
		return regionDecision{order: append(order, rest...), source: source}
	}
	// fallbackPrimary picks a region when the requested one cannot serve:
	// the best region by score, or the first eligible priority region.
	// firstPriority is the first priority region that is eligible, else
	// the first one with any healthy node (min_nodes relaxed, as in best).
	firstPriority := func() string {
		for _, code := range b.priority {
			if eligible(code) {
				return code
			}
		}
		for _, code := range b.priority {
			if b.allowed(code) && usable(code) {
				return code
			}
		}
		return ""
	}
	fallbackPrimary := func() string {
		switch b.fallback {
		case regionFallbackNone:
			return ""
		case regionFallbackPriority:
			return firstPriority()
		}
		return best("")
	}

	// A region view (smart-region outbound) pins its region.
	if request != nil && request.region != "" {
		if usable(request.region) {
			return finish(request.region, "region-view", request.fallback)
		}
		if request.fallback {
			return finish(fallbackPrimary(), "region-view-fallback", true)
		}
		return regionDecision{source: "region-view-unavailable"}
	}
	// A region locked through the Clash API.
	if lock := b.currentLock(); lock != "" {
		if usable(lock) {
			return finish(lock, "lock", true)
		}
		return finish(fallbackPrimary(), "lock-fallback", true)
	}

	switch b.currentMode() {
	case regionModeOff:
		return regionDecision{order: []string{""}, source: "global"}
	case regionModePriority:
		if code := firstPriority(); code != "" {
			return finish(code, "priority", true)
		}
		if b.fallback == regionFallbackAuto {
			return finish(best(""), "priority-fallback", true)
		}
		return regionDecision{source: "priority-unavailable"}
	case regionModeDestination:
		country := b.destinationCountry(meta)
		if country != "" {
			candidates, mapped := b.destMap[country]
			if !mapped {
				candidates = []string{country}
			}
			for _, code := range candidates {
				if eligible(code) {
					return finish(code, "destination:"+country, true)
				}
			}
		}
		primary, source := b.autoRegion(meta, snap, eligible, score, best)
		return finish(primary, "destination-fallback:"+source, true)
	}
	primary, source := b.autoRegion(meta, snap, eligible, score, best)
	return finish(primary, source, true)
}

// autoRegion picks the region for a target from the learned scores, keeping
// the target's previous region unless it stopped being eligible, its memory
// expired, or another region scores switchMargin better.
func (b *smartBalance) autoRegion(meta *smartDialMeta, snap *regionSnapshot, eligible func(string) bool, score func(string) float64, best func(string) string) (string, string) {
	target := ""
	if meta != nil {
		target = meta.smartTarget
	}
	now := time.Now().UnixNano()
	if target == "" {
		return best(""), "auto"
	}
	memo, ok := b.regionMemo.Load(target)
	if ok && now-memo.lastUse < int64(b.sticky) && eligible(memo.code) {
		if now-memo.checkedAt < int64(regionReevaluateInterval) {
			memo.lastUse = now
			b.regionMemo.Store(target, memo)
			return memo.code, "auto-sticky"
		}
		challenger := best(memo.code)
		if challenger != "" && score(challenger) > score(memo.code)*(1+b.switchMargin) {
			b.storeRegionMemo(target, regionMemoEntry{code: challenger, lastUse: now, checkedAt: now})
			return challenger, "auto-switch"
		}
		memo.lastUse, memo.checkedAt = now, now
		b.regionMemo.Store(target, memo)
		return memo.code, "auto-sticky"
	}
	code := best("")
	if code != "" {
		b.storeRegionMemo(target, regionMemoEntry{code: code, lastUse: now, checkedAt: now})
	}
	return code, "auto"
}

func (b *smartBalance) storeRegionMemo(target string, entry regionMemoEntry) {
	if b.regionMemo.Size() >= balanceMemoLimit {
		b.pruneMemos(true)
	}
	b.regionMemo.Store(target, entry)
}

// destinationCountry returns the ISO country of the connection's target:
// the GeoIP country of its resolved address, else the country-code TLD of
// its domain, else the GeoIP country of the domain resolved here (a landing
// server given by name reaches the group unresolved).
func (b *smartBalance) destinationCountry(meta *smartDialMeta) string {
	if meta == nil {
		return ""
	}
	if len(meta.destGeoIP) > 0 && meta.destGeoIP[0] != "" {
		return strings.ToUpper(meta.destGeoIP[0])
	}
	if country := b.lookupCountry(meta.resolvedIPs); country != "" {
		return country
	}
	if meta.host == "" {
		return ""
	}
	if b.destTLD {
		if country := countryFromTLD(meta.host); country != "" {
			return country
		}
	}
	if b.destResolve && len(meta.resolvedIPs) == 0 {
		return b.resolveCountry(meta.host)
	}
	return ""
}

type destinationCacheEntry struct {
	country string
	expires int64
}

const (
	destinationResolveTimeout = 300 * time.Millisecond
	destinationCacheTTL       = 10 * time.Minute
	destinationFailureTTL     = time.Minute
	destinationCacheLimit     = 4096
)

// resolveCountry looks a domain up through the DNS router and returns the
// country of its addresses, cached per host. Fake-IP and private answers
// have no country and yield "".
func (b *smartBalance) resolveCountry(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		return ""
	}
	now := time.Now().UnixNano()
	if entry, ok := b.destCache.Load(host); ok && now < entry.expires {
		return entry.country
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](b.s.ctx)
	if dnsRouter == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), destinationResolveTimeout)
	ips, err := dnsRouter.Lookup(ctx, host, adapter.DNSQueryOptions{})
	cancel()
	entry := destinationCacheEntry{expires: now + int64(destinationCacheTTL)}
	if err != nil || len(ips) == 0 {
		entry.expires = now + int64(destinationFailureTTL)
	} else {
		entry.country = b.lookupCountry(ips)
	}
	if b.destCache.Size() >= destinationCacheLimit {
		b.destCache.Clear()
	}
	b.destCache.Store(host, entry)
	return entry.country
}

// lookupCountry resolves a country from the GeoX country database, opening
// it on first use.
func (b *smartBalance) lookupCountry(ips []netip.Addr) string {
	if len(ips) == 0 {
		return ""
	}
	if codes := b.s.lookupCountry(ips); len(codes) > 0 {
		return strings.ToUpper(codes[0])
	}
	db := b.countryDatabase()
	if db == nil {
		return ""
	}
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.Lookup(ip, &record); err == nil && record.Country.ISOCode != "" {
			return strings.ToUpper(record.Country.ISOCode)
		}
	}
	return ""
}

func (b *smartBalance) countryDatabase() *geodb.Database {
	if db := b.country.Load(); db != nil {
		return db
	}
	b.countryMu.Lock()
	defer b.countryMu.Unlock()
	if db := b.country.Load(); db != nil {
		return db
	}
	geoSvc := service.FromContext[adapter.GeoXService](b.s.ctx)
	if geoSvc == nil {
		return nil
	}
	path := geoSvc.MMDBPath()
	if path == "" {
		path = geoSvc.RequireDefaultMMDB()
	}
	db, err := geodb.Open(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		b.s.logger.Warn("smart-loadbalance[", b.s.Tag(), "] country database: ", err)
	}
	if db != nil {
		b.country.Store(db)
	}
	return db
}

// tldCountries maps country-code TLDs to regions. Generic-use ccTLDs
// (.io, .co, .tv, .me, .ai, …) are left out on purpose.
var tldCountries = map[string]string{
	"hk": "HK", "tw": "TW", "mo": "MO", "jp": "JP", "kr": "KR", "sg": "SG", "my": "MY", "th": "TH",
	"vn": "VN", "ph": "PH", "id": "ID", "in": "IN", "pk": "PK", "bd": "BD", "kh": "KH", "mn": "MN",
	"kz": "KZ", "ae": "AE", "sa": "SA", "qa": "QA", "il": "IL", "tr": "TR", "ir": "IR", "ru": "RU",
	"ua": "UA", "by": "BY", "pl": "PL", "de": "DE", "fr": "FR", "uk": "GB", "ie": "IE", "nl": "NL",
	"be": "BE", "lu": "LU", "ch": "CH", "at": "AT", "it": "IT", "es": "ES", "pt": "PT", "no": "NO",
	"se": "SE", "fi": "FI", "dk": "DK", "cz": "CZ", "sk": "SK", "hu": "HU", "ro": "RO", "bg": "BG",
	"gr": "GR", "rs": "RS", "hr": "HR", "ee": "EE", "lv": "LV", "lt": "LT", "ca": "CA", "mx": "MX",
	"br": "BR", "ar": "AR", "cl": "CL", "pe": "PE", "au": "AU", "nz": "NZ", "za": "ZA", "eg": "EG",
	"ng": "NG", "ke": "KE", "cn": "CN", "us": "US",
}

func countryFromTLD(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	tld := host
	if i := strings.LastIndexByte(host, '.'); i >= 0 {
		tld = host[i+1:]
	}
	return tldCountries[tld]
}

// ── Pool and pick ──────────────────────────────────────────────────────────

type poolEntry struct {
	ob   adapter.Outbound
	tag  string
	q    float64
	load int64
}

func (b *smartBalance) nodeLoad(tag string) int64 {
	load := b.s.nodeLoad.get(tag)
	if counter, ok := b.pending.Load(tag); ok {
		load += counter.Load()
	}
	return load
}

func (b *smartBalance) pendingAdd(tag string, delta int64) {
	if tag == "" {
		return
	}
	counter, _ := b.pending.LoadOrCompute(tag, func() *atomic.Int64 { return new(atomic.Int64) })
	counter.Add(delta)
}

// regionMembers returns the members of a region, or every member of an
// allowed region for the "" (all-members) pool.
func (b *smartBalance) regionMembers(snap *regionSnapshot, code string) []adapter.Outbound {
	if code != "" {
		return snap.members(code)
	}
	var all []adapter.Outbound
	for _, region := range snap.codes {
		if b.allowed(region) {
			all = append(all, snap.regions[region].members...)
		}
	}
	return all
}

// buildPool returns the healthy members of a region that are good enough
// to share its traffic, best first.
func (b *smartBalance) buildPool(code string, snap *regionSnapshot, meta *smartDialMeta, isUDP bool, blocked map[string]bool, sc *balanceScorer) []poolEntry {
	members := b.regionMembers(snap, code)
	if len(members) == 0 {
		return nil
	}
	target := ""
	if meta != nil {
		target = meta.smartTarget
	}
	pool := make([]poolEntry, 0, len(members))
	weak := make([]bool, 0, len(members))
	strong := 0
	for _, ob := range members {
		if !b.nodeHealthy(ob, isUDP, blocked) {
			continue
		}
		tag := ob.Tag()
		if target != "" && b.s.isTargetDebargoed(target, tag) {
			continue
		}
		q, isWeak := sc.quality(tag)
		if target != "" && b.s.isTargetSuspicious(target, tag) {
			q *= 0.3
		}
		pool = append(pool, poolEntry{ob: ob, tag: tag, q: q, load: b.nodeLoad(tag)})
		weak = append(weak, isWeak)
		if !isWeak {
			strong++
		}
	}
	if len(pool) == 0 {
		return nil
	}
	// Nodes the store has learned to be bad for this target only take
	// traffic when nothing better is left.
	if strong > 0 && strong < len(pool) {
		kept := pool[:0]
		for i, entry := range pool {
			if !weak[i] {
				kept = append(kept, entry)
			}
		}
		pool = kept
	}
	sort.SliceStable(pool, func(i, j int) bool { return pool[i].q > pool[j].q })
	floor := pool[0].q * b.minQuality
	cut := len(pool)
	for i, entry := range pool {
		if entry.q < floor {
			cut = i
			break
		}
	}
	pool = pool[:max(cut, 1)]
	if b.maxNodes > 0 && len(pool) > b.maxNodes {
		pool = pool[:b.maxNodes]
	}
	if b.maxConnsPerNode > 0 {
		open := pool[:0:0]
		for _, entry := range pool {
			if entry.load < b.maxConnsPerNode {
				open = append(open, entry)
			}
		}
		if len(open) > 0 {
			pool = open
		}
	}
	return pool
}

// affinityKey returns the key connections sharing a node are grouped by,
// or "" when affinity is off or the key's ingredient is missing.
func (b *smartBalance) affinityKey(meta *smartDialMeta, code string) string {
	if meta == nil {
		return ""
	}
	var key string
	switch b.currentAffinity() {
	case balanceAffinityTarget:
		key = meta.smartTarget
	case balanceAffinitySite:
		key = siteOf(meta)
	case balanceAffinitySource:
		if meta.source.IsValid() {
			key = meta.source.String()
		}
	case balanceAffinitySourceSite:
		if site := siteOf(meta); site != "" && meta.source.IsValid() {
			key = meta.source.String() + "|" + site
		}
	}
	if key == "" {
		return ""
	}
	return code + "|" + key
}

// siteOf returns the registrable domain of the target (or its IP).
func siteOf(meta *smartDialMeta) string {
	if meta.host != "" {
		host := strings.TrimSuffix(strings.ToLower(meta.host), ".")
		if _, err := netip.ParseAddr(host); err == nil {
			return host
		}
		if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			return site
		}
		return host
	}
	if len(meta.resolvedIPs) > 0 {
		return meta.resolvedIPs[0].String()
	}
	return meta.smartTarget
}

// pick chooses the node of the pool that carries this connection.
func (b *smartBalance) pick(pool []poolEntry, code string, meta *smartDialMeta) (int, string) {
	if len(pool) == 1 {
		return 0, "single"
	}
	key := b.affinityKey(meta, code)
	if key != "" {
		if entry, ok := b.affinityMemo.Load(key); ok && time.Now().UnixNano()-entry.lastUse < int64(b.affinityTTL) {
			for i := range pool {
				if pool[i].tag == entry.tag {
					return i, "affinity"
				}
			}
		}
	}
	strategy := b.currentStrategy()
	switch strategy {
	case balanceStrategyLeastConnections:
		return pickLeastConnections(pool), strategy
	case balanceStrategyRoundRobin:
		return b.pickRoundRobin(pool, code), strategy
	case balanceStrategyWeightedRoundRobin:
		return b.pickWeightedRoundRobin(pool, code), strategy
	case balanceStrategyWeightedRandom:
		return pickWeightedRandom(pool, nil), strategy
	case balanceStrategyRandom:
		return rand.IntN(len(pool)), strategy
	case balanceStrategyConsistentHashing:
		hashKey := key
		if hashKey == "" && meta != nil {
			hashKey = meta.smartTarget
		}
		return pickRendezvous(pool, hashKey), strategy
	}
	return pickSmart(pool), balanceStrategySmart
}

// pickSmart is weighted least-connections: the cost of a node is its live
// connections (+1) divided by its quality, so a node twice as good carries
// twice the connections at equilibrium. Nodes within balanceSmartSpread of
// the cheapest share the draw, weighted by quality, so a burst of new
// connections does not all land on the one node that was cheapest when the
// burst started.
func pickSmart(pool []poolEntry) int {
	costs := make([]float64, len(pool))
	minCost := math.Inf(1)
	for i, entry := range pool {
		costs[i] = float64(entry.load+1) / entry.q
		if costs[i] < minCost {
			minCost = costs[i]
		}
	}
	limit := minCost * balanceSmartSpread
	return pickWeightedRandom(pool, func(i int) bool { return costs[i] <= limit })
}

func pickLeastConnections(pool []poolEntry) int {
	minLoad := pool[0].load
	for _, entry := range pool[1:] {
		if entry.load < minLoad {
			minLoad = entry.load
		}
	}
	return pickWeightedRandom(pool, func(i int) bool { return pool[i].load == minLoad })
}

// pickWeightedRandom draws an index with probability proportional to its
// quality among the entries include accepts (all when nil).
func pickWeightedRandom(pool []poolEntry, include func(int) bool) int {
	total := 0.0
	for i, entry := range pool {
		if include == nil || include(i) {
			total += entry.q
		}
	}
	if total <= 0 {
		return 0
	}
	draw := rand.Float64() * total
	last := 0
	for i, entry := range pool {
		if include != nil && !include(i) {
			continue
		}
		last = i
		draw -= entry.q
		if draw < 0 {
			return i
		}
	}
	return last
}

// tagOrder returns pool indexes sorted by tag, the stable order the
// round-robin strategies rotate over.
func tagOrder(pool []poolEntry) []int {
	order := make([]int, len(pool))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return pool[order[i]].tag < pool[order[j]].tag })
	return order
}

func (b *smartBalance) pickRoundRobin(pool []poolEntry, code string) int {
	counter, _ := b.rrCounters.LoadOrCompute(code, func() *atomic.Uint64 { return new(atomic.Uint64) })
	order := tagOrder(pool)
	return order[int((counter.Add(1)-1)%uint64(len(order)))]
}

// pickWeightedRoundRobin is nginx's smooth weighted round-robin over the
// pool, weights being the qualities: deterministic, proportional, and
// interleaved instead of bursty.
func (b *smartBalance) pickWeightedRoundRobin(pool []poolEntry, code string) int {
	b.wrrMu.Lock()
	defer b.wrrMu.Unlock()
	current := b.wrrState[code]
	if current == nil {
		current = make(map[string]float64, len(pool))
		b.wrrState[code] = current
	}
	present := make(map[string]struct{}, len(pool))
	total := 0.0
	best := -1
	for _, i := range tagOrder(pool) {
		entry := pool[i]
		present[entry.tag] = struct{}{}
		current[entry.tag] += entry.q
		total += entry.q
		if best < 0 || current[entry.tag] > current[pool[best].tag] {
			best = i
		}
	}
	for tag := range current {
		if _, ok := present[tag]; !ok {
			delete(current, tag)
		}
	}
	current[pool[best].tag] -= total
	return best
}

// pickRendezvous is weighted rendezvous hashing: the same key keeps landing
// on the same node while it stays in the pool, and when a node leaves only
// its own keys move.
func pickRendezvous(pool []poolEntry, key string) int {
	if key == "" {
		return pickWeightedRandom(pool, nil)
	}
	best := 0
	bestScore := math.Inf(-1)
	for i, entry := range pool {
		h := xxhash.Sum64String(key + "\x00" + entry.tag)
		u := (float64(h>>11) + 0.5) / (1 << 53)
		score := -entry.q / math.Log(u)
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// selectCandidates is the smart-loadbalance replacement for the tiered
// Smart selection: decide the region order, build the primary pool, pick
// the node for this connection, and append the rest of the pool plus the
// best nodes of the fallback regions for dialWithRetry's failover. The list
// fits in what dialWithRetry dials before it re-selects (one node, then
// batches of three), so the fallback tail is actually reached.
func (b *smartBalance) selectCandidates(meta *smartDialMeta, isUDP bool, bypassPin bool) ([]adapter.Outbound, string) {
	snap := b.snapshot()
	var request *balanceRequest
	if meta != nil {
		request = meta.balance
	}
	blocked := b.blockedNodes()
	if request != nil && request.pin != "" && !bypassPin {
		for _, ob := range snap.members(request.region) {
			if ob.Tag() == request.pin && !b.s.isBreakerOpen(request.pin) && (!isUDP || b.s.supportsUDP(ob)) {
				return []adapter.Outbound{ob}, "region-pin"
			}
		}
	}
	sc := b.newScorer(meta, isUDP)
	decision := b.decideRegions(meta, snap, isUDP, sc)
	var (
		primary   []poolEntry
		picked    int
		source    string
		fallbacks []adapter.Outbound
		regions   int
	)
	for _, code := range decision.order {
		pool := b.buildPool(code, snap, meta, isUDP, blocked, sc)
		if len(pool) == 0 {
			continue
		}
		if primary == nil {
			var how string
			primary = pool
			picked, how = b.pick(pool, code, meta)
			label := code
			if label == "" {
				label = "*"
			}
			source = decision.source + " region=" + label + " pick=" + how + " pool=" + strconv.Itoa(len(pool))
			continue
		}
		if regions >= balanceFallbackRegions {
			break
		}
		regions++
		for i := 0; i < len(pool) && i < balanceFallbackPerRegion; i++ {
			fallbacks = append(fallbacks, pool[i].ob)
		}
	}
	if primary == nil {
		// Nothing dialable where the connection may go. Like Smart's last
		// resort, try the members anyway — health data may be wrong or
		// stale, and one success revives the group. With a region chosen
		// (its healthy nodes were all filtered out for this destination),
		// stay in it; otherwise go wherever lastResortScope allows.
		code, ok := "", true
		if len(decision.order) > 0 {
			code = decision.order[0]
		} else {
			code, ok = b.lastResortScope(meta, snap, isUDP)
		}
		if !ok {
			return nil, decision.source + " (no healthy node)"
		}
		primary = b.lastResortPool(code, snap, meta, isUDP, blocked, sc)
		if len(primary) == 0 {
			return nil, decision.source + " (no node)"
		}
		picked = 0
		source = decision.source + " (last resort: no healthy node)"
	}
	reach := 1 + (smartMaxRetries-1)*smartParallelDials
	if len(fallbacks) > balanceFallbackSlots {
		fallbacks = fallbacks[:balanceFallbackSlots]
	}
	primaryTake := min(len(primary), reach-len(fallbacks))
	candidates := make([]adapter.Outbound, 0, primaryTake+len(fallbacks))
	candidates = append(candidates, primary[picked].ob)
	for i, entry := range primary {
		if i != picked && len(candidates) < primaryTake {
			candidates = append(candidates, entry.ob)
		}
	}
	return append(candidates, fallbacks...), source
}

// lastResortScope decides where the last resort may look when no healthy
// node could be chosen: a region outbound without fallback or a region
// locked with fallback none stays in its region, everything else may use
// every allowed member. It refuses when healthy members exist in scope —
// then the configuration (fallback none, allow / deny, min_nodes) is what
// rejected the connection, and that is honoured.
func (b *smartBalance) lastResortScope(meta *smartDialMeta, snap *regionSnapshot, isUDP bool) (string, bool) {
	code := ""
	switch {
	case meta != nil && meta.balance != nil && meta.balance.region != "" && !meta.balance.fallback:
		code = meta.balance.region
	case meta != nil && meta.balance != nil && meta.balance.region != "":
		code = ""
	case b.currentLock() != "" && b.fallback == regionFallbackNone:
		code = b.currentLock()
	}
	counts := b.healthyCounts(snap, isUDP)
	if code != "" {
		return code, counts[code] == 0
	}
	for region, n := range counts {
		if n > 0 && b.allowed(region) {
			return "", false
		}
	}
	return "", true
}

// lastResortPool is the members of the scope that are not blocked and can
// carry the connection, best quality first, health ignored.
func (b *smartBalance) lastResortPool(code string, snap *regionSnapshot, meta *smartDialMeta, isUDP bool, blocked map[string]bool, sc *balanceScorer) []poolEntry {
	var pool []poolEntry
	for _, ob := range b.regionMembers(snap, code) {
		tag := ob.Tag()
		if blocked[tag] || (isUDP && !b.s.supportsUDP(ob)) {
			continue
		}
		q, _ := sc.quality(tag)
		pool = append(pool, poolEntry{ob: ob, tag: tag, q: q, load: b.nodeLoad(tag)})
	}
	sort.SliceStable(pool, func(i, j int) bool { return pool[i].q > pool[j].q })
	return pool
}

// dialIsChainedHop reports whether a dial is a hop of a proxy chain rather
// than the connection the inherited meta describes: a landing node that
// uses the group as its detour dials its own server, while the meta in the
// context (set by an outer Smart group) still describes the website. The
// group must then learn, match destinations and balance for the landing
// server, not the website.
func dialIsChainedHop(meta *smartDialMeta, destination M.Socksaddr) bool {
	if meta == nil || meta.smartTarget == "" {
		return false
	}
	if destination.IsFqdn() {
		host := strings.TrimSuffix(strings.ToLower(destination.Fqdn), ".")
		metaHost := strings.TrimSuffix(strings.ToLower(meta.host), ".")
		if host == metaHost {
			return false
		}
		// Another host of the same site (www → cdn) is the same connection
		// target, not a chain hop.
		if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && metaHost != "" {
			if metaSite, err := publicsuffix.EffectiveTLDPlusOne(metaHost); err == nil && site == metaSite {
				return false
			}
		}
		return normaliseDialTarget(host, "") != meta.smartTarget
	}
	if !destination.Addr.IsValid() {
		return false
	}
	addr := destination.Addr.Unmap()
	for _, ip := range meta.resolvedIPs {
		if ip.Unmap() == addr {
			return false
		}
	}
	return meta.host != addr.String() && meta.smartTarget != addr.String()
}

// attachRequest copies meta with the region view's request when the dial
// came from a smart-region outbound of this group.
func (b *smartBalance) attachRequest(ctx context.Context, meta *smartDialMeta) *smartDialMeta {
	request, _ := ctx.Value(balanceRequestKey{}).(*balanceRequest)
	if request == nil || request.group != b.s.Tag() {
		if meta.balance == nil {
			return meta
		}
		// A request meant for another group leaked in through a nested
		// dial; drop it.
		copied := *meta
		copied.balance = nil
		return &copied
	}
	copied := *meta
	copied.balance = request
	return &copied
}

// onDialSuccess records the outcome of a successful dial: the affinity
// binding, the target's region memory (following a failover into another
// region), the region's last node for its view, and the probe target.
func (b *smartBalance) onDialSuccess(meta *smartDialMeta, tag string) {
	snap := b.snapshot()
	code := snap.regionOf[tag]
	now := time.Now().UnixNano()
	if code != "" {
		b.regionLast.Store(code, tag)
		b.lastRegion.Store(&code)
	}
	if meta == nil {
		return
	}
	if meta.balance != nil && meta.balance.onSuccess != nil {
		meta.balance.onSuccess(tag)
	}
	// Affinity is keyed by the pool the pick came from: the node's region,
	// or the all-members pool of region mode off.
	pool := code
	if meta.balance == nil && b.currentLock() == "" && b.currentMode() == regionModeOff {
		pool = ""
	}
	if key := b.affinityKey(meta, pool); key != "" && (code != "" || pool == "") {
		if b.affinityMemo.Size() >= balanceMemoLimit {
			b.pruneMemos(false)
		}
		b.affinityMemo.Store(key, affinityEntry{tag: tag, lastUse: now})
	}
	if meta.balance == nil && meta.smartTarget != "" && code != "" {
		if memo, ok := b.regionMemo.Load(meta.smartTarget); ok && memo.code != code {
			memo.code, memo.lastUse = code, now
			b.regionMemo.Store(meta.smartTarget, memo)
		}
	}
	b.recordProbeTarget(meta)
}

// pruneMemos drops expired region / affinity memories, and clears the map
// outright when it is still over the limit.
func (b *smartBalance) pruneMemos(region bool) {
	now := time.Now().UnixNano()
	if region {
		b.regionMemo.Range(func(key string, entry regionMemoEntry) bool {
			if now-entry.lastUse > int64(b.sticky) {
				b.regionMemo.Delete(key)
			}
			return true
		})
		if b.regionMemo.Size() >= balanceMemoLimit {
			b.regionMemo.Clear()
		}
		return
	}
	b.affinityMemo.Range(func(key string, entry affinityEntry) bool {
		if now-entry.lastUse > int64(b.affinityTTL) {
			b.affinityMemo.Delete(key)
		}
		return true
	})
	if b.affinityMemo.Size() >= balanceMemoLimit {
		b.affinityMemo.Clear()
	}
}

// pruneMemory is the periodic janitor: expired memories, stale probe
// results and probe targets, counters of departed members.
func (b *smartBalance) pruneMemory() {
	b.pruneMemos(true)
	b.pruneMemos(false)
	b.pruneProbes()
	snap := b.snapshot()
	b.pending.Range(func(tag string, counter *atomic.Int64) bool {
		if _, ok := snap.regionOf[tag]; !ok && counter.Load() == 0 {
			b.pending.Delete(tag)
		}
		return true
	})
}

// ── Construction ───────────────────────────────────────────────────────────

func RegisterSmartLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.SmartLoadBalanceOutboundOptions](registry, C.TypeSmartLoadBalance, NewSmartLoadBalance)
}

// NewSmartLoadBalance builds a smart-loadbalance group: a Smart group whose
// selection is replaced by region pools and per-connection distribution.
func NewSmartLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartLoadBalanceOutboundOptions) (adapter.Outbound, error) {
	smartOptions := options.SmartOutboundOptions
	if smartOptions.Algorithm != "" {
		logger.Warn("smart-loadbalance[", tag, "]: algorithm is ignored; use balance.strategy")
		smartOptions.Algorithm = ""
	}
	if smartOptions.Hysteresis > 0 {
		logger.Warn("smart-loadbalance[", tag, "]: hysteresis is ignored; use region.sticky and balance.affinity")
		smartOptions.Hysteresis = 0
	}
	s, err := newSmart(ctx, router, logger, tag, C.TypeSmartLoadBalance, smartOptions)
	if err != nil {
		return nil, err
	}
	s.balance, err = newSmartBalance(s, options.Balance, options.Region)
	if err != nil {
		return nil, E.Cause(err, "smart-loadbalance[", tag, "]")
	}
	if err = s.balance.createDeclaredSubgroups(ctx, router, logger); err != nil {
		return nil, E.Cause(err, "smart-loadbalance[", tag, "]")
	}
	return s, nil
}
