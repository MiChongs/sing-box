package group

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/common/urltest"
	smartservice "github.com/sagernet/sing-box/experimental/smart"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	smartMaxRetries     = 4
	smartMaxSelected    = 10
	smartParallelDials  = 3
	smartConnThreshold  = 2.0
	smartConfigName     = "singbox"
)

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

var _ adapter.OutboundGroup = (*Smart)(nil)

// smartGroupState is an immutable snapshot of the outbound list.
type smartGroupState struct {
	outbounds []adapter.Outbound
	tags      []string
}

// smartDialMeta carries per-request metadata injected from NewConnectionEx.
type smartDialMeta struct {
	host        string
	smartTarget string
	asnCode     string
	destGeoIP   []string // ISO country codes; best-effort from resolved IP
	resolvedIPs []netip.Addr
	isUDP       bool
	destPort    uint16
}

// firstValidIPString returns the first valid IP from a slice as its string form, or "".
func firstValidIPString(ips []netip.Addr) string {
	for _, ip := range ips {
		if ip.IsValid() {
			return ip.String()
		}
	}
	return ""
}

type smartMetaCtxKey struct{}

// priorityRule is a policy-priority rule (pattern + factor).
type priorityRule struct {
	pattern string
	regex   *regexp.Regexp
	factor  float64
	isRegex bool
}

// Smart is the Smart outbound group — history-weighted, parallel-race, ASN-aware.
type Smart struct {
	outbound.Adapter
	ctx        context.Context
	router     adapter.Router
	outboundMgr adapter.OutboundManager
	connection  adapter.ConnectionManager
	logger      log.ContextLogger

	state atomic.Pointer[smartGroupState]

	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	testURL            string
	interval           time.Duration
	disableUDP         bool
	policyPriority     []priorityRule
	useASN             bool
	asnDBPath          string // configured path; "" means "fall back to geox service"
	asnDB              *maxminddb.Reader
	countryDB          *maxminddb.Reader // country.mmdb from GeoX, optional
	maxHostFailedTimes int               // mihomo parity; 0 = default 10

	store *smart.Store

	// Active connections registry keyed by target. Used by markTargetDegraded
	// to proactively close in-flight connections to a target after a node was
	// degraded so the user's client re-issues and Smart re-selects.
	// Mirrors mihomo's findSameConnection behaviour.
	targetConnsMu sync.Mutex
	targetConns   map[string]map[*smartTrackedConn]struct{}

	// Dial-failure tracking at the group level. Same idea as URLTest's
	// reportDialFailure — accumulated failures across the group trigger an
	// immediate async health re-evaluation (mihomo onDialFailed/Success).
	dialFailCount atomic.Int32
	dialFailAt    atomic.Int64
	recheckOnce   atomic.Bool

	// knownDead records nodes that failed their most recent probe. It
	// disambiguates "untested" (history=nil → assume alive during bootstrap)
	// from "tested and failed" (must-not-select until next success). The
	// previous implementation called DeleteURLTestHistory on failure, which
	// isAlive then saw as nil and treated as alive — the node never got
	// removed from selection even when permanently broken.
	//
	// Entries expire after knownDeadTTL so a recovered node isn't
	// permanently blackholed if the test URL was only briefly unreachable.
	knownDeadMu sync.RWMutex
	knownDead   map[string]time.Time

	// countryDBRetryAt throttles re-opening country.mmdb when the GeoX
	// download finishes after PostStart (first open was a no-op because
	// the file didn't exist yet).
	countryDBRetryAt atomic.Int64

	// shortLife tracks "user gave up quickly" closes per (target, node)
	// pair. When the user reaches the threshold within the window we
	// promote the node to knownDead — even though individual closes were
	// not classified as failures. Makes Smart actually respond to the
	// user's observable dissatisfaction (three Ctrl+W's in a row on a
	// slow page) instead of silently re-picking the same bad node.
	shortLifeMu sync.Mutex
	shortLife   map[string][]time.Time

	// provider support
	provider         adapter.ProviderManager
	providers        map[string]adapter.Provider
	outboundsCacheMu sync.Mutex
	outboundsCache   map[string][]adapter.Outbound
	providerTags     []string
	exclude          *regexp.Regexp
	include          *regexp.Regexp
	useAllProviders  bool

	history adapter.URLTestHistoryStorage

	taskCtx    context.Context
	taskCancel context.CancelFunc
	taskWg     sync.WaitGroup

	started atomic.Bool

	// Most recently selected (successfully dialed) node tag. Surfaced via
	// Now() for ClashAPI / UI display. Updated on every successful dial
	// from both DialContext and ListenPacket paths.
	lastSelectedTag atomic.Value // string

	// Manually pinned node tag (ClashAPI PUT /proxies/<tag> with {"name": X}).
	// When non-empty, selectProxies short-circuits to only this node — the
	// Smart algorithm is bypassed entirely (mihomo parity: Set/ForceSet).
	manualSelected atomic.Value // string

	// Per-group ML/collector opt-in flags. The actual model, downloader and
	// collector are owned by the shared SmartService (experimental.smart);
	// we only hold references here for zero-lookup on the hot path.
	useLightGBM   bool
	collectData   bool
	sampleRate    float64
	weightModel   *lightgbm.WeightModel
	dataCollector *lightgbm.DataCollector
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	networks := []string{N.NetworkTCP}
	if !options.DisableUDP {
		networks = append(networks, N.NetworkUDP)
	}

	s := &Smart{
		Adapter: outbound.NewAdapter(C.TypeSmart, tag, networks, options.Outbounds),
		ctx:     ctx,
		router:  router,
		outboundMgr: service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:  logger,

		interruptExternalConnections: options.InterruptExistConnections,

		testURL:    options.URL,
		interval:   time.Duration(options.Interval),
		disableUDP: options.DisableUDP,
		useASN:     options.UseASN,

		provider:        service.FromContext[adapter.ProviderManager](ctx),
		providers:       make(map[string]adapter.Provider),
		outboundsCache:  make(map[string][]adapter.Outbound),
		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,

		useLightGBM:        options.UseLightGBM,
		collectData:        options.CollectData,
		sampleRate:         options.SampleRate,
		maxHostFailedTimes: options.MaxHostFailedTimes,
		targetConns:        make(map[string]map[*smartTrackedConn]struct{}),
		shortLife:          make(map[string][]time.Time),
	}
	if s.maxHostFailedTimes <= 0 {
		s.maxHostFailedTimes = 10
	}

	if s.testURL == "" {
		s.testURL = "https://www.gstatic.com/generate_204"
	}
	if s.interval <= 0 {
		s.interval = 3 * time.Minute
	}
	if s.sampleRate <= 0 || s.sampleRate > 1 {
		s.sampleRate = 1.0
	}

	s.parsePolicyPriority(options.PolicyPriority)

	// Record the per-group ASN mmdb path; actual file open happens in
	// PostStart so we can fall back to the global GeoX service path when
	// the per-group field is empty.
	s.asnDBPath = options.ASNDatabase

	return s, nil
}

func (s *Smart) parsePolicyPriority(raw string) {
	if raw == "" {
		return
	}
	for _, pair := range strings.Split(raw, ";") {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[1]) == "" {
			continue
		}
		factor, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
		if err != nil || factor <= 0 {
			continue
		}
		rule := priorityRule{pattern: kv[0], factor: factor}
		if re, err := regexp.Compile(kv[0]); err == nil {
			rule.regex = re
			rule.isRegex = true
		}
		s.policyPriority = append(s.policyPriority, rule)
	}
}

func (s *Smart) Start() error {
	if s.useAllProviders {
		for _, provider := range s.provider.Providers() {
			s.providers[provider.Tag()] = provider
			s.providerTags = append(s.providerTags, provider.Tag())
			provider.RegisterCallback(s.onProviderUpdated)
		}
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			provider.RegisterCallback(s.onProviderUpdated)
		}
	}

	deps := s.Dependencies()
	if len(deps)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	var outbounds []adapter.Outbound
	var tags []string
	for i, tag := range deps {
		detour, loaded := s.outboundMgr.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		detour, _ := s.outboundMgr.Outbound("Compatible")
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}

	s.interruptGroup = interrupt.NewGroup()
	s.state.Store(&smartGroupState{outbounds: outbounds, tags: tags})
	return nil
}

func (s *Smart) PostStart() error {
	// Get history storage from Clash server (for alive-checking)
	if clashServer := service.FromContext[adapter.ClashServer](s.ctx); clashServer != nil {
		s.history = clashServer.HistoryStorage()
	}

	// Get cache file and init store
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
		db := cacheFile.SmartDB()
		if db != nil {
			s.store = smart.GetOrInitStore(db)
		}
	}

	if s.store == nil {
		s.logger.Warn("smart: no cache file available, using ephemeral store")
	}

	// Resolve ASN mmdb: per-group path wins; fall back to global experimental.geox.
	if s.useASN {
		asnPath := s.asnDBPath
		if asnPath == "" {
			if geoSvc := service.FromContext[adapter.GeoXService](s.ctx); geoSvc != nil {
				asnPath = geoSvc.ASNPath()
				if asnPath != "" {
					s.logger.Info("smart: ASN database path not configured; using global experimental.geox.asn = ", asnPath)
				}
			}
		}
		if asnPath == "" {
			s.logger.Warn("smart: use_asn is true but no ASN database path resolved (set asn_database or experimental.geox.url.asn); ASN features disabled")
		} else if db, err := maxminddb.Open(asnPath); err != nil {
			s.logger.Warn("smart: failed to open ASN database [", asnPath, "]: ", err, " (will retry on next reload)")
		} else {
			s.asnDB = db
		}
	}

	// Optional country mmdb — feeds ModelInput.DestGeoIP (LightGBM features
	// 17 and 26). When the GeoX service has downloaded country.mmdb we use
	// it; otherwise DestGeoIP stays nil and those features fall back to 0.
	if geoSvc := service.FromContext[adapter.GeoXService](s.ctx); geoSvc != nil {
		if mmdbPath := geoSvc.MMDBPath(); mmdbPath != "" {
			if db, err := maxminddb.Open(mmdbPath); err == nil {
				s.countryDB = db
				s.logger.Info("smart: country mmdb loaded from ", mmdbPath, " (feeds DestGeoIP feature)")
			} else {
				s.logger.Debug("smart: country mmdb not yet available: ", err)
			}
		}
	}

	// Pull shared infrastructure from experimental.smart (SmartService).
	// This lets multiple Smart groups share a single model/downloader/collector.
	// Defaults kick in when experimental.smart.{lightgbm,collector} is absent —
	// a group-level flag alone is enough.
	if s.useLightGBM || s.collectData {
		smartSvc, _ := service.FromContext[adapter.SmartService](s.ctx).(*smartservice.Service)
		if smartSvc == nil {
			s.logger.Warn("smart: use_lightgbm/collect_data requested but experimental.smart service unavailable; falling back to traditional algorithm")
		} else {
			if s.useLightGBM {
				if model, err := smartSvc.WeightModel(); err != nil {
					s.logger.Warn("smart: failed to obtain shared LightGBM model: ", err)
				} else {
					s.weightModel = model
					s.logger.Info("smart: group [", s.Tag(), "] ML prediction enabled")
				}
			}
			if s.collectData {
				if dc, err := smartSvc.DataCollector(); err != nil {
					s.logger.Warn("smart: failed to obtain shared data collector: ", err)
				} else {
					s.dataCollector = dc
					s.logger.Info("smart: group [", s.Tag(), "] training-data collection enabled (sample_rate=", s.sampleRate, ")")
				}
			}
		}
	}

	// Start background tasks
	s.taskCtx, s.taskCancel = context.WithCancel(context.Background())

	type taskDef struct {
		name    string
		initial time.Duration
		period  time.Duration
		fn      func()
		once    bool
	}

	tasks := []taskDef{
		// Active URL probing — populates URLTestHistoryStorage so isAlive,
		// selectFullScan ranking and fillProxies actually see dead nodes.
		// Without this a standalone Smart group treats every node as alive.
		{"health-check", 10 * time.Second, s.interval, s.runHealthCheck, false},
		{"nodes-ranking", 1 * time.Minute, 5 * time.Minute, s.updateNodeRanking, false},
		{"prefetch", 5 * time.Minute, 10 * time.Minute, s.runPrefetch, false},
		{"recovery-check", 5 * time.Minute, 5 * time.Minute, s.checkAndRecoverDegradedNodes, false},
		{"cleanup-old", 10 * time.Minute, 120 * time.Minute, s.cleanupOldRecords, false},
		{"cleanup-orphan", 10 * time.Minute, 10 * time.Minute, s.cleanupOrphanedNodeCache, false},
		// Orphan-groups cleanup only runs on one arbitrarily-chosen group each
		// interval; it's process-global work (remove Smart store data for
		// groups no longer present in config). Doing it per group still works
		// because the logic is idempotent.
		{"cleanup-orphan-groups", 15 * time.Minute, 120 * time.Minute, s.cleanupOrphanedGroups, false},
		{"flush-queue", 5 * time.Second, 5 * time.Minute, s.flushQueue, false},
		{"cache-adjust", 5 * time.Second, 5 * time.Minute, s.adjustCache, false},
	}

	for _, t := range tasks {
		s.startTimedTask(t.name, t.initial, t.period, t.fn, t.once)
	}

	// Startup summary — single info line with all relevant flags.
	snap := s.state.Load()
	outboundCount := 0
	if snap != nil {
		outboundCount = len(snap.tags)
	}
	asnStatus := "off"
	if s.useASN {
		if s.asnDB != nil {
			asnStatus = "on"
		} else {
			asnStatus = "on(no-db)"
		}
	}
	mlStatus := "off"
	if s.useLightGBM {
		if s.weightModel != nil && s.weightModel.IsLoaded() {
			mlStatus = "loaded"
		} else {
			mlStatus = "pending"
		}
	}
	collectStatus := "off"
	if s.dataCollector != nil {
		collectStatus = "on(" + formatFloat(s.sampleRate, 2) + ")"
	}
	s.logger.Info("smart[", s.Tag(), "] started: ", outboundCount, " outbounds, ",
		len(tasks), " background tasks, testURL=", s.testURL,
		" interval=", s.interval, " asn=", asnStatus,
		" ml=", mlStatus, " collect=", collectStatus)

	s.started.Store(true)
	return nil
}

func (s *Smart) startTimedTask(name string, initial, period time.Duration, fn func(), once bool) {
	s.taskWg.Add(1)
	go func() {
		defer s.taskWg.Done()
		jitter := time.Duration(rand.Float64() * 30 * float64(time.Second))
		select {
		case <-time.After(initial + jitter):
		case <-s.taskCtx.Done():
			return
		}
		fn()
		if once {
			return
		}
		ticker := time.NewTicker(period + jitter)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fn()
			case <-s.taskCtx.Done():
				return
			}
		}
	}()
}

func (s *Smart) Close() error {
	s.started.Store(false)
	if s.taskCancel != nil {
		s.taskCancel()
	}
	s.taskWg.Wait()
	// Shared LightGBM model, downloader and collector are owned by
	// experimental.smart.Service — do NOT close them here.
	if s.store != nil {
		s.store.FlushQueue(true)
	}
	if s.asnDB != nil {
		_ = s.asnDB.Close()
	}
	if s.countryDB != nil {
		_ = s.countryDB.Close()
	}
	return nil
}

// TestURL returns the URL used for aliveness checks.
func (s *Smart) TestURL() string { return s.testURL }

// UseASN returns whether ASN-based routing is enabled.
func (s *Smart) UseASN() bool { return s.useASN }

// UseLightGBM reports whether ML prediction is enabled.
func (s *Smart) UseLightGBM() bool { return s.useLightGBM }

// CollectData reports whether training-data collection is enabled.
func (s *Smart) CollectData() bool { return s.collectData }

// LGBMModelAge returns time since last successful model load.
// Returns 0 when no model is loaded (useful for API display).
func (s *Smart) LGBMModelAge() time.Duration {
	if s.weightModel == nil {
		return 0
	}
	last := s.weightModel.LastUpdate()
	if last.IsZero() {
		return 0
	}
	return time.Since(last)
}

// getManualSelected returns the currently pinned node tag, or "" if none.
func (s *Smart) getManualSelected() string {
	if v, ok := s.manualSelected.Load().(string); ok {
		return v
	}
	return ""
}

// SelectOutbound pins a specific node as the only one Smart will use. Pass
// empty name to clear the pin and resume automatic selection. Returns false
// only if the name is non-empty and does not match any current outbound.
//
// ClashAPI exposes this via `PUT /proxies/<tag>` with JSON `{"name": "..."}`,
// mirroring the Selector behaviour and mihomo's Set/ForceSet.
func (s *Smart) SelectOutbound(tag string) bool {
	if tag == "" {
		s.manualSelected.Store("")
		s.logger.Info("smart[", s.Tag(), "] manual pin cleared, automatic selection resumed")
		return true
	}
	snap := s.state.Load()
	if snap == nil {
		return false
	}
	for _, ob := range snap.outbounds {
		if ob.Tag() == tag {
			s.manualSelected.Store(tag)
			s.setLastSelected(tag)
			s.logger.Info("smart[", s.Tag(), "] manually pinned to [", tag, "]")
			return true
		}
	}
	return false
}

// Selected returns the pinned node tag, or "" when Smart is in automatic mode.
// Surfaced in Clash API output as the `fixed` field.
func (s *Smart) Selected() string { return s.getManualSelected() }

// ConfigName returns the Smart store's config namespace ("singbox" in this
// fork — mihomo used the config filename). Exposed for ClashAPI routes that
// need to address the Smart store per-config.
func (s *Smart) ConfigName() string { return smartConfigName }

// WeightRanking returns the cached ranked node list (sorted by weight) for
// this group, used by `GET /proxies/<tag>/weights`. Returns a non-nil empty
// slice when no ranking has been computed yet; never returns nil.
// When forceRefresh is true, the ranking is recomputed synchronously before
// returning — useful for an explicit recompute button in the UI.
func (s *Smart) WeightRanking(forceRefresh bool) ([]smart.NodeRank, error) {
	if s.store == nil {
		return []smart.NodeRank{}, nil
	}
	if forceRefresh {
		snap := s.state.Load()
		if snap == nil || len(snap.tags) == 0 {
			return []smart.NodeRank{}, nil
		}
		ranking, err := s.store.GetNodeWeightRanking(s.Tag(), smartConfigName, s.testURL, s.isAlive, snap.tags)
		if err != nil {
			return []smart.NodeRank{}, err
		}
		if ranking == nil {
			return []smart.NodeRank{}, nil
		}
		return ranking, nil
	}
	ranking, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName)
	if err != nil {
		return []smart.NodeRank{}, err
	}
	if ranking == nil {
		return []smart.NodeRank{}, nil
	}
	return ranking, nil
}

// FlushStore wipes all Smart persistent data for this specific group.
func (s *Smart) FlushStore() error {
	if s.store == nil {
		return nil
	}
	s.manualSelected.Store("")
	return s.store.FlushByGroup(s.Tag(), smartConfigName)
}

// SmartStore exposes the underlying store for global-flush operations.
// Returns nil if the cache file was not configured.
func (s *Smart) SmartStore() *smart.Store { return s.store }

// NotifyUserDisconnect records an unambiguous user-initiated disconnect
// against (target, node). The Clash API connection-close handlers call
// this so manual "close connection" clicks / API DELETEs participate in
// the same short-life → markDead escalation path as in-process
// smartTrackedConn.Close. Without this, disconnects routed exclusively
// through the API bypassed the detection logic.
//
// target may be empty (derived from tracker metadata) — in that case we
// still drop any unwrap cache that references the node across all
// targets, so the next dial re-evaluates candidates.
func (s *Smart) NotifyUserDisconnect(target, node string, isUDP bool, asnCode string) {
	if node == "" {
		return
	}
	if target == "" {
		// Best-effort: we don't know which target to blame, so at minimum
		// ensure the node re-enters short-life aggregation via a synthetic
		// key. Uses node tag as the sole key so repeated API closes on the
		// same node still accumulate.
		target = "__clashapi__"
	}
	if s.recordShortLife(target, node) {
		s.markDead(node)
		if s.store != nil && target != "__clashapi__" {
			s.store.DeleteUnwrapResult(s.Tag(), smartConfigName, target, asnCode, isUDP)
		}
		s.logger.Info("smart[", s.Tag(), "] node [", node,
			"] marked dead after ", shortLifeThreshold,
			" user-initiated disconnects (target=", target, ")")
		return
	}
	// Below threshold: still clear unwrap for this target so the next dial
	// re-selects rather than pinning back to the same node.
	if s.store != nil && target != "__clashapi__" {
		s.store.DeleteUnwrapResult(s.Tag(), smartConfigName, target, asnCode, isUDP)
	}
}

// DefaultBlockDuration applied by MarkBlocked when caller doesn't specify one.
const DefaultBlockDuration = 30 * time.Minute

// MarkBlocked writes an immediate long-duration block for a specific node.
// Mirrors mihomo's `DELETE /connections/smart/{id}` flow where a user-initiated
// block forces the Smart algorithm to stop selecting that node even if its
// raw weight is still high (the failure hasn't propagated yet).
//
// duration <= 0 uses DefaultBlockDuration (30 min). Failure count is set to
// 100 so the natural recovery (0.01 per tick) takes meaningful time.
func (s *Smart) MarkBlocked(nodeTag string, duration time.Duration) error {
	if s.store == nil {
		return E.New("smart: store unavailable")
	}
	if nodeTag == "" {
		return E.New("smart: empty node tag")
	}
	if duration <= 0 {
		duration = DefaultBlockDuration
	}
	now := time.Now()
	state := smart.NodeState{
		Name:           nodeTag,
		FailureCount:   100,
		LastFailure:    now.Unix(),
		Degraded:       true,
		DegradedFactor: 0.1,
		BlockedUntil:   now.Add(duration).Unix(),
	}
	data, err := json.Marshal(&state)
	if err != nil {
		return err
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveNodeState,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   nodeTag,
		Data:   data,
	})
	smart.ClearBlockedNodesCache(s.Tag(), smartConfigName)

	// Also drop any unwrap-cache entries that might still point at this node.
	// The alternative — traversing every cached target — is expensive; the
	// blockedNodes filter in fillProxies handles it lazily on next dial.
	s.logger.Info("smart[", s.Tag(), "] node [", nodeTag, "] manually blocked for ", duration)
	return nil
}

// Now returns the most recently successfully dialed node tag.
//
// Smart has no single "current" outbound like Selector — it races and chooses
// per-connection. This surfaces the last winner so ClashAPI / dashboards can
// show a useful value instead of a static placeholder.
//
// Fallback order:
//  1. Last successful dial's winning tag.
//  2. Top-ranked node from the pre-sorted ranking cache, if any.
//  3. First outbound in the snapshot (best-effort guess before any traffic).
//  4. Empty string — OutboundGroup helpers fall back to the group's own tag.
func (s *Smart) Now() string {
	if v, ok := s.lastSelectedTag.Load().(string); ok && v != "" {
		return v
	}
	// Second-best: use the ranking cache's top entry.
	if s.store != nil {
		if ranking, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName); err == nil {
			for _, r := range ranking {
				if r.Weight > 0 {
					return r.Name
				}
			}
		}
	}
	// Third-best: first available node from the snapshot.
	if snap := s.state.Load(); snap != nil && len(snap.tags) > 0 {
		return snap.tags[0]
	}
	return ""
}

// setLastSelected records a successful dial winner for Now() reporting.
func (s *Smart) setLastSelected(tag string) {
	if tag == "" {
		return
	}
	s.lastSelectedTag.Store(tag)
}

// All returns a snapshot of all outbound tags.
func (s *Smart) All() []string {
	snap := s.state.Load()
	if snap == nil {
		return nil
	}
	result := make([]string, len(snap.tags))
	copy(result, snap.tags)
	return result
}

// NewConnectionEx injects Smart metadata and delegates to connection manager.
func (s *Smart) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	meta := s.buildMeta(metadata, false)
	ctx = context.WithValue(ctx, smartMetaCtxKey{}, meta)
	if s.interruptExternalConnections {
		ctx = interrupt.ContextWithIsExternalConnection(ctx)
	}
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

// NewPacketConnectionEx injects Smart metadata (UDP) and delegates.
func (s *Smart) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	meta := s.buildMeta(metadata, true)
	ctx = context.WithValue(ctx, smartMetaCtxKey{}, meta)
	if s.interruptExternalConnections {
		ctx = interrupt.ContextWithIsExternalConnection(ctx)
	}
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *Smart) buildMeta(metadata adapter.InboundContext, isUDP bool) *smartDialMeta {
	host := metadata.Destination.Fqdn
	if host == "" {
		host = metadata.SniffHost
	}

	ips := metadata.DestinationAddresses
	var firstIP string
	if len(ips) > 0 {
		firstIP = ips[0].String()
	}

	target := smart.GetEffectiveTarget(host, firstIP)
	asnCode := s.lookupASN(ips)
	geoIP := s.lookupCountry(ips)

	return &smartDialMeta{
		host:        host,
		smartTarget: target,
		asnCode:     asnCode,
		destGeoIP:   geoIP,
		resolvedIPs: ips,
		isUDP:       isUDP,
		destPort:    metadata.Destination.Port,
	}
}

// DialContext implements the race-dial with retry logic.
func (s *Smart) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	meta, _ := ctx.Value(smartMetaCtxKey{}).(*smartDialMeta)
	if meta == nil {
		meta = &smartDialMeta{}
	}

	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return nil, E.New("smart: no outbounds available")
	}

	isUDP := N.NetworkName(network) == N.NetworkUDP
	selectedOutbounds, isUnwrap, source := s.selectProxiesTraced(meta, snap.outbounds, isUDP)

	// If everyone in the candidate list is dead, selectProxiesTraced will
	// have already fallen through to a fallback tier via fillProxies. But if
	// the unwrap cache returned a single dead node that survived isAlive
	// (e.g. the health-check goroutine hasn't run yet), proactively drop
	// the unwrap cache and re-select fresh.
	if isUnwrap && len(selectedOutbounds) == 1 && !s.isAlive(selectedOutbounds[0].Tag()) {
		if s.store != nil {
			s.store.DeleteUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP)
		}
		s.logger.DebugContext(ctx, "smart[", s.Tag(),
			"] unwrap cache hit on dead node [", selectedOutbounds[0].Tag(),
			"]; re-selecting")
		selectedOutbounds, isUnwrap, source = s.selectProxiesTraced(meta, snap.outbounds, isUDP)
	}

	s.logger.DebugContext(ctx, "smart[", s.Tag(), "] select via ", source,
		": target=", meta.smartTarget, " asn=[", meta.asnCode,
		"] candidates=", proxyTagsPreview(selectedOutbounds, 5))

	if !isUnwrap && s.store != nil && meta.smartTarget != "" {
		names := outboundNames(selectedOutbounds)
		s.store.StoreUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP, names)
	}

	conn, proxyTag, connectTime, err := s.dialWithRetry(ctx, network, destination, selectedOutbounds, meta)
	if err != nil {
		s.logger.WarnContext(ctx, "smart[", s.Tag(), "] dial failed to ", destination,
			" after retries: ", err)
		return nil, err
	}
	s.setLastSelected(proxyTag)
	s.markAlive(proxyTag) // successful dial = confirmed alive; clears knownDead
	s.logger.InfoContext(ctx, "smart[", s.Tag(), "] ", network, " → ", destination,
		" via [", proxyTag, "] in ", connectTime, "ms (target=", meta.smartTarget,
		" asn=[", meta.asnCode, "] source=", source, ")")

	return s.wrapConn(conn, proxyTag, meta, connectTime, isUDP), nil
}

// ListenPacket implements UDP race-dial.
func (s *Smart) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if s.disableUDP {
		return nil, E.New("smart: UDP disabled")
	}

	meta, _ := ctx.Value(smartMetaCtxKey{}).(*smartDialMeta)
	if meta == nil {
		meta = &smartDialMeta{isUDP: true}
	}

	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return nil, E.New("smart: no outbounds available")
	}

	selectedOutbounds, isUnwrap, source := s.selectProxiesTraced(meta, snap.outbounds, true)

	s.logger.DebugContext(ctx, "smart[", s.Tag(), "] select via ", source,
		" (UDP): target=", meta.smartTarget, " asn=[", meta.asnCode,
		"] candidates=", proxyTagsPreview(selectedOutbounds, 5))

	if !isUnwrap && s.store != nil && meta.smartTarget != "" {
		names := outboundNames(selectedOutbounds)
		s.store.StoreUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, true, names)
	}

	var finalErr error
	for i := 0; i < len(selectedOutbounds) && i < 3; i++ {
		ob := selectedOutbounds[i]
		histCT := s.getHistoryConnectTime(meta, ob.Tag())
		timeout := time.Duration(float64(histCT)*smartConnThreshold) * time.Millisecond
		if timeout <= 0 || timeout > 10*time.Second {
			timeout = 10 * time.Second
		}

		ctxDial, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		pc, err := ob.ListenPacket(ctxDial, destination)
		connectTime := time.Since(start).Milliseconds()
		cancel()

		if err == nil {
			s.setLastSelected(ob.Tag())
			s.markAlive(ob.Tag())
			s.logger.InfoContext(ctx, "smart[", s.Tag(), "] UDP → ", destination,
				" via [", ob.Tag(), "] in ", connectTime, "ms (target=",
				meta.smartTarget, " asn=[", meta.asnCode, "] source=", source, ")")
			return s.wrapPacketConn(pc, ob.Tag(), meta, connectTime), nil
		}
		finalErr = err
		s.markDead(ob.Tag())
		s.logger.DebugContext(ctx, "smart[", s.Tag(), "] UDP probe [", ob.Tag(),
			"] failed in ", connectTime, "ms: ", err)
		go s.recordStats("failed", meta, ob.Tag(), connectTime, 0, 0, 0, 0, 0, 0)
	}

	return nil, finalErr
}

// selectProxiesTraced performs the 3-tier selection and returns which tier
// produced the result. Used for user-visible logging. Tier names:
//   - "manual"   : user-pinned via SetSelected (ClashAPI)
//   - "unwrap"   : hot cache of a recently-used node list for this target
//   - "prefetch" : periodically pre-computed best-node list
//   - "weight"   : realtime computation from the weight store
//   - "fallback" : no history; random pick filtered by alive/blocked
func (s *Smart) selectProxiesTraced(meta *smartDialMeta, all []adapter.Outbound, isUDP bool) ([]adapter.Outbound, bool, string) {
	// Manual selection short-circuit: if user pinned a node, use ONLY that node
	// (matches mihomo's Set/ForceSet semantics).
	if selected := s.getManualSelected(); selected != "" {
		for _, ob := range all {
			if ob.Tag() == selected {
				return []adapter.Outbound{ob}, true, "manual"
			}
		}
		// Pinned tag no longer in provider set — clear pin and fall through.
		s.manualSelected.Store("")
		s.logger.Warn("smart[", s.Tag(), "] pinned node [", selected, "] no longer exists, clearing pin")
	}

	if s.store == nil || meta.smartTarget == "" {
		return s.fillProxies(nil, nil, all, smartMaxSelected, isUDP, false), false, "fallback"
	}

	// Tier 1: unwrap cache
	if names := s.store.GetUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); len(names) > 0 {
		return s.fillProxies(names, nil, all, smartMaxSelected, isUDP, true), true, "unwrap"
	}

	// Tier 2: prefetch cache
	if names, weights := s.store.GetPrefetchResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); len(names) > 0 {
		return s.fillProxies(names, weights, all, smartMaxSelected, isUDP, false), false, "prefetch"
	}

	// Tier 3: real-time computation
	if names, weights, err := s.store.GetBestProxyForTarget(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); err == nil && len(names) > 0 {
		return s.fillProxies(names, weights, all, smartMaxSelected, isUDP, false), false, "weight"
	}

	return s.fillProxies(nil, nil, all, smartMaxSelected, isUDP, false), false, "fallback"
}

// proxyTagsPreview returns a comma-joined preview of up to `limit` tags,
// with an ellipsis when there are more. Used purely for log output.
func proxyTagsPreview(outbounds []adapter.Outbound, limit int) string {
	if len(outbounds) == 0 {
		return "[]"
	}
	n := len(outbounds)
	if n > limit {
		n = limit
	}
	tags := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tags = append(tags, outbounds[i].Tag())
	}
	s := "[" + strings.Join(tags, ",")
	if len(outbounds) > limit {
		s += ",...+" + strconv.Itoa(len(outbounds)-limit) + "]"
	} else {
		s += "]"
	}
	return s
}

// fillProxies assembles the final candidate list with alive/blocked checks and fallback.
func (s *Smart) fillProxies(names []string, weights []float64, all []adapter.Outbound, minCount int, isUDP bool, unwrap bool) []adapter.Outbound {
	var blockedNodes map[string]bool
	if s.store != nil {
		blockedNodes, _ = s.store.GetBlockedNodes(s.Tag(), smartConfigName)
	}

	proxyByName := make(map[string]adapter.Outbound, len(all))
	for _, ob := range all {
		proxyByName[ob.Tag()] = ob
	}

	var selected []adapter.Outbound
	for i, name := range names {
		ob := proxyByName[name]
		if ob == nil || blockedNodes[name] || !s.isAlive(name) || (isUDP && !s.supportsUDP(ob)) {
			continue
		}
		w := 0.0
		if weights != nil && i < len(weights) {
			w = weights[i]
		}
		if weights == nil || w >= smart.AllowedWeight {
			selected = append(selected, ob)
		}
	}

	if unwrap && len(selected) > 0 {
		return selected
	}

	if len(selected) >= minCount {
		return selected[:minCount]
	}

	// Build supplemental pool from nodes not already in named list
	inNamed := make(map[string]bool, len(names))
	for _, name := range names {
		inNamed[name] = true
	}

	filteredAll := make([]adapter.Outbound, 0, len(all))
	for _, ob := range all {
		if !inNamed[ob.Tag()] {
			filteredAll = append(filteredAll, ob)
		}
	}

	// Sort supplemental: policyPriority > ranking > random
	if len(s.policyPriority) > 0 {
		sort.Slice(filteredAll, func(i, j int) bool {
			fi := s.getPriorityFactor(filteredAll[i].Tag())
			fj := s.getPriorityFactor(filteredAll[j].Tag())
			if fi != fj {
				return fi > fj
			}
			return filteredAll[i].Tag() < filteredAll[j].Tag()
		})
	} else if s.store != nil {
		if ranking, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName); err == nil && len(ranking) > 0 {
			rankMap := make(map[string]float64, len(ranking))
			for _, r := range ranking {
				rankMap[r.Name] = r.Weight
			}
			sort.Slice(filteredAll, func(i, j int) bool {
				wi, oki := rankMap[filteredAll[i].Tag()]
				wj, okj := rankMap[filteredAll[j].Tag()]
				if oki && okj {
					if wi != wj {
						return wi > wj
					}
					return filteredAll[i].Tag() < filteredAll[j].Tag()
				}
				return oki
			})
		} else {
			rand.Shuffle(len(filteredAll), func(i, j int) {
				filteredAll[i], filteredAll[j] = filteredAll[j], filteredAll[i]
			})
		}
	} else {
		rand.Shuffle(len(filteredAll), func(i, j int) {
			filteredAll[i], filteredAll[j] = filteredAll[j], filteredAll[i]
		})
	}

	firstAppended := false
	for _, ob := range filteredAll {
		if blockedNodes[ob.Tag()] || !s.isAlive(ob.Tag()) || (isUDP && !s.supportsUDP(ob)) {
			continue
		}
		if !firstAppended && len(names) < minCount {
			selected = append([]adapter.Outbound{ob}, selected...)
			firstAppended = true
		} else {
			selected = append(selected, ob)
		}
		if len(selected) >= minCount {
			break
		}
	}

	if len(selected) == 0 {
		// Last resort: any alive outbound
		for _, ob := range all {
			if s.isAlive(ob.Tag()) {
				selected = append(selected, ob)
				if len(selected) >= minCount {
					break
				}
			}
		}
		if len(selected) == 0 {
			for _, ob := range all {
				selected = append(selected, ob)
				if len(selected) >= minCount {
					break
				}
			}
		}
	}

	return selected
}

// dialWithRetry runs up to maxRetries rounds with exponential jitter backoff.
func (s *Smart) dialWithRetry(ctx context.Context, network string, dest M.Socksaddr, outbounds []adapter.Outbound, meta *smartDialMeta) (net.Conn, string, int64, error) {
	var finalErr error

	for i := 0; i < smartMaxRetries; i++ {
		if i > 0 {
			base := time.Duration(math.Pow(2, float64(i-1))) * 50 * time.Millisecond
			jitter := 1.0 + (rand.Float64()*2-1)*0.2
			delay := time.Duration(float64(base) * jitter)
			s.logger.DebugContext(ctx, "smart[", s.Tag(), "] retry round ", i,
				" after ", delay, " backoff")
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, "", 0, ctx.Err()
			}
		}

		batch, timeout := s.getBatch(outbounds, meta, i)
		if len(batch) == 0 {
			break
		}

		s.logger.DebugContext(ctx, "smart[", s.Tag(), "] round ", i, " batch=",
			proxyTagsPreview(batch, 5), " timeout=", timeout)

		ctxDial, cancel := context.WithTimeout(ctx, timeout)
		conn, proxyTag, connectTime, err := s.parallelDial(ctxDial, network, dest, batch, meta)
		cancel()

		if err == nil {
			return conn, proxyTag, connectTime, nil
		}
		finalErr = err
	}

	return nil, "", 0, E.New("smart: all retries failed: ", finalErr)
}

// getBatch returns the batch for retry round i and the dial timeout.
func (s *Smart) getBatch(outbounds []adapter.Outbound, meta *smartDialMeta, round int) ([]adapter.Outbound, time.Duration) {
	var batch []adapter.Outbound
	if round == 0 {
		if len(outbounds) > 0 {
			batch = outbounds[:1]
		}
	} else {
		begin := (round-1)*smartParallelDials + 1
		if begin >= len(outbounds) {
			return nil, 0
		}
		end := begin + smartParallelDials
		if end > len(outbounds) {
			end = len(outbounds)
		}
		batch = outbounds[begin:end]
	}

	var maxHistCT int64
	for _, ob := range batch {
		if ct := s.getHistoryConnectTime(meta, ob.Tag()); ct > maxHistCT {
			maxHistCT = ct
		}
	}

	timeout := time.Duration(float64(maxHistCT)*smartConnThreshold) * time.Millisecond
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}

	return batch, timeout
}

// parallelDial races all outbounds in batch; first success wins. Losers get
// their failure recorded against the real meta so weight history updates.
func (s *Smart) parallelDial(ctx context.Context, network string, dest M.Socksaddr, outbounds []adapter.Outbound, meta *smartDialMeta) (net.Conn, string, int64, error) {
	if len(outbounds) == 1 {
		start := time.Now()
		conn, err := outbounds[0].DialContext(ctx, network, dest)
		ct := time.Since(start).Milliseconds()
		if err != nil {
			go s.recordFailedDial(outbounds[0].Tag(), meta, ct)
		}
		return conn, outbounds[0].Tag(), ct, err
	}

	type result struct {
		conn        net.Conn
		tag         string
		connectTime int64
		err         error
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(outbounds))
	for _, ob := range outbounds {
		ob := ob
		go func() {
			start := time.Now()
			conn, err := ob.DialContext(raceCtx, network, dest)
			ct := time.Since(start).Milliseconds()
			results <- result{conn, ob.Tag(), ct, err}
		}()
	}

	var errs []error
	for i := 0; i < len(outbounds); i++ {
		r := <-results
		if r.err == nil {
			cancel()
			return r.conn, r.tag, r.connectTime, nil
		}
		errs = append(errs, r.err)
		// Only record non-cancelled failures — losing race arms get cancelled
		// via raceCtx after the winner returns, and that's not a real failure.
		if r.err != context.Canceled && !errors.Is(r.err, context.Canceled) {
			s.markDead(r.tag)
			go s.recordFailedDial(r.tag, meta, r.connectTime)
		}
	}

	return nil, "", 0, E.Errors(errs...)
}

// recordFailedDial records a dial failure against the node + target in the
// stats store. Requires a valid meta.smartTarget; otherwise recordStats
// drops the event (keeps Store bucket clean of bare-target entries).
func (s *Smart) recordFailedDial(tag string, meta *smartDialMeta, connectTime int64) {
	if meta == nil {
		return
	}
	s.recordStats("failed", meta, tag, connectTime, 0, 0, 0, 0, 0, 0)
}

// ─── tracked connection wrappers ──────────────────────────────────────────────

// smartTrackedConn wraps a dialed connection to feed per-connection telemetry
// into recordStats on Close. Tracks (mihomo parity):
//   - first-read latency: wall-clock ms from dial-success until the first byte
//     is read. Approximates TLS handshake + upstream round-trip; a critical
//     signal separate from connectTime (TCP handshake only).
//   - first-read / first-write errors: used to classify the connection outcome
//     as "closed" (success) vs "failed". Without this every connection looked
//     like a success to the weight algorithm, neutering the failure counter.
//   - peak byte rate: sampled at 1-second granularity on each Read/Write call;
//     substitutes for mihomo's statistic.DefaultManager peak tracking.
type smartTrackedConn struct {
	net.Conn
	s           *Smart
	proxyTag    string
	meta        *smartDialMeta
	connectTime int64
	startTime   time.Time

	upload   atomic.Int64
	download atomic.Int64

	// first-byte tracking
	firstReadOnce  atomic.Bool
	firstReadMs    atomic.Int64   // latency in ms from dial-success
	firstReadErr   atomic.Pointer[error]
	firstWriteOnce atomic.Bool
	firstWriteErr  atomic.Pointer[error]

	// peak byte-rate tracking (sampled on each IO call)
	rateMu        sync.Mutex
	rateLastTime  time.Time
	rateLastUp    int64
	rateLastDown  int64
	maxUpBps      atomic.Int64
	maxDownBps    atomic.Int64

	closeOnce sync.Once
}

func (c *smartTrackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.download.Add(int64(n))
	}
	if c.firstReadOnce.CompareAndSwap(false, true) {
		c.firstReadMs.Store(time.Since(c.startTime).Milliseconds())
		if err != nil {
			e := err // copy to heap before pointer-atomic Store
			c.firstReadErr.Store(&e)
		}
	}
	c.sampleRate()
	return n, err
}

func (c *smartTrackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.upload.Add(int64(n))
	}
	if c.firstWriteOnce.CompareAndSwap(false, true) {
		if err != nil {
			e := err
			c.firstWriteErr.Store(&e)
		}
	}
	c.sampleRate()
	return n, err
}

// sampleRate updates maxUpBps / maxDownBps when at least 1 second has elapsed
// since the last sample. Cheap — a single mutex + Time.Since comparison per IO.
func (c *smartTrackedConn) sampleRate() {
	c.rateMu.Lock()
	now := time.Now()
	if c.rateLastTime.IsZero() {
		c.rateLastTime = c.startTime
	}
	dt := now.Sub(c.rateLastTime).Seconds()
	if dt < 1.0 {
		c.rateMu.Unlock()
		return
	}
	upNow := c.upload.Load()
	downNow := c.download.Load()
	upBps := int64(float64(upNow-c.rateLastUp) / dt)
	downBps := int64(float64(downNow-c.rateLastDown) / dt)
	c.rateLastTime = now
	c.rateLastUp = upNow
	c.rateLastDown = downNow
	c.rateMu.Unlock()

	if upBps > c.maxUpBps.Load() {
		c.maxUpBps.Store(upBps)
	}
	if downBps > c.maxDownBps.Load() {
		c.maxDownBps.Store(downBps)
	}
}

// classifyStatus returns ("closed", nil) for a clean completion or
// ("failed", <reason>) for an abnormal one. Mirrors mihomo's logic in
// registerClosureMetricsCallback — EOF with no write error is a clean
// server-initiated close; any other read error, or EOF-with-write-error,
// signals a broken node.
func (c *smartTrackedConn) classifyStatus() (string, error) {
	var rErr, wErr error
	if p := c.firstReadErr.Load(); p != nil {
		rErr = *p
	}
	if p := c.firstWriteErr.Load(); p != nil {
		wErr = *p
	}
	if rErr == nil {
		return "closed", nil
	}
	if errors.Is(rErr, io.EOF) {
		if wErr != nil && !errors.Is(wErr, io.EOF) {
			return "failed", wErr
		}
		return "closed", nil
	}
	return "failed", rErr
}

func (c *smartTrackedConn) Close() error {
	c.closeOnce.Do(func() {
		// Remove from per-target registry so a subsequent mass-close doesn't
		// try to close this already-closed connection.
		if c.meta != nil {
			c.s.deregisterTargetConn(c.meta.smartTarget, c)
		}

		durMS := time.Since(c.startTime).Milliseconds()
		up := c.upload.Load()
		down := c.download.Load()
		latency := c.firstReadMs.Load() // 0 if no reads ever happened

		// Peak rates (bytes/sec); avg-as-fallback when no 1s sample window fired
		maxUpBps := c.maxUpBps.Load()
		maxDownBps := c.maxDownBps.Load()
		durSec := float64(durMS) / 1000.0
		if maxUpBps == 0 && durSec > 0 && up > 0 {
			maxUpBps = int64(float64(up) / durSec)
		}
		if maxDownBps == 0 && durSec > 0 && down > 0 {
			maxDownBps = int64(float64(down) / durSec)
		}

		status, reason := c.classifyStatus()
		if status == "failed" && reason != nil {
			c.s.logger.Debug("smart[", c.s.Tag(), "] conn [", c.proxyTag,
				"] classified as failed: ", reason)
		}

		// SYNCHRONOUS short-life handling — fires BEFORE the async
		// recordStats goroutine below, and BEFORE Conn.Close returns to
		// the caller. This closes the timing window where the user's next
		// DialContext races ahead of the stats update and re-selects the
		// same bad node via stale unwrap cache.
		firstByteSeen := c.firstReadOnce.Load()
		if c.meta != nil && classifyShortLife(durMS, up, down, firstByteSeen) {
			if c.s.recordShortLife(c.meta.smartTarget, c.proxyTag) {
				// Threshold crossed — take decisive action now.
				c.s.markDead(c.proxyTag)
				if c.s.store != nil && c.meta.smartTarget != "" {
					c.s.store.DeleteUnwrapResult(c.s.Tag(), smartConfigName,
						c.meta.smartTarget, c.meta.asnCode, c.meta.isUDP)
				}
				c.s.logger.Info("smart[", c.s.Tag(), "] node [", c.proxyTag,
					"] marked dead after ", shortLifeThreshold,
					" short-life closes on target [", c.meta.smartTarget,
					"] within ", shortLifeWindow)
			} else if c.s.store != nil && c.meta.smartTarget != "" {
				// Even below threshold, drop the unwrap cache for this
				// target so the very next dial re-evaluates the candidate
				// list. Cheap operation, and it fixes the primary
				// "same target always picks same dead node" loop.
				c.s.store.DeleteUnwrapResult(c.s.Tag(), smartConfigName,
					c.meta.smartTarget, c.meta.asnCode, c.meta.isUDP)
			}
		}

		go c.s.recordStats(status, c.meta, c.proxyTag, c.connectTime,
			latency, up, down, maxUpBps, maxDownBps, durMS)
	})
	return c.Conn.Close()
}

func (c *smartTrackedConn) Upstream() any { return c.Conn }

type smartTrackedPacketConn struct {
	net.PacketConn
	s           *Smart
	proxyTag    string
	meta        *smartDialMeta
	connectTime int64
	startTime   time.Time

	upload   atomic.Int64
	download atomic.Int64

	firstReadOnce atomic.Bool
	firstReadMs   atomic.Int64

	rateMu       sync.Mutex
	rateLastTime time.Time
	rateLastUp   int64
	rateLastDown int64
	maxUpBps     atomic.Int64
	maxDownBps   atomic.Int64

	closeOnce sync.Once
}

func (c *smartTrackedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.download.Add(int64(n))
	}
	if c.firstReadOnce.CompareAndSwap(false, true) && err == nil {
		c.firstReadMs.Store(time.Since(c.startTime).Milliseconds())
	}
	c.samplePktRate()
	return n, addr, err
}

func (c *smartTrackedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.upload.Add(int64(n))
	}
	c.samplePktRate()
	return n, err
}

func (c *smartTrackedPacketConn) samplePktRate() {
	c.rateMu.Lock()
	now := time.Now()
	if c.rateLastTime.IsZero() {
		c.rateLastTime = c.startTime
	}
	dt := now.Sub(c.rateLastTime).Seconds()
	if dt < 1.0 {
		c.rateMu.Unlock()
		return
	}
	upNow := c.upload.Load()
	downNow := c.download.Load()
	upBps := int64(float64(upNow-c.rateLastUp) / dt)
	downBps := int64(float64(downNow-c.rateLastDown) / dt)
	c.rateLastTime = now
	c.rateLastUp = upNow
	c.rateLastDown = downNow
	c.rateMu.Unlock()

	if upBps > c.maxUpBps.Load() {
		c.maxUpBps.Store(upBps)
	}
	if downBps > c.maxDownBps.Load() {
		c.maxDownBps.Store(downBps)
	}
}

func (c *smartTrackedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		durMS := time.Since(c.startTime).Milliseconds()
		up := c.upload.Load()
		down := c.download.Load()
		latency := c.firstReadMs.Load()
		maxUpBps := c.maxUpBps.Load()
		maxDownBps := c.maxDownBps.Load()
		durSec := float64(durMS) / 1000.0
		if maxUpBps == 0 && durSec > 0 && up > 0 {
			maxUpBps = int64(float64(up) / durSec)
		}
		if maxDownBps == 0 && durSec > 0 && down > 0 {
			maxDownBps = int64(float64(down) / durSec)
		}
		go c.s.recordStats("closed", c.meta, c.proxyTag, c.connectTime,
			latency, up, down, maxUpBps, maxDownBps, durMS)
	})
	return c.PacketConn.Close()
}

func (s *Smart) wrapConn(conn net.Conn, tag string, meta *smartDialMeta, connectTime int64, isUDP bool) net.Conn {
	tracked := &smartTrackedConn{
		Conn:        conn,
		s:           s,
		proxyTag:    tag,
		meta:        meta,
		connectTime: connectTime,
		startTime:   time.Now(),
	}
	s.registerTargetConn(meta.smartTarget, tracked)
	if s.interruptExternalConnections {
		return s.interruptGroup.NewConn(tracked,
			interrupt.IsExternalConnectionFromContext(context.Background()),
			false)
	}
	return tracked
}

// registerTargetConn adds a tracked conn to the per-target registry used by
// closeTargetConnections for mihomo-style findSameConnection cleanup.
func (s *Smart) registerTargetConn(target string, c *smartTrackedConn) {
	if target == "" {
		return
	}
	s.targetConnsMu.Lock()
	defer s.targetConnsMu.Unlock()
	set := s.targetConns[target]
	if set == nil {
		set = make(map[*smartTrackedConn]struct{})
		s.targetConns[target] = set
	}
	set[c] = struct{}{}
}

// deregisterTargetConn removes a tracked conn from the registry at Close time.
func (s *Smart) deregisterTargetConn(target string, c *smartTrackedConn) {
	if target == "" {
		return
	}
	s.targetConnsMu.Lock()
	defer s.targetConnsMu.Unlock()
	if set := s.targetConns[target]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(s.targetConns, target)
		}
	}
}

// closeTargetConnections force-closes every in-flight connection whose
// selected node matches the given node tag and whose target matches. Called
// when a node was just degraded so active connections through it drop and
// the user's client re-establishes against the updated selection.
//
// We intentionally skip the triggering connection itself — the caller was
// already about to close it (the close path is what invoked recordStats).
func (s *Smart) closeTargetConnections(target, nodeTag string) {
	if target == "" {
		return
	}
	s.targetConnsMu.Lock()
	set := s.targetConns[target]
	victims := make([]*smartTrackedConn, 0, len(set))
	for c := range set {
		if c.proxyTag == nodeTag {
			victims = append(victims, c)
		}
	}
	s.targetConnsMu.Unlock()

	if len(victims) == 0 {
		return
	}
	s.logger.Debug("smart[", s.Tag(), "] target [", target, "] degraded via [",
		nodeTag, "]: closing ", len(victims), " active connection(s)")
	for _, c := range victims {
		_ = c.Conn.Close() // raw close; our Close() wrapper will de-register
	}
}

// onDialOutcome feeds dial success/failure into group-level counters.
// After 5 consecutive (within the last interval) failures, triggers an
// async prefetch re-run so the Smart store catches up without waiting
// for the 10-minute scheduled tick. Mirrors mihomo GroupBase.onDialFailed.
func (s *Smart) onDialOutcome(success bool) {
	if success {
		s.dialFailCount.Store(0)
		return
	}
	now := time.Now().Unix()
	last := s.dialFailAt.Swap(now)
	if now-last > 60 {
		// >1 minute since last failure — reset counter
		s.dialFailCount.Store(1)
		return
	}
	cnt := s.dialFailCount.Add(1)
	if cnt >= 5 && s.recheckOnce.CompareAndSwap(false, true) {
		go func() {
			defer s.recheckOnce.Store(false)
			s.logger.Info("smart[", s.Tag(), "] accumulated ", cnt,
				" dial failures in short window; triggering emergency prefetch refresh")
			s.runPrefetch()
		}()
	}
}

func (s *Smart) wrapPacketConn(pc net.PacketConn, tag string, meta *smartDialMeta, connectTime int64) net.PacketConn {
	return &smartTrackedPacketConn{
		PacketConn:  pc,
		s:           s,
		proxyTag:    tag,
		meta:        meta,
		connectTime: connectTime,
		startTime:   time.Now(),
	}
}

// ─── connection statistics ────────────────────────────────────────────────────

// smartSkipTypes is the set of outbound types that should never contribute to
// the weight store — dialing through them is not a "real" route measurement.
// Mihomo uses proxy.Type() against C.Compatible/C.Reject/C.Pass/C.RejectDrop;
// sing-box equivalents live in constant.Type*.
func smartSkipType(t string) bool {
	switch t {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS:
		return true
	}
	return false
}

func (s *Smart) recordStats(
	status string, meta *smartDialMeta, proxyTag string,
	connectTime, latency, uploadBytes, downloadBytes, maxUploadRate, maxDownloadRate, durationMS int64,
) {
	// Skip special types — prevents polluting the weight store with results
	// from direct / block / dns outbounds (mihomo parity).
	if ob, loaded := s.outboundMgr.Outbound(proxyTag); loaded && smartSkipType(ob.Type()) {
		return
	}

	// Feed dial outcome into group-level failure tracking (mihomo's
	// onDialFailed / onDialSuccess). Accumulated failures trigger an async
	// prefetch refresh so the group catches new breakage faster than the
	// scheduled 10-minute tick.
	if status == "failed" {
		s.onDialOutcome(false)
	} else {
		s.onDialOutcome(true)
	}

	if s.store == nil {
		return
	}

	target := meta.smartTarget
	if target == "" {
		return
	}

	uploadMB := float64(uploadBytes) / (1024.0 * 1024.0)
	downloadMB := float64(downloadBytes) / (1024.0 * 1024.0)
	maxUpKB := float64(maxUploadRate) / 1024.0
	maxDownKB := float64(maxDownloadRate) / 1024.0
	durationMin := float64(durationMS) / 60000.0

	weightType := smart.WeightTypeTCP
	if meta.asnCode != "" && !smart.CdnASNs[meta.asnCode] {
		if meta.isUDP {
			weightType = smart.WeightTypeUDPASN + ":" + meta.asnCode
		} else {
			weightType = smart.WeightTypeTCPASN + ":" + meta.asnCode
		}
	} else if meta.isUDP {
		weightType = smart.WeightTypeUDP
	}

	lock := smart.GetTargetNodeLock(target, s.Tag(), proxyTag)
	lock.Lock()
	defer lock.Unlock()

	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, smartConfigName, s.Tag(), target, proxyTag)
	record := s.store.GetOrCreateAtomicRecord(cacheKey, s.Tag(), smartConfigName, target, proxyTag)

	switch status {
	case "failed":
		record.AddInt64("failure", 1)
	case "closed":
		record.AddInt64("success", 1)
	}

	if connectTime > 0 {
		old := record.GetInt64("connectTime")
		record.SetInt64("connectTime", smart.UpdateAverageInt(old, connectTime))
	}
	if latency > 0 {
		old := record.GetInt64("latency")
		record.SetInt64("latency", smart.UpdateAverageInt(old, latency))
	}
	if durationMin > 0 {
		old := record.GetFloat64("duration")
		if old > 0 {
			record.SetFloat64("duration", (old+durationMin)/2.0)
		} else {
			record.SetFloat64("duration", durationMin)
		}
	}

	// CRITICAL: snapshot history BEFORE mutating totals. ModelInput semantics
	// (mihomo parity): UploadTotal / MaxuploadRate / DownloadTotal / MaxdownloadRate
	// refer to THIS connection; History* fields refer to accumulated values prior
	// to this connection. Swapping them breaks both CalculateWeight's scene
	// detection and LightGBM features 4-11.
	historyUploadTotal := record.GetFloat64("uploadTotal")
	historyDownloadTotal := record.GetFloat64("downloadTotal")
	historyMaxUploadRate := record.GetFloat64("maxUploadRate")
	historyMaxDownloadRate := record.GetFloat64("maxDownloadRate")

	record.AddUpload(uploadMB)
	record.AddDownload(downloadMB)

	if maxUpKB > historyMaxUploadRate {
		record.SetFloat64("maxUploadRate", maxUpKB)
	}
	if maxDownKB > historyMaxDownloadRate {
		record.SetFloat64("maxDownloadRate", maxDownKB)
	}

	oldWeight := record.GetWeight(weightType)
	priorityFactor := s.getPriorityFactor(proxyTag)

	input := &smart.ModelInput{
		Success:                record.GetInt64("success"),
		Failure:                record.GetInt64("failure"),
		ConnectTime:            record.GetInt64("connectTime"),
		Latency:                record.GetInt64("latency"),
		IsUDP:                  meta.isUDP,
		IsTCP:                  !meta.isUDP,
		UploadTotal:            uploadMB,               // this connection
		HistoryUploadTotal:     historyUploadTotal,     // accumulated before
		MaxuploadRate:          maxUpKB,                // this connection
		HistoryMaxUploadRate:   historyMaxUploadRate,   // accumulated before
		DownloadTotal:          downloadMB,
		HistoryDownloadTotal:   historyDownloadTotal,
		MaxdownloadRate:        maxDownKB,
		HistoryMaxDownloadRate: historyMaxDownloadRate,
		ConnectionDuration:     record.GetFloat64("duration"), // smoothed avg (post-update)
		LastUsed:               record.GetInt64("lastUsed"),
		DestIPASN:              meta.asnCode,
		Host:                   meta.host,
		DestIP:                 firstValidIPString(meta.resolvedIPs),
		DestPort:               meta.destPort,
		DestGeoIP:              meta.destGeoIP,
		GroupName:              s.Tag(),
		NodeName:               proxyTag,
	}

	// ML prediction path (LightGBM) with automatic fallback to traditional algorithm.
	var calculatedWeight float64
	var mlPredicted bool
	if s.useLightGBM && s.weightModel != nil && s.weightModel.IsLoaded() {
		calculatedWeight, mlPredicted = s.weightModel.PredictWeight(input, priorityFactor)
	} else {
		calculatedWeight, _ = smart.CalculateWeight(input, priorityFactor)
	}

	// Host-level failure tracking (mihomo parity): a wildcard target that has
	// failed many times should NOT further penalize the node — the problem is
	// the target, not the route. Threshold is configurable per group via
	// max_host_failed_times (default 10).
	hostFailCount, hostLastUsed := s.store.GetHostStatus(s.Tag(), smartConfigName, target)
	hostBlocked := hostFailCount >= s.maxHostFailedTimes

	finalWeight, isDegraded := s.checkNodeQualityDegradation(
		status, meta, proxyTag, calculatedWeight, oldWeight,
		durationMS, uploadMB, downloadMB, hostBlocked,
	)

	// Training-sample collection: record the NORMALISED post-degradation score
	// (finalWeight / priorityFactor) as the model target — mihomo parity.
	// Pre-priority / pre-degradation calculatedWeight was the training-target
	// value prior to this fix, which caused the model to learn priority-biased
	// scores rather than the raw algorithmic signal.
	if s.dataCollector != nil && (s.sampleRate >= 1 || rand.Float64() < s.sampleRate) {
		source := "traditional"
		if mlPredicted {
			source = "lightgbm"
		}
		baseWeight := finalWeight
		if priorityFactor > 0 {
			baseWeight = finalWeight / priorityFactor
		}
		cmeta := &lightgbm.CollectorMeta{
			DestASN:  meta.asnCode,
			Host:     meta.host,
			DestPort: meta.destPort,
		}
		for _, ip := range meta.resolvedIPs {
			if ip.IsValid() {
				cmeta.DestIP = ip.String()
				break
			}
		}
		go s.dataCollector.AddSample(input, cmeta, baseWeight, source)
	}

	if isDegraded {
		s.updatePrefetchCache(meta, target, proxyTag, finalWeight)
		// mihomo's findSameConnection equivalent: force-close in-flight
		// connections to the same target so the user's client re-issues
		// against the refreshed node selection.
		if s.store != nil {
			s.store.DeleteUnwrapResult(s.Tag(), smartConfigName, target, meta.asnCode, meta.isUDP)
		}
		s.closeTargetConnections(target, proxyTag)
	}

	// Update host failure/success counter. Only update lastUsed on zero-traffic
	// HTTPS 443 TCP — the "host might be blocked" heuristic from mihomo.
	needLastUsedUpdate := downloadMB < 0.03 && meta.host != "" && meta.destPort == 443 && !meta.isUDP
	s.store.UpdateHostStatus(s.Tag(), smartConfigName, target, isDegraded, needLastUsedUpdate)
	_ = hostLastUsed // reserved for future StatusTest-like logic

	record.SetInt64("lastUsed", time.Now().Unix())
	record.SetWeight(weightType, finalWeight, meta.isUDP)

	snapshot := record.CreateStatsSnapshot()
	if data, err := json.Marshal(snapshot); err == nil {
		go s.store.AppendToGlobalQueue(smart.StoreOperation{
			Type:   smart.OpSaveStats,
			Group:  s.Tag(),
			Config: smartConfigName,
			Target: target,
			Node:   proxyTag,
			Data:   data,
		})
	}

	// Verbose per-event log — includes enough context to reconstruct node
	// quality trajectory without querying the store. Debug level to avoid
	// noise on info by default.
	algo := "traditional"
	if mlPredicted {
		algo = "lightgbm"
	}
	degradedTag := ""
	if isDegraded {
		degradedTag = " DEGRADED"
	}
	blockedTag := ""
	if hostBlocked {
		blockedTag = " HOST_BLOCKED"
	}
	s.logger.Debug("smart[", s.Tag(), "] [", status, algo, degradedTag, blockedTag,
		"] node=[", proxyTag, "] target=[", target, "] asn=[", meta.asnCode,
		"] weight=", formatFloat(finalWeight, 4), " (was ", formatFloat(oldWeight, 4),
		") S/F=", input.Success, "/", input.Failure,
		" connect=", input.ConnectTime, "ms latency=", input.Latency,
		"ms up=", formatFloat(uploadMB, 3), "MB down=", formatFloat(downloadMB, 3),
		"MB dur=", durationMS, "ms prio=", formatFloat(priorityFactor, 2),
		" hostFails=", hostFailCount)
}

// formatFloat renders a float with fixed precision for log output.
func formatFloat(v float64, prec int) string {
	return strconv.FormatFloat(v, 'f', prec, 64)
}

func (s *Smart) checkNodeQualityDegradation(
	status string, meta *smartDialMeta, proxyTag string,
	newWeight, oldWeight float64,
	durationMS int64, uploadMB, downloadMB float64,
	hostBlocked bool,
) (float64, bool) {
	newWeight = smart.UpdateAverageFloat(oldWeight, newWeight, false)

	degradedWeight := smart.UpdateAverageFloat(oldWeight, newWeight*0.1, false)

	if status == "failed" {
		failedWeight, nodeBlock := s.handleFailedConnection(proxyTag, oldWeight, newWeight)
		// If the host is known-blocked, do NOT propagate node-level block —
		// the target is the cause, not the node.
		if nodeBlock && hostBlocked {
			return newWeight, false
		}
		return failedWeight, nodeBlock
	}

	// Zero-traffic HTTPS detection — strong signal of TLS handshake failure,
	// upstream reset, or transparent blackhole. But if the host itself is
	// blocked elsewhere, don't penalize the node.
	if durationMS > 100 && downloadMB == 0 && uploadMB == 0 && meta.destPort == 443 && !meta.isUDP {
		if hostBlocked {
			return newWeight, false
		}
		return degradedWeight, true
	}

	// Weight drop detection — >30% drop is a quality signal, but still
	// skip it when the host is the culprit.
	if oldWeight > 0 && newWeight > 0 {
		drop := (oldWeight - newWeight) / oldWeight
		if drop > 0.3 {
			if hostBlocked {
				return newWeight, false
			}
			return newWeight, true
		}
	}

	return newWeight, false
}

func (s *Smart) handleFailedConnection(proxyName string, oldWeight, calculatedWeight float64) (float64, bool) {
	if s.store == nil {
		return smart.UpdateAverageFloat(oldWeight, calculatedWeight, false), false
	}

	now := time.Now().Unix()
	stateData, _ := s.store.GetNodeStates(s.Tag(), smartConfigName)

	var state smart.NodeState
	if data, exists := stateData[proxyName]; exists {
		if json.Unmarshal(data, &state) != nil {
			state = smart.NodeState{Name: proxyName, FailureCount: 1, LastFailure: now, DegradedFactor: 1.0}
		} else {
			state.FailureCount++
			state.LastFailure = now
		}
	} else {
		state = smart.NodeState{Name: proxyName, FailureCount: 1, LastFailure: now, DegradedFactor: 1.0}
	}

	k := 0.01
	linearFactor := math.Max(0.1, 1.0-k*float64(state.FailureCount))
	state.DegradedFactor = linearFactor
	state.Degraded = true

	block := false
	if linearFactor <= 0.7 {
		block = true
		blockDur := time.Duration(30+state.FailureCount*2) * time.Minute
		additional := time.Duration(state.FailureCount/10) * time.Minute
		state.BlockedUntil = time.Now().Add(blockDur + additional).Unix()
	}

	if data, err := json.Marshal(&state); err == nil {
		s.store.AppendToGlobalQueue(smart.StoreOperation{
			Type:   smart.OpSaveNodeState,
			Group:  s.Tag(),
			Config: smartConfigName,
			Node:   proxyName,
			Data:   data,
		})
	}

	if block {
		smart.ClearBlockedNodesCache(s.Tag(), smartConfigName)
	}

	return smart.UpdateAverageFloat(oldWeight, calculatedWeight*state.DegradedFactor, false), block
}

func (s *Smart) updatePrefetchCache(meta *smartDialMeta, target, nodeName string, weight float64) {
	if s.store == nil {
		return
	}
	nodes, weights := s.store.GetPrefetchResult(s.Tag(), smartConfigName, target, meta.asnCode, meta.isUDP)

	type nw struct {
		node   string
		weight float64
	}
	list := make([]nw, 0, len(nodes)+1)
	found := false
	for i, n := range nodes {
		w := 0.0
		if i < len(weights) {
			w = weights[i]
		}
		if n == nodeName {
			list = append(list, nw{n, weight})
			found = true
		} else {
			list = append(list, nw{n, w})
		}
	}
	if !found {
		list = append(list, nw{nodeName, weight})
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].weight != list[j].weight {
			return list[i].weight > list[j].weight
		}
		return list[i].node < list[j].node
	})

	sortedNodes := make([]string, len(list))
	sortedWeights := make([]float64, len(list))
	for i, item := range list {
		sortedNodes[i] = item.node
		sortedWeights[i] = item.weight
	}
	s.store.StorePrefetchResult(s.Tag(), smartConfigName, target, meta.asnCode, meta.isUDP, sortedNodes, sortedWeights)
}

// ─── background tasks ─────────────────────────────────────────────────────────

// rankByDelay builds a NodeRank slice from URLTestHistoryStorage delays.
// Used as a cold-start fallback when the prefetch-based ranking has no
// data yet. Lower delay → higher weight; dead nodes (no history, or
// history with Delay==0) sink to the bottom.
//
// Weight is a 0..100 percentage, same scale as GetNodeWeightRanking's
// prefetch-score output, so consumers don't need to distinguish the two
// sources. Rank category (MostUsed / Occasional / RarelyUsed) follows
// mihomo's rules: top 20% = MostUsed, next 50% = Occasional, rest = RarelyUsed,
// with a floor of 1 node in each category when ≥3 alive exist.
func (s *Smart) rankByDelay(tags []string) []smart.NodeRank {
	if s.history == nil || len(tags) == 0 {
		return nil
	}

	type nodeDelay struct {
		tag   string
		delay uint16
		alive bool
	}
	nodes := make([]nodeDelay, 0, len(tags))
	for _, tag := range tags {
		h := s.history.LoadURLTestHistory(tag)
		if h != nil && h.Delay > 0 {
			nodes = append(nodes, nodeDelay{tag, h.Delay, true})
		} else {
			nodes = append(nodes, nodeDelay{tag, 0, false})
		}
	}

	// No probes have landed yet — can't rank anything, return empty rather
	// than persisting garbage that would overwrite a future real ranking.
	aliveCount := 0
	for _, n := range nodes {
		if n.alive {
			aliveCount++
		}
	}
	if aliveCount == 0 {
		return nil
	}

	// Sort: alive first, then ascending delay, tag asc as tie-breaker.
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].alive != nodes[j].alive {
			return nodes[i].alive
		}
		if nodes[i].delay != nodes[j].delay {
			return nodes[i].delay < nodes[j].delay
		}
		return nodes[i].tag < nodes[j].tag
	})

	// Find min/max delay among alive nodes for weight scaling.
	var minD, maxD uint16 = 65535, 0
	for _, n := range nodes {
		if !n.alive {
			continue
		}
		if n.delay < minD {
			minD = n.delay
		}
		if n.delay > maxD {
			maxD = n.delay
		}
	}

	// mihomo-style category boundaries (see GetNodeWeightRanking).
	mostBound := int(float64(aliveCount) * 0.2)
	if mostBound < 1 {
		mostBound = 1
	}
	occBound := mostBound + int(float64(aliveCount)*0.5)

	now := time.Now().Unix()
	result := make([]smart.NodeRank, 0, len(nodes))
	for i, n := range nodes {
		nr := smart.NodeRank{Name: n.tag, LastUpdated: now}
		if !n.alive {
			nr.Weight = 0
			nr.Rank = smart.RankRarelyUsed
			result = append(result, nr)
			continue
		}
		// Linear interpolation: best delay → 100, worst → 1.
		if maxD == minD {
			nr.Weight = 100
		} else {
			// Invert: smaller delay yields larger weight.
			frac := float64(maxD-n.delay) / float64(maxD-minD)
			nr.Weight = math.Round((1+frac*99)*100) / 100
		}
		switch {
		case i < mostBound:
			nr.Rank = smart.RankMostUsed
		case i < occBound:
			nr.Rank = smart.RankOccasional
		default:
			nr.Rank = smart.RankRarelyUsed
		}
		result = append(result, nr)
	}
	return result
}

// runHealthCheck actively probes every outbound with urltest.URLTest and
// writes the result into URLTestHistoryStorage. This is what populates the
// isAlive()/selectFullScan/ranking inputs. Without it, a standalone Smart
// group (no URLTest group covering the same nodes) has no idea which of
// its members are actually reachable.
//
// Concurrency is capped at smartHealthCheckConcurrency (8) to avoid
// stampeding the test URL host with hundreds of simultaneous probes when
// a large provider is loaded.
func (s *Smart) runHealthCheck() {
	if s.history == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return
	}

	const smartHealthCheckConcurrency = 8
	ctx, cancel := context.WithTimeout(s.taskCtx, s.interval)
	defer cancel()

	sem := make(chan struct{}, smartHealthCheckConcurrency)
	var wg sync.WaitGroup
	start := time.Now()

	var alive, dead atomic.Int32
	for _, ob := range snap.outbounds {
		ob := ob
		tag := ob.Tag()
		// Skip outbounds that aren't real routes
		if smartSkipType(ob.Type()) {
			continue
		}
		// If we already have a fresh history entry (≤ 1 interval), reuse it.
		if h := s.history.LoadURLTestHistory(tag); h != nil && time.Since(h.Time) < s.interval {
			if h.Delay > 0 {
				alive.Add(1)
			}
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
			delay, err := urltest.URLTest(probeCtx, s.testURL, ob)
			probeCancel()

			if err != nil || delay == 0 {
				// Record both the URLTest-null and our own known-dead set so
				// isAlive has a durable signal. Purely deleting history made
				// failed nodes look "untested → alive" to downstream callers.
				s.history.DeleteURLTestHistory(tag)
				s.markDead(tag)
				dead.Add(1)
				return
			}
			s.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: delay,
			})
			s.markAlive(tag)
			alive.Add(1)
		}()
	}
	wg.Wait()

	s.logger.Info("smart[", s.Tag(), "] health-check in ",
		time.Since(start).Round(time.Millisecond), ": ",
		alive.Load(), " alive, ", dead.Load(), " dead")
}

// cleanupOrphanedGroups removes Smart store data for group tags that no
// longer exist in the live outbound manager. Handles the case where a user
// renames / removes a Smart group between runs — without this the bbolt
// bucket grows unbounded.
func (s *Smart) cleanupOrphanedGroups() {
	if s.store == nil {
		return
	}
	cachedGroups, err := s.store.GetAllGroupsForConfig(smartConfigName)
	if err != nil {
		return
	}

	liveGroups := make(map[string]struct{})
	if s.outboundMgr != nil {
		for _, ob := range s.outboundMgr.Outbounds() {
			if _, isSmart := ob.(*Smart); isSmart {
				liveGroups[ob.Tag()] = struct{}{}
			}
		}
	}

	var orphaned []string
	for _, g := range cachedGroups {
		if _, ok := liveGroups[g]; !ok {
			orphaned = append(orphaned, g)
		}
	}
	if len(orphaned) == 0 {
		return
	}
	for _, g := range orphaned {
		if err := s.store.FlushByGroup(g, smartConfigName); err != nil {
			s.logger.Warn("smart: orphan-groups cleanup failed for [", g, "]: ", err)
			continue
		}
	}
	s.logger.Info("smart[", s.Tag(), "] cleaned ", len(orphaned),
		" orphaned group(s): ", proxyTagsPreviewStrings(orphaned, 5))
}

func (s *Smart) updateNodeRanking() {
	if s.store == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil {
		return
	}

	start := time.Now()
	tags := snap.tags
	ranking, err := s.store.GetNodeWeightRanking(s.Tag(), smartConfigName, s.testURL, s.isAlive, tags)
	if err != nil {
		s.logger.Debug("smart[", s.Tag(), "] ranking update failed: ", err)
		return
	}

	// Cold-start fallback — GetNodeWeightRanking derives scores purely from
	// prefetch history. Before the "prefetch" task has fired (5+ minutes
	// after start, or whenever the store is empty), maxScore==0 and we get
	// an empty ranking even when we DO have fresh URLTest delay data.
	//
	// Fall back to delay-based ranking in that case: lower delay = higher
	// weight, normalized to 0..100 with the same MostUsed / Occasional /
	// RarelyUsed categorisation mihomo uses. Saves the result to the store
	// so `GET /proxies/<tag>/weights` returns something meaningful even
	// during the first few minutes of operation.
	usingFallback := false
	if len(ranking) == 0 {
		ranking = s.rankByDelay(tags)
		if len(ranking) > 0 {
			usingFallback = true
			if s.store != nil {
				s.store.StoreNodeWeightRanking(s.Tag(), smartConfigName, ranking)
			}
		}
	}
	most, occ, rare := 0, 0, 0
	var topName string
	var topWeight float64
	for i, r := range ranking {
		switch r.Rank {
		case smart.RankMostUsed:
			most++
		case smart.RankOccasional:
			occ++
		case smart.RankRarelyUsed:
			rare++
		}
		if i == 0 {
			topName = r.Name
			topWeight = r.Weight
		}
	}
	source := "prefetch"
	if usingFallback {
		source = "delay-fallback"
	}
	s.logger.Info("smart[", s.Tag(), "] ranking updated in ", time.Since(start).Round(time.Millisecond),
		" via ", source, ": ", len(ranking), " nodes (most=", most, " occasional=", occ,
		" rarely=", rare, ") top=[", topName, "] weight=", formatFloat(topWeight, 2))
}

func (s *Smart) runPrefetch() {
	if s.store == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil {
		return
	}
	start := time.Now()
	proxyMap := make(map[string]string, len(snap.outbounds))
	alive, skipped := 0, 0
	for _, ob := range snap.outbounds {
		if s.isAlive(ob.Tag()) {
			proxyMap[ob.Tag()] = ob.Tag()
			alive++
		} else {
			skipped++
		}
	}
	count := s.store.RunPrefetch(s.Tag(), smartConfigName, proxyMap)
	s.logger.Info("smart[", s.Tag(), "] prefetch completed in ", time.Since(start).Round(time.Millisecond),
		": ", count, " targets pre-computed (alive=", alive, " skipped=", skipped, ")")
}

func (s *Smart) checkAndRecoverDegradedNodes() {
	if s.store == nil {
		return
	}
	stateData, err := s.store.GetNodeStates(s.Tag(), smartConfigName)
	if err != nil {
		return
	}

	var ops []smart.StoreOperation
	now := time.Now().Unix()
	unblocked, recovered, stillDegraded := 0, 0, 0

	for nodeName, data := range stateData {
		var state smart.NodeState
		if json.Unmarshal(data, &state) != nil {
			continue
		}

		updated := false
		if state.BlockedUntil > 0 && state.BlockedUntil <= now {
			state.BlockedUntil = 0
			updated = true
			unblocked++
			s.logger.Info("smart[", s.Tag(), "] unblocked node [", nodeName,
				"] (cooldown ended)")
		}

		if state.Degraded && state.BlockedUntil == 0 {
			recoveryFactor := math.Min(1.0, state.DegradedFactor+0.01)
			state.FailureCount = int(float64(state.FailureCount) * 0.95)
			if recoveryFactor >= 0.99 {
				state.Degraded = false
				state.DegradedFactor = 1.0
				recovered++
				s.logger.Info("smart[", s.Tag(), "] node [", nodeName, "] fully recovered")
			} else {
				state.DegradedFactor = recoveryFactor
				stillDegraded++
			}
			updated = true
		}

		if updated {
			if stateBytes, err := json.Marshal(&state); err == nil {
				ops = append(ops, smart.StoreOperation{
					Type:   smart.OpSaveNodeState,
					Group:  s.Tag(),
					Config: smartConfigName,
					Node:   nodeName,
					Data:   stateBytes,
				})
			}
		}
	}

	if len(ops) > 0 {
		s.store.AppendToGlobalQueue(ops...)
		s.logger.Debug("smart[", s.Tag(), "] recovery check: unblocked=", unblocked,
			" recovered=", recovered, " still_degraded=", stillDegraded)
	}
}

func (s *Smart) cleanupOldRecords() {
	if s.store != nil {
		start := time.Now()
		_ = s.store.CleanupOldRecords(s.Tag(), smartConfigName)
		s.logger.Debug("smart[", s.Tag(), "] old-records cleanup in ",
			time.Since(start).Round(time.Millisecond))
	}
}

func (s *Smart) cleanupOrphanedNodeCache() {
	if s.store == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil {
		return
	}

	currentNodes := make(map[string]bool, len(snap.tags))
	for _, tag := range snap.tags {
		currentNodes[tag] = true
	}

	cachedNodes, err := s.store.GetAllNodesForGroup(s.Tag(), smartConfigName)
	if err != nil {
		return
	}

	var orphaned []string
	for _, node := range cachedNodes {
		if !currentNodes[node] {
			orphaned = append(orphaned, node)
		}
	}

	if len(orphaned) > 0 {
		s.logger.Info("smart[", s.Tag(), "] cleaning ", len(orphaned),
			" orphaned node record(s): ", proxyTagsPreviewStrings(orphaned, 5))
		if err := s.store.RemoveNodesData(s.Tag(), smartConfigName, orphaned); err != nil {
			s.logger.Warn("smart[", s.Tag(), "] failed to clean orphaned nodes: ", err)
		}
	}
}

// proxyTagsPreviewStrings is a variant of proxyTagsPreview that takes raw tag strings.
func proxyTagsPreviewStrings(tags []string, limit int) string {
	if len(tags) == 0 {
		return "[]"
	}
	n := len(tags)
	if n > limit {
		n = limit
	}
	out := "[" + strings.Join(tags[:n], ",")
	if len(tags) > limit {
		out += ",...+" + strconv.Itoa(len(tags)-limit) + "]"
	} else {
		out += "]"
	}
	return out
}

func (s *Smart) flushQueue() {
	if s.store != nil {
		s.store.FlushQueue(true)
	}
}

func (s *Smart) adjustCache() {
	if s.store != nil {
		s.store.AdjustCacheParameters()
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// knownDeadTTL is the window during which a recently-failed node stays
// in knownDead. After this elapses, isAlive starts trusting URLTestHistory
// again — giving the node another chance in case the test URL was briefly
// unreachable rather than the node itself being broken.
const knownDeadTTL = 3 * time.Minute

// isAlive returns false iff we have evidence the node is unreachable.
// Evidence comes from two sources:
//  1. knownDead — populated by runHealthCheck on probe failure; authoritative
//     within knownDeadTTL of the last failure.
//  2. URLTestHistoryStorage — populated by our probe OR by a co-located URLTest
//     group. An entry with Delay=0 is also treated as dead.
//
// When neither source has data (fresh boot), assume alive so the group can
// bootstrap.
func (s *Smart) isAlive(tag string) bool {
	// Source 1: known-dead set
	s.knownDeadMu.RLock()
	deadAt, isDead := s.knownDead[tag]
	s.knownDeadMu.RUnlock()
	if isDead {
		if time.Since(deadAt) < knownDeadTTL {
			return false
		}
		// TTL expired — fall through to source 2
	}

	if s.history == nil {
		return true
	}
	h := s.history.LoadURLTestHistory(tag)
	if h == nil {
		return true // no data = assume alive (bootstrap)
	}
	// A Delay of 0 indicates a tested-and-failed entry (URLTest group
	// occasionally writes these). Treat as dead.
	if h.Delay == 0 {
		return false
	}
	return time.Since(h.Time) < s.interval*3
}

// markDead records a probe / dial failure for tag.
func (s *Smart) markDead(tag string) {
	if tag == "" {
		return
	}
	s.knownDeadMu.Lock()
	if s.knownDead == nil {
		s.knownDead = make(map[string]time.Time)
	}
	s.knownDead[tag] = time.Now()
	s.knownDeadMu.Unlock()
}

// markAlive clears tag from knownDead. Called on successful probe or dial.
func (s *Smart) markAlive(tag string) {
	if tag == "" {
		return
	}
	s.knownDeadMu.Lock()
	delete(s.knownDead, tag)
	s.knownDeadMu.Unlock()
	// A successful dial also clears any short-life history for this node
	// so a previously-problematic node that's recovered doesn't keep
	// counting toward a future threshold.
	s.shortLifeMu.Lock()
	for k := range s.shortLife {
		if strings.HasSuffix(k, "|"+tag) {
			delete(s.shortLife, k)
		}
	}
	s.shortLifeMu.Unlock()
}

// Short-life connection parameters — tuned so 3 consecutive "user gave up
// quickly" closes within a minute mark a node dead for half a minute.
const (
	shortLifeDurationLimit = 2 * time.Second // below this = gave up
	shortLifeBytesLimit    = int64(4096)     // below this = effectively no data
	shortLifeThreshold     = 3               // events before banning the node
	shortLifeWindow        = 60 * time.Second
)

// recordShortLife registers one short-life close for (target, node).
// Returns true when the threshold has just been crossed so the caller
// can escalate (mark the node dead + drop unwrap cache).
//
// Called SYNCHRONOUSLY from Close so the state updates before the user's
// next DialContext races ahead of the async recordStats goroutine — that
// timing gap was the primary cause of "user keeps disconnecting and
// Smart keeps picking the same dead node".
func (s *Smart) recordShortLife(target, node string) (crossed bool) {
	if target == "" || node == "" {
		return false
	}
	key := target + "|" + node
	now := time.Now()
	cutoff := now.Add(-shortLifeWindow)

	s.shortLifeMu.Lock()
	defer s.shortLifeMu.Unlock()

	// Compact existing slice: drop entries outside the 60s window
	old := s.shortLife[key]
	kept := old[:0]
	for _, t := range old {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	s.shortLife[key] = kept

	if len(kept) >= shortLifeThreshold {
		// Clear so a single spike doesn't ban the node twice in a row;
		// next short-life cycle starts fresh.
		delete(s.shortLife, key)
		return true
	}
	return false
}

// classifyShortLife returns true when a close event has "user gave up on
// this node" signature. Mihomo-inspired but with broader coverage — the
// previous strict (duration<2s AND bytes<4KB) missed the common case of
// a 10-second wait on a page that never loaded (duration long, bytes low).
//
// Any ONE of these patterns qualifies:
//
//  1. Very quick + barely any bytes — classic dropped-handshake abort.
//     (duration < 2s AND total bytes < 4 KB)
//
//  2. No first-byte ever — we wrote to the node but the server never sent
//     anything back. Strong "node is eating bytes" signal regardless of
//     how long the user waited before giving up.
//     (firstByteSeen == false AND duration > 500ms)
//
//  3. Long-but-empty — connection stayed alive for seconds but saw almost
//     no downstream data. User watched the spinner and gave up.
//     (download < 1 KB AND duration > 2s)
//
// Pattern 2 requires knowing whether we saw a first byte; caller passes
// firstByteSeen flag from smartTrackedConn.firstReadOnce / firstReadMs.
func classifyShortLife(durationMS int64, upBytes, downBytes int64, firstByteSeen bool) bool {
	// Rule 1: classic short-abort
	if durationMS < int64(shortLifeDurationLimit/time.Millisecond) &&
		upBytes+downBytes < shortLifeBytesLimit {
		return true
	}
	// Rule 2: no response ever from server
	if !firstByteSeen && durationMS > 500 {
		return true
	}
	// Rule 3: long connection but effectively no downstream payload
	if downBytes < 1024 && durationMS > int64(shortLifeDurationLimit/time.Millisecond) {
		return true
	}
	return false
}

func (s *Smart) supportsUDP(ob adapter.Outbound) bool {
	for _, n := range ob.Network() {
		if n == N.NetworkUDP {
			return true
		}
	}
	return false
}

func (s *Smart) getPriorityFactor(tag string) float64 {
	for _, rule := range s.policyPriority {
		if rule.isRegex && rule.regex != nil {
			if rule.regex.MatchString(tag) {
				return rule.factor
			}
		} else if strings.Contains(tag, rule.pattern) {
			return rule.factor
		}
	}
	return 1.0
}

func (s *Smart) getHistoryConnectTime(meta *smartDialMeta, proxyTag string) int64 {
	if s.store == nil || meta.smartTarget == "" {
		return 0
	}
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, smartConfigName, s.Tag(), meta.smartTarget, proxyTag)
	record := s.store.GetOrCreateAtomicRecord(cacheKey, s.Tag(), smartConfigName, meta.smartTarget, proxyTag)
	return record.GetInt64("connectTime")
}

func (s *Smart) lookupASN(ips []netip.Addr) string {
	if !s.useASN || s.asnDB == nil {
		return ""
	}
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() {
			continue
		}
		var record struct {
			AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
		}
		if err := s.asnDB.Lookup(ip.AsSlice(), &record); err == nil && record.AutonomousSystemNumber != 0 {
			return strconv.FormatUint(uint64(record.AutonomousSystemNumber), 10)
		}
	}
	return ""
}

// lookupCountry returns a single-element ISO country code slice from the GeoX
// country mmdb for the first valid non-private destination IP, or nil.
// Format matches mihomo's ModelInput.DestGeoIP ([]string); LightGBM
// extractGeoIPFeature + FNV hash bucket consume it.
//
// Lazy-retry: if countryDB is nil, attempt to re-open via the GeoX service
// at most once per 60s. This handles the common case where Smart started
// before GeoX finished downloading country.mmdb.
func (s *Smart) lookupCountry(ips []netip.Addr) []string {
	if s.countryDB == nil {
		s.maybeOpenCountryDB()
		if s.countryDB == nil {
			return nil
		}
	}
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() {
			continue
		}
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := s.countryDB.Lookup(ip.AsSlice(), &record); err == nil && record.Country.ISOCode != "" {
			return []string{record.Country.ISOCode}
		}
	}
	return nil
}

// maybeOpenCountryDB attempts to open the GeoX country mmdb if we don't
// already have a reader. Rate-limited to once per 60 seconds to avoid
// hammering Stat() on a path that doesn't exist yet.
func (s *Smart) maybeOpenCountryDB() {
	if s.countryDB != nil {
		return
	}
	now := time.Now().Unix()
	last := s.countryDBRetryAt.Load()
	if now-last < 60 {
		return
	}
	if !s.countryDBRetryAt.CompareAndSwap(last, now) {
		return // another goroutine raced us
	}

	geoSvc := service.FromContext[adapter.GeoXService](s.ctx)
	if geoSvc == nil {
		return
	}
	mmdbPath := geoSvc.MMDBPath()
	if mmdbPath == "" {
		return
	}
	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return // file still not present; try again next time
	}
	s.countryDB = db
	s.logger.Info("smart[", s.Tag(), "] country mmdb lazily opened from ",
		mmdbPath, " (feeds DestGeoIP feature)")
}

func (s *Smart) onProviderUpdated(tag string) error {
	if _, loaded := s.providers[tag]; !loaded {
		return E.New("outbound provider not found: ", tag)
	}

	deps := s.Dependencies()
	var (
		tags      []string
		outbounds []adapter.Outbound
	)
	for _, dep := range deps {
		detour, _ := s.outboundMgr.Outbound(dep)
		tags = append(tags, dep)
		outbounds = append(outbounds, detour)
	}

	s.outboundsCacheMu.Lock()
	for _, providerTag := range s.providerTags {
		if providerTag != tag && s.outboundsCache[providerTag] != nil {
			for _, detour := range s.outboundsCache[providerTag] {
				tags = append(tags, detour.Tag())
				outbounds = append(outbounds, detour)
			}
			continue
		}
		provider := s.providers[providerTag]
		var cache []adapter.Outbound
		for _, detour := range provider.Outbounds() {
			t := detour.Tag()
			if s.exclude != nil && s.exclude.MatchString(t) {
				continue
			}
			if s.include != nil && !s.include.MatchString(t) {
				continue
			}
			tags = append(tags, t)
			cache = append(cache, detour)
		}
		outbounds = append(outbounds, cache...)
		s.outboundsCache[providerTag] = cache
	}
	s.outboundsCacheMu.Unlock()

	if len(tags) == 0 {
		detour, _ := s.outboundMgr.Outbound("Compatible")
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}

	s.state.Store(&smartGroupState{outbounds: outbounds, tags: tags})
	return nil
}

// outboundNames extracts tag strings from outbound slice.
func outboundNames(outbounds []adapter.Outbound) []string {
	names := make([]string, len(outbounds))
	for i, ob := range outbounds {
		names[i] = ob.Tag()
	}
	return names
}

// CloseHandlerFunc N.CloseHandlerFunc alias used in NewConnectionEx / NewPacketConnectionEx
type CloseHandlerFunc = N.CloseHandlerFunc
