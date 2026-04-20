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
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
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
	smartMaxRetries    = 4
	smartMaxSelected   = 10
	smartParallelDials = 3
	smartConnThreshold = 2.0
	smartConfigName    = "singbox"

	// Failover tuning — optimised for "react in <100ms when top node breaks".
	//
	// smartRound0Parallel: races the TOP-N candidates in round 0 instead of
	// the previous solo-dial-then-fallback pattern. With N=2 we get failover
	// speed close to URLTest's parallel race while preserving the selector's
	// notion of "primary" candidate (whoever ranked higher loses the tie-
	// break so stickiness isn't compromised).
	smartRound0Parallel = 2

	// smartFastFailThreshold: a dial that fails in less than this is a
	// "fast fail" (connection refused / host unreachable / TCP RST) and
	// the retry loop skips exponential backoff — the network is working,
	// only this node is broken, so we should try the next immediately.
	smartFastFailThreshold = 200 * time.Millisecond

	// smartBaseBackoff: cut from 50ms → 20ms. Combined with fast-fail
	// bypass this is only applied after a genuine TIMEOUT (the whole round
	// hit its deadline), which is rare.
	smartBaseBackoff = 20 * time.Millisecond

	// Circuit breaker parameters. When a node accumulates
	// cbMaxConsecFail failures within cbWindow, the breaker opens for
	// cbOpenDuration — during that window the node is excluded from
	// candidate lists entirely. Mihomo-style "instant demotion" signal.
	cbMaxConsecFail = 2
	cbWindow        = 30 * time.Second
	cbOpenDuration  = 15 * time.Second

	// manualPinWeightBoost is the confidence multiplier applied to the
	// user's manually-pinned node during recordStats. 1.15 = 15% uplift.
	//
	// Rationale: when the user pins a node, that pin itself is a strong
	// preference signal — the user has decided this route is worth
	// keeping even if the algorithm would pick another. We persist that
	// intent into the weight store so that:
	//
	//  1. If the user unpins later, auto-selection still remembers the
	//     preference and biases toward the formerly-pinned node.
	//  2. The priority factor (policy_priority config rules) composes
	//     multiplicatively with the boost, matching how other weight
	//     signals combine.
	//
	// The boost is applied BEFORE CalculateWeight / PredictWeight via
	// the priority factor, so both traditional and LightGBM paths see
	// it. The training target (baseWeight = finalWeight/priorityFactor)
	// divides the boost back out — we want LightGBM to learn the raw
	// algorithmic signal, not a user-preference-inflated version, and
	// keeping the boost out of training prevents a feedback loop where
	// the model overfits to manually-pinned nodes across retrainings.
	//
	// Value picked empirically: 1.15 is large enough to survive a few
	// bad samples from a marginal pinned node (~one rank tier) without
	// making a genuinely broken node ride the pin indefinitely (two
	// consecutive failures still trip degradation / circuit breaker).
	manualPinWeightBoost = 1.15
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

// priorityMatchKind enumerates the four ways a single rule can match a
// node tag. The kind is fixed at parse time from the rule's prefix; at
// match time we just dispatch on the kind without re-inspecting the
// pattern.
type priorityMatchKind uint8

const (
	priorityMatchSubstring priorityMatchKind = iota // default (no prefix)
	priorityMatchExact                              // "=tag"
	priorityMatchRegex                              // "~regex"
	priorityMatchGlob                               // "*globpat*" (translated to regex)
)

// priorityRule is one parsed entry from option.SmartOutboundOptions.PolicyPriority.
//
// Compared to the previous design (silently autopilot regex when the
// pattern compiled as one), each rule now carries an EXPLICIT match
// kind decided by the prefix the user wrote. This makes config
// behaviour deterministic — `HK*` is no longer ambiguously treated as
// a regex matching empty string.
//
// Negate flips the match outcome: a `!` prefix means "factor applies
// to every node EXCEPT those matching this pattern".
//
// Multiple rules can match the same tag; getPriorityFactor multiplies
// every matching rule's factor instead of stopping at the first hit
// (mihomo parity for compositional config like "HK:1.5;VIP:1.2"). 1.0
// is the identity factor — rules that resolve to 1.0 are dropped at
// parse time so the hot path doesn't iterate them.
type priorityRule struct {
	raw     string         // original user text (without prefix) — for logging
	pattern string         // canonical pattern body (substring or regex source)
	regex   *regexp.Regexp // populated for regex / glob kinds
	factor  float64
	kind    priorityMatchKind
	negate  bool
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
	// priorityFactorCache memoises getPriorityFactor(tag) so the dial
	// hot path doesn't re-walk the rule slice for every selection. The
	// node tag set is effectively static — cache size grows to ≤
	// |snap.tags|. Lazily allocated by parsePolicyPriority when at
	// least one rule survives parsing.
	priorityFactorCache *xsync.MapOf[string, float64]
	useASN             bool
	asnDBPaths         []string            // per-group configured paths; empty → fall back to geox service
	asnDBs             []*maxminddb.Reader // multi-source: tried in order until one returns a hit
	countryDB          *maxminddb.Reader   // country.mmdb from GeoX, optional
	maxHostFailedTimes int                 // mihomo parity; 0 = default 10

	store *smart.Store

	// Active connections registry keyed by target. Used by markTargetDegraded
	// to proactively close in-flight connections to a target after a node was
	// degraded so the user's client re-issues and Smart re-selects.
	// Mirrors mihomo's findSameConnection behaviour.
	targetConnsMu sync.Mutex
	targetConns   map[string]map[*smartTrackedConn]struct{}

	// targetConnsCount mirrors len(flattened targetConns) as a lock-free
	// atomic counter. Maintained in lock-step with register/deregister so
	// the stalled-conn watchdog can bail in O(1) without acquiring
	// targetConnsMu when the group has zero active conns — avoids 24
	// mutex acquires/min per idle Smart group on battery-sensitive
	// Android builds (15 groups * 24/min = 360 waste acquires/min).
	targetConnsCount atomic.Int32

	// netChange holds debounce/scheduling state for the
	// InterfaceUpdateListener hook — see smart_netchange.go. Zero-value
	// is safe to use; declared inline (not a pointer) so it doesn't
	// need explicit initialisation in NewSmart.
	netChange netChangeState

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
	//
	// Backed by xsync.MapOf — read every dial (hottest lookup in the
	// group) and written from the health-check goroutine. xsync gives us
	// zero-alloc lock-free reads; the prior sync.RWMutex+map allocated
	// on every write and took a full mutex on every read.
	knownDead *xsync.MapOf[string, time.Time]

	// targetDebargo soft-breaks a specific node for a specific target when it fails
	// via WatchDog or Mid-Stream RST (like an IP filter). This stops the engine from
	// continually repicking it from the generic URLTest fallback ranking.
	// Key format: "target|proxyTag". Expiry bounded like knownDead.
	targetDebargo *xsync.MapOf[string, time.Time]

	// Per-node circuit breaker. Tracks consecutive-failure count and the
	// "breaker open until" timestamp. When the breaker is open, the node
	// is filtered out of selectProxiesTraced candidate lists even if
	// URLTest history says it's alive — a dial failure is a fresher
	// signal than a 10-second-old HTTP probe.
	//
	// Reset on successful dial (onDialOutcome(true)). xsync.MapOf gives
	// us lock-free reads on the dial hot path.
	breakers *xsync.MapOf[string, *circuitBreakerState]

	// aliveAt stores the unix-nano timestamp of the most recent successful
	// DIAL for each node. Used by runHealthCheck to skip probing nodes
	// that just proved alive via real user traffic — no point spending an
	// HTTP probe on a node that handled a real dial 5 seconds ago.
	//
	// This is intentionally SEPARATE from URLTestHistory: the history
	// feeds the dashboard latency display, and writing synthetic sentinels
	// (Delay=1) into it would make every dialed node show "1ms" which is
	// misleading. aliveAt is the Smart-internal signal; URLTestHistory
	// stays populated ONLY by real timed probes.
	aliveAt *xsync.MapOf[string, int64]

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

	// resetEvents tracks upstream TCP RST / broken-pipe / forcibly-
	// closed events per (target, node) pair. Distinct from shortLife
	// (which captures user-side abandonment) because a server-initiated
	// reset is a much stronger "this node is broken" signal: the user
	// wasn't going anywhere, the proxy node is silently dropping or
	// being filtered. Threshold (2 events / 60 s) is intentionally
	// lower than shortLife so we cut over faster.
	resetEvents *resetEventTracker

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

	// groupOrdinal is this group's process-unique sequence number assigned
	// at construction time. Used to stagger background task firings across
	// groups so a multi-group config doesn't have every group fire its
	// first health-check on the same tick.
	groupOrdinal int64

	taskCtx    context.Context
	taskCancel context.CancelFunc
	taskWg     sync.WaitGroup

	// scheduledTasks holds handles to every task this group registered on
	// the shared timing wheel so Close() can cancel them (the wheel is
	// process-wide; individual groups must explicitly unregister).
	scheduledTasks []*scheduledTask

	started atomic.Bool

	// coldStartLogged guards the once-per-process "no ranking data yet" log
	// so we don't re-spam it every tick while the pipeline warms up.
	coldStartLogged atomic.Bool

	// pinBypassLogged gates the "pinned node unhealthy, bypassing"
	// warning to once-per-outage. Flipped false the moment the pin
	// recovers so the NEXT unhealthy window gets its own log line —
	// otherwise operators can't tell a continuous outage apart from
	// a flapping pin.
	pinBypassLogged atomic.Bool

	// Most recently selected (successfully dialed) node tag. Surfaced via
	// Now() for ClashAPI / UI display. Updated on every successful dial
	// from both DialContext and ListenPacket paths.
	lastSelectedTag atomic.Value // string

	// lastDialAt is the unix-nano timestamp of the most recent successful
	// dial through this group. Used by the idle-aware task scheduler to
	// STOP running health-check / prefetch / ranking when the group has
	// seen no traffic for `idleThreshold` — critical for Android battery
	// life when the phone is in the user's pocket.
	lastDialAt atomic.Int64

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

	// Dashboard hints surfaced through Clash API (mihomo parity). Set
	// from option.GroupCommonOption at construction; read-only afterwards.
	hidden bool
	icon   string

	// rankingSnapshot is the in-process cache of the most recent
	// successful ranking computation. WeightRanking reads it first so
	// the API surface returns real numbers IMMEDIATELY after
	// updateNodeRanking finishes — no waiting on the bbolt batch
	// flusher (5 s task interval) or the 50-op BatchSaveThreshold.
	//
	// Persisted bbolt cache (StoreNodeWeightRanking) is still written
	// in parallel for cross-restart durability, but it is no longer the
	// only path between "computed" and "visible". This eliminates the
	// 5–60 s window after every ranking refresh during which
	// WeightRanking() would silently fall back to GetLiveNodeRanking
	// or delayBasedRanking even though prefetch-derived data was ready.
	//
	// atomic.Pointer keeps the reader path fully lock-free; writers
	// publish a fresh snapshot via Store. nil means "no ranking
	// computed yet this process lifetime" — fall through to the
	// existing live/delay paths in that case.
	rankingSnapshot atomic.Pointer[smartRankingSnapshot]

	// rankingKickOnce gates the post-first-dial kick of updateNodeRanking.
	// The 45 s scheduled initial delay made every fresh process
	// look "fallback-only" until the first nodes-ranking task fired,
	// regardless of how quickly real dial data accumulated. After the
	// first successful dial we kick the ranking task immediately so
	// /weights returns prefetch-derived data within seconds.
	rankingKickOnce sync.Once

	// algorithm is the post-tier reordering strategy. atomic.Pointer
	// allows ClashAPI to swap it at runtime via SetAlgorithm without
	// holding any lock on the Smart struct. nil → smartAlgoStrictBest
	// (handled by currentAlgorithm()).
	algorithm atomic.Pointer[string]

	// configAlgorithm 保存用户在配置文件中填写的原始算法字符串。
	// 用于 PostStart 阶段重新应用——确保即使 NewSmart 阶段的
	// atomic.Store 因某种生命周期原因未持久生效，PostStart 也能
	// 将正确的值写入 algorithm atomic.Pointer。
	configAlgorithm string

	// nodeLoad tracks active dial counts per proxy tag. Powers the
	// least-loaded algorithm; updated on register/deregister of every
	// smartTrackedConn so the read path is one xsync load per node.
	nodeLoad *nodeLoadCounter

	// nodeHTTP3Fallbacks counts HTTP/3 → HTTP/2 fallback events per node tag,
	// surfaced into ModelInput.HTTP3FallbackCount for v2 strategies and the
	// retraining CSV. Updated externally via RecordHTTP3Fallback (xiaobaf14g
	// v2.1 work item: wire from sing-quic's "HTTP/3 broken authority"
	// detection per the upstream "Scope HTTP/2 fallback per authority"
	// commit). Counter never decrements — it is a lifetime indicator of
	// QUIC instability for that node, which is what the model wants to
	// learn from. Lazily allocated to avoid the xsync.MapOf cost on groups
	// that never see QUIC traffic.
	nodeHTTP3Fallbacks atomic.Pointer[xsync.MapOf[string, *atomic.Int32]]

	// stickyByTarget remembers the last successfully-dialled node for
	// each target so the sticky-session algorithm can prefer it on the
	// next request to the same target. Lazily allocated when algorithm
	// == sticky-session — other algorithms pay no overhead. The
	// structured key avoids per-call string concatenation that
	// previously dominated the dial hot path under load.
	stickyByTarget *xsync.MapOf[stickyKey, string]

	// rrCounter / wrrCounter back the round-robin and weighted-round-
	// robin algorithms. Lazily allocated only when their algorithm is
	// selected; idle Smart groups never pay for unused counters.
	rrCounter  *roundRobinCounter
	wrrCounter *roundRobinCounter

	// hysteresisWindow + hysteresisMemo implement the cross-cutting
	// anti-flap layer. When window is 0 the layer is a no-op; the
	// memo map is allocated lazily so the disabled path costs nothing.
	hysteresisWindow time.Duration
	hysteresisMemo   *xsync.MapOf[stickyKey, hysteresisEntry]

	// pinEndorsements is the Smart-instance-level store tracking manual
	// pins to apply decayed multiplicative boosts.
	pinEndorsements     *xsync.MapOf[string, *pinEndorsementEntry]
	pinEndorsementsOnce sync.Once
}

// smartRankingSnapshot bundles the ranking slice with its computation
// timestamp so WeightRanking can both serve the cached result and
// expire it (>30 min stale → recompute on next refresh).
type smartRankingSnapshot struct {
	ranking    []smart.NodeRank
	computedAt time.Time
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
		hidden:             options.Hidden,
		icon:               options.Icon,
		nodeLoad:           newNodeLoadCounter(),
		targetConns:        make(map[string]map[*smartTrackedConn]struct{}),
		shortLife:          make(map[string][]time.Time),
		resetEvents:        newResetEventTracker(),
		knownDead:          xsync.NewMapOf[string, time.Time](),
		targetDebargo:      xsync.NewMapOf[string, time.Time](),
		breakers:           xsync.NewMapOf[string, *circuitBreakerState](),
		aliveAt:            xsync.NewMapOf[string, int64](),
		groupOrdinal:       nextGroupOrdinal(),
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
	// 保存原始配置值，用于 PostStart 阶段重新应用。
	s.configAlgorithm = options.Algorithm
	// Apply the configured algorithm via the same SetAlgorithm path
	// that ClashAPI uses for runtime swaps — keeps the lazy-allocation
	// rules (sticky map, RR counters) in one place.
	s.SetAlgorithm(options.Algorithm)
	// Hysteresis is orthogonal to the algorithm choice — allocate the
	// memo whenever the user requested a non-zero window. Costs ~one
	// xsync map (≈ 200 B baseline) per Smart group.
	if d := time.Duration(options.Hysteresis); d > 0 {
		s.hysteresisWindow = d
		s.hysteresisMemo = xsync.NewMapOf[stickyKey, hysteresisEntry]()
	}

	s.parsePolicyPriority(options.PolicyPriority)

	// Record per-group ASN mmdb paths (Listable: 0..N entries); actual
	// file opens happen in PostStart so we can fall back to the global
	// GeoX service paths when the per-group list is empty.
	for _, p := range options.ASNDatabase {
		if p != "" {
			s.asnDBPaths = append(s.asnDBPaths, p)
		}
	}

	return s, nil
}

// parsePolicyPriority moved to smart_priority.go (richer prefix grammar
// + multiplicative aggregation + per-tag factor cache).

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
	// Intern tag strings so N Smart groups sharing the same node hold
	// pointers to ONE backing byte slice — saves ~1 KB per overlapping
	// node across the process (13 KB → ~1 KB on a 15-group × 30-node
	// overlap scenario).
	for i := range tags {
		tags[i] = internTag(tags[i])
	}
	s.state.Store(&smartGroupState{outbounds: outbounds, tags: tags})
	return nil
}

func (s *Smart) PostStart() error {
	// 在 PostStart 阶段重新应用配置中的算法。NewSmart 构造阶段虽然
	// 已经调用了 SetAlgorithm，但 logFactory 尚未 Start()，日志会
	// 被丢弃且无法确认。这里重新应用确保：
	//   1. atomic.Pointer 中的值一定是最新的（防御性保障）
	//   2. 日志在 logFactory 已启动后输出，用户一定能看到
	if s.configAlgorithm != "" {
		s.SetAlgorithm(s.configAlgorithm)
	}

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

	// Resolve ASN mmdb paths: per-group list wins (in order); fall back to
	// the global experimental.geox.url.asn list. Multi-source lookup tries
	// each opened reader in order until a hit is found, so users can stack
	// providers (MaxMind / IPInfo / DBIP / Cloudflare) for better coverage.
	if s.useASN {
		paths := s.asnDBPaths
		if len(paths) == 0 {
			if geoSvc := service.FromContext[adapter.GeoXService](s.ctx); geoSvc != nil {
				paths = geoSvc.ASNPaths()
				if len(paths) > 0 {
					s.logger.Info("smart: ASN database not configured per-group; using ",
						len(paths), " global source(s) from experimental.geox.url.asn")
				}
			}
		}
		if len(paths) == 0 {
			s.logger.Warn("smart: use_asn is true but no ASN database resolved (set asn_database or experimental.geox.url.asn); ASN features disabled")
		} else {
			for _, p := range paths {
				db, err := getSharedMMDB(p)
				if err != nil {
					s.logger.Warn("smart: failed to open ASN database [", p, "]: ", err, " (skipping; other sources still tried)")
					continue
				}
				s.asnDBs = append(s.asnDBs, db)
				s.logger.Info("smart: ASN database loaded from ", p, " (shared across groups via mmdbPool)")
			}
			if len(s.asnDBs) == 0 {
				s.logger.Warn("smart: all configured ASN databases failed to open; ASN features disabled")
			}
		}
	}

	// Optional country mmdb — feeds ModelInput.DestGeoIP (LightGBM features
	// 17 and 26). When the GeoX service has downloaded country.mmdb we use
	// it; otherwise DestGeoIP stays nil and those features fall back to 0.
	if geoSvc := service.FromContext[adapter.GeoXService](s.ctx); geoSvc != nil {
		if mmdbPath := geoSvc.MMDBPath(); mmdbPath != "" {
			if db, err := getSharedMMDB(mmdbPath); err == nil {
				s.countryDB = db
				s.logger.Info("smart: country mmdb loaded from ", mmdbPath, " (shared via mmdbPool)")
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

	// Hydrate runtime state from bbolt BEFORE any background task / dial
	// path can read knownDead / breakers / manualSelected. Keeps the dial
	// pipeline consistent with the pre-shutdown view within TTL bounds.
	s.hydratePersistedState()
	s.restorePinEndorsements()

	// Start background tasks
	s.taskCtx, s.taskCancel = context.WithCancel(context.Background())

	type taskDef struct {
		name     string
		initial  time.Duration
		period   time.Duration
		fn       func()
		once     bool
		idleSkip bool // true = skip execution when s.isGroupIdle() (battery-friendly)
	}

	tasks := []taskDef{
		// Active URL probing — populates URLTestHistoryStorage so isAlive,
		// selectFullScan ranking and fillProxies actually see dead nodes.
		// SKIP when idle: 16 groups × 30 probes is the #1 CPU/battery
		// drain on Android when the phone is in the user's pocket with
		// no active traffic.
		{"health-check", 10 * time.Second, s.interval, s.runHealthCheck, false, true},
		// Warm the pipeline fast so /proxies/<tag>/weights returns non-empty
		// within a minute of first traffic. Idle-skip: ranking is pointless
		// when no one's dialing.
		{"nodes-ranking", 45 * time.Second, 1 * time.Minute, s.updateNodeRanking, false, true},
		{"prefetch", 30 * time.Second, 2 * time.Minute, s.runPrefetch, false, true},
		{"recovery-check", 5 * time.Minute, 5 * time.Minute, s.checkAndRecoverDegradedNodes, false, true},
		// Stalled-conn watchdog: catches dialled-OK conns that never
		// produce a first byte OR went silent mid-transfer. NOT idle-
		// gated because by definition it only does work when at least
		// one conn is in flight; an idle group skips in O(1).
		{"stalled-watchdog", 10 * time.Second, watchdogScanInterval, s.runStalledConnWatchdog, false, false},
		// Cleanup tasks are process-global (gated via claimGlobalTask) and
		// their work is bounded — safe to keep running so data hygiene
		// survives long idle periods.
		{"cleanup-old", 10 * time.Minute, 120 * time.Minute, s.cleanupOldRecords, false, false},
		{"cleanup-orphan", 10 * time.Minute, 10 * time.Minute, s.cleanupOrphanedNodeCache, false, false},
		{"cleanup-orphan-groups", 15 * time.Minute, 120 * time.Minute, s.cleanupOrphanedGroups, false, false},
		// Queue flush must run even when idle — ensures pending writes
		// from the final pre-idle dials actually land on disk.
		{"flush-queue", 5 * time.Second, 5 * time.Minute, s.flushQueue, false, false},
		{"cache-adjust", 5 * time.Second, 5 * time.Minute, s.adjustCache, false, false},
	}

	for _, t := range tasks {
		// Stagger initial firing across groups so N Smart groups don't
		// all thrash the CPU / testURL host at the exact same tick.
		// singleflight de-dup kicks in even without staggering, but
		// staggering also spreads the freshness-cache fill across time.
		initial := staggeredInitialDelay(t.initial, s.groupOrdinal)
		fn := t.fn
		if t.idleSkip {
			tname := t.name
			fn = func() {
				if s.isGroupIdle() {
					// Idle groups skip CPU-heavy tasks entirely.
					// Single-line debug trace so operators investigating
					// "task stopped firing" can see it's intentional.
					s.logger.Debug("smart[", s.Tag(), "] skip ", tname,
						" — group idle (no dial in ", idleThresholdNanos/int64(time.Second), "s)")
					return
				}
				t.fn()
			}
		}
		s.startTimedTask(t.name, initial, t.period, fn, t.once)
	}

	// Startup summary — single info line with all relevant flags.
	snap := s.state.Load()
	outboundCount := 0
	if snap != nil {
		outboundCount = len(snap.tags)
	}
	asnStatus := "off"
	if s.useASN {
		switch n := len(s.asnDBs); {
		case n == 0:
			asnStatus = "on(no-db)"
		case n == 1:
			asnStatus = "on"
		default:
			asnStatus = "on(" + strconv.Itoa(n) + " sources)"
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
	// 在 PostStart 阶段重新输出 algorithm 确认日志。
	// NewSmart 构造阶段 SetAlgorithm 已经设置了算法，但那时
	// logFactory 还未 Start()，日志可能被丢弃。这里确保
	// 用户一定能看到生效的算法名称——解决 "配置无效" 的误解。
	algoStatus := s.currentAlgorithm()
	hysteresisStatus := "off"
	if s.hysteresisWindow > 0 {
		hysteresisStatus = s.hysteresisWindow.String()
	}
	s.logger.Info("smart[", s.Tag(), "] started: ", outboundCount, " outbounds, ",
		len(tasks), " background tasks, testURL=", s.testURL,
		" interval=", s.interval, " asn=", asnStatus,
		" algorithm=", algoStatus, " hysteresis=", hysteresisStatus,
		" ml=", mlStatus, " collect=", collectStatus)
	// 对非默认算法额外输出一条醒目的单独日志行，方便用户通过
	// grep 确认算法配置已生效。
	if algoStatus != smartAlgoStrictBest {
		s.logger.Info("smart[", s.Tag(), "] algorithm: ", algoStatus, " (confirmed in PostStart)")
	}

	s.started.Store(true)
	return nil
}

// startTimedTask registers a periodic task on the process-wide timing wheel.
//
// The previous implementation spawned one goroutine per task that blocked on
// time.NewTicker — for 15 Smart groups × 9 tasks = 135 parked goroutines
// each costing 2-8 KB stack + a runtime timer slot. Now a single bucket
// processor goroutine in timingwheel.TimingWheel drives every group's
// tasks, and the actual work routes through the shared ants pool (which
// already caps global concurrency at 64 workers).
//
// Semantic preservation:
//   - "task completes before next tick considers firing" — enforced by
//     running fn() synchronously inside the ants worker before the
//     scheduler's Next() computes the next firing time.
//   - Cancellation via s.taskCtx.Done() — checked inside the fire
//     callback AND via scheduledTask.stop() on Close().
//   - Per-group startup staggering via groupOrdinal to avoid
//     thundering-herd on cold start.
func (s *Smart) startTimedTask(name string, initial, period time.Duration, fn func(), once bool) {
	worker := getSmartWorker()
	s.taskWg.Add(1)
	wrapped := func() {
		defer func() {
			if once {
				s.taskWg.Done()
			}
		}()
		// Cheap context check at fire time — wheel might have queued us
		// before group close but run us after.
		select {
		case <-s.taskCtx.Done():
			return
		default:
		}
		fn()
	}
	// Add a sub-second random skew on top of the staggered initial to
	// spread tasks that share the same ordinal bucket.
	skew := time.Duration(rand.Float64() * float64(period) * 0.1)
	task := worker.scheduleTask(initial+skew, period, wrapped, once, s.taskCtx)
	s.scheduledTasks = append(s.scheduledTasks, task)
	if !once {
		// For non-once tasks we keep a slot on taskWg so Close() waits
		// for the final fire. Release it during Close by calling Done()
		// from stopScheduledTasks.
	}
}

// stopScheduledTasks cancels every timing-wheel entry this group registered
// and releases the matching taskWg slots so Close() can proceed without
// waiting for the wheel processor to notice cancellation via context.
func (s *Smart) stopScheduledTasks() {
	for _, t := range s.scheduledTasks {
		t.stop()
		if !t.once {
			s.taskWg.Done()
		}
	}
	s.scheduledTasks = nil
}

func (s *Smart) Close() error {
	s.started.Store(false)
	if s.taskCancel != nil {
		s.taskCancel()
	}
	// Stop every timing-wheel registration BEFORE waiting on taskWg.
	// The wheel's bucket processor might still be mid-fire for our group
	// when Close is called; stopScheduledTasks tells it to drop future
	// firings and releases the WaitGroup slots that would otherwise
	// block here forever (the periodic tasks never naturally "finish").
	s.stopScheduledTasks()
	s.taskWg.Wait()
	// Shared LightGBM model, downloader and collector are owned by
	// experimental.smart.Service — do NOT close them here.
	if s.store != nil {
		// StoreFlushNow drains in-flight async BatchSaves AND fsyncs, so
		// a process kill immediately after Close cannot lose the last
		// batch of observed dial stats. FlushQueue(true) alone would
		// return before the async goroutines finish committing.
		_ = s.store.StoreFlushNow()
	}
	for _, db := range s.asnDBs {
		releaseSharedMMDB(db)
	}
	s.asnDBs = nil
	if s.countryDB != nil {
		releaseSharedMMDB(s.countryDB)
		s.countryDB = nil
	}
	return nil
}

// Hidden / Icon expose the dashboard hints from option.GroupCommonOption.
// See adapter.OutboundGroup interface for the semantic contract.
func (s *Smart) Hidden() bool { return s.hidden }
func (s *Smart) Icon() string { return s.icon }

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
		s.persistManualPinDelete()
		// Drop the unwrap cache unconditionally — this is an
		// in-memory routing-table invariant, not an active-
		// connection signal; stale (target → old-pin) mappings
		// would let downstream queries see ghost state even when
		// the user asked to preserve existing conns.
		if s.store != nil {
			s.store.ClearUnwrapByGroup(s.Tag(), smartConfigName)
		}
		// Interrupt existing connections ONLY when the user opted
		// into that via interrupt_exist_connections=true. Smart's
		// pin switching is often exploratory; many users want
		// "new dials go to the new pin, existing downloads/streams
		// keep running on the old node" — forcibly interrupting
		// there breaks long transfers mid-flight.
		if s.interruptExternalConnections && s.interruptGroup != nil {
			s.interruptGroup.Interrupt(s.interruptExternalConnections)
		}
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
			s.persistManualPin(tag)
			// Mirror Selector.SelectOutbound — writing the pin alone
			// wasn't enough; users experienced "pin doesn't take
			// effect" because ALREADY-OPEN mux / HTTP2 / QUIC
			// streams kept flowing through the prior node. Pin
			// only gates NEW dials.
			//
			// Unwrap cache is dropped unconditionally: it's a stale
			// in-memory map, not an active connection. Interrupt on
			// live connections is conditional on
			// interrupt_exist_connections so the "preserve running
			// transfers" preference is honoured.
			if s.store != nil {
				s.store.ClearUnwrapByGroup(s.Tag(), smartConfigName)
			}
			if s.interruptExternalConnections && s.interruptGroup != nil {
				s.interruptGroup.Interrupt(s.interruptExternalConnections)
			}
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

// WeightRanking returns the ranked node list (sorted by weight) for this
// group, used by `GET /proxies/<tag>/weights`. Four-layer resolution so the
// API returns usable data at every lifecycle stage, matching mihomo parity:
//
//  1. forceRefresh=true → recompute from prefetch (authoritative).
//  2. Cached ranking from the store (fast path; populated ~1 min).
//  3. Live aggregation from raw stats (covers the "some traffic closed"
//     window, as soon as the first connection stats land in bbolt).
//  4. URLTest-delay fallback — covers COLD START where no user traffic has
//     closed yet. The health-check task seeds URLTestHistoryStorage every
//     10 s, so weights are available within ~10 s of process start.
//     Weight = 1000 - delay_ms (clamped to ≥1); this monotonically prefers
//     lower-latency nodes. Same rank categorization as the stats path.
//
// Returns a non-nil empty slice when no data exists anywhere; never returns nil.
func (s *Smart) WeightRanking(forceRefresh bool) ([]smart.NodeRank, error) {
	if s.store == nil {
		return s.delayBasedRanking(), nil
	}
	snap := s.state.Load()
	if snap == nil || len(snap.tags) == 0 {
		return []smart.NodeRank{}, nil
	}
	// Primary source (non-refresh path): in-process snapshot from the
	// last successful updateNodeRanking. Always preferred when fresh
	// because it bypasses the bbolt write→flush→read round-trip that
	// previously made WeightRanking fall through for several seconds
	// after every recompute.
	const snapshotMaxAge = 30 * time.Minute
	if !forceRefresh {
		if mem := s.rankingSnapshot.Load(); mem != nil &&
			len(mem.ranking) > 0 && time.Since(mem.computedAt) < snapshotMaxAge {
			return s.finalizeRanking(mem.ranking, true), nil
		}
	}
	if forceRefresh {
		ranking, err := s.store.GetNodeWeightRanking(s.Tag(), smartConfigName, s.testURL, s.isAlive, snap.tags)
		if err != nil {
			return []smart.NodeRank{}, err
		}
		if len(ranking) > 0 {
			ranking = s.finalizeRanking(ranking, false)
			s.publishRankingSnapshot(ranking)
			return ranking, nil
		}
		// Authoritative recompute came up empty — fall through to live.
	} else if cached, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName); err == nil && len(cached) > 0 {
		// bbolt-cached ranking exists (recovered after restart): warm
		// the in-process snapshot so subsequent calls hit the fast path.
		cached = s.finalizeRanking(cached, false)
		s.publishRankingSnapshot(cached)
		return cached, nil
	}
	if live := s.store.GetLiveNodeRanking(s.Tag(), smartConfigName, s.isAlive, snap.tags); len(live) > 0 {
		// Live computation succeeded — also publish to the snapshot so
		// repeat calls in the next 30 min skip the GetAllStats scan.
		// finalizeRanking is a no-op for live results (they already
		// have correct counts by construction) but kept for symmetry.
		live = s.finalizeRanking(live, false)
		s.publishRankingSnapshot(live)
		return live, nil
	}
	if delayed := s.delayBasedRanking(); len(delayed) > 0 {
		return s.finalizeRanking(delayed, false), nil
	}
	return []smart.NodeRank{}, nil
}

// publishRankingSnapshot updates the in-process ranking cache. Idempotent;
// concurrent callers all overwrite with the latest result. Used by both
// the API path (when it computes via live/cache fallback) and the
// scheduled updateNodeRanking task.
func (s *Smart) publishRankingSnapshot(ranking []smart.NodeRank) {
	if len(ranking) == 0 {
		return
	}
	// Defensive copy so a concurrent mutation of the source slice
	// (sort.Slice in updateNodeRanking, for example) can't tear the
	// snapshot mid-read on another goroutine.
	clone := make([]smart.NodeRank, len(ranking))
	copy(clone, ranking)
	s.rankingSnapshot.Store(&smartRankingSnapshot{
		ranking:    clone,
		computedAt: time.Now(),
	})
}

// DiagnosticSnapshot returns the deep internal state of this Smart
// group for the /smart/groups/{name}/diag endpoint. Read-only — never
// mutates anything. Designed so operators staring at "TargetCount is
// wrong" can see exactly which path the API would serve from and
// what the source-of-truth bbolt table actually contains.
func (s *Smart) DiagnosticSnapshot() map[string]any {
	out := map[string]any{
		"name":             s.Tag(),
		"algorithm":        s.CurrentAlgorithm(),
		"hysteresis":       s.HysteresisDuration().String(),
		"policy_priority":  s.PolicyPriorityRules(),
		"members":          len(s.All()),
		"now":              s.Now(),
		"fixed":            s.Selected(),
		"test_url":         s.TestURL(),
	}

	// Snapshot age — hint for which tier serves the next /weights call.
	if mem := s.rankingSnapshot.Load(); mem != nil {
		out["snapshot_entries"] = len(mem.ranking)
		out["snapshot_age"] = time.Since(mem.computedAt).Truncate(time.Second).String()
	} else {
		out["snapshot_entries"] = 0
		out["snapshot_age"] = "(none)"
	}

	// Source-of-truth from bbolt stats table — which (target, node)
	// pairs actually carry observed dial outcomes RIGHT NOW. Bypasses
	// every cache layer above bbolt's GetSubBytesByPath.
	if s.store != nil {
		snap := s.state.Load()
		if snap != nil {
			realTC, realSC := s.collectRealCoverage(snap.tags)
			perNode := make(map[string]map[string]int, len(realTC))
			for tag, tc := range realTC {
				perNode[tag] = map[string]int{
					"target_count":   tc,
					"sample_count":   realSC[tag],
				}
			}
			out["live_coverage"] = perNode
		}
	}
	return out
}

// finalizeRanking is the single chokepoint every WeightRanking return
// path runs through. It force-refreshes TargetCount / SampleCount
// from the live bbolt stats so the API surface always reports counts
// consistent with what the dial path observes. Called on a fresh
// (defensive-copied) slice when the source might be a shared
// snapshot, otherwise mutates in place.
func (s *Smart) finalizeRanking(ranking []smart.NodeRank, fromSnapshot bool) []smart.NodeRank {
	if len(ranking) == 0 || s.store == nil {
		return ranking
	}
	target := ranking
	if fromSnapshot {
		// Snapshot is shared between callers; mutate a copy so a
		// transient enrich result doesn't poison the cached snapshot
		// for callers that follow. The snapshot itself is also
		// re-enriched on its own cadence elsewhere.
		target = make([]smart.NodeRank, len(ranking))
		copy(target, ranking)
	}
	s.store.EnrichRankingCounts(s.Tag(), smartConfigName, target)
	return target
}

// delayBasedRanking synthesizes a NodeRank list from URLTestHistoryStorage
// latency data — the ONLY signal that's reliably available before any user
// traffic has closed through the group. Used as the cold-start fallback in
// WeightRanking so /proxies/<tag>/weights never returns an empty list once
// the first health-check pass has completed (usually within 10 s).
//
// Normalised scoring: weight% = (1 - delay/maxDelay) * 100, so the fastest
// node in the group gets ~100 and the slowest gets ~0. Dead nodes (no
// history OR Delay==0) are pushed to the bottom with Rank=RarelyUsed.
//
// Rank buckets follow the same 20/50 split used elsewhere (top 20% =
// MostUsed, next 50% = Occasional, remainder = RarelyUsed).
func (s *Smart) delayBasedRanking() []smart.NodeRank {
	snap := s.state.Load()
	if snap == nil || len(snap.tags) == 0 {
		return nil
	}
	if s.history == nil {
		return nil
	}
	type row struct {
		name  string
		delay int
		alive bool
	}
	rows := make([]row, 0, len(snap.tags))
	var maxDelay int
	for _, tag := range snap.tags {
		h := s.history.LoadURLTestHistory(tag)
		if h == nil {
			rows = append(rows, row{name: tag, delay: 0, alive: false})
			continue
		}
		d := int(h.Delay)
		alive := d > 0
		rows = append(rows, row{name: tag, delay: d, alive: alive})
		if alive && d > maxDelay {
			maxDelay = d
		}
	}
	if maxDelay == 0 {
		return nil
	}
	// Pull real per-node target/sample counts from the stats table so the
	// delay-based fallback reports the same TargetCount semantic as the
	// live/prefetch paths: number of distinct targets the node has been
	// observed on. Truly cold-start nodes (no stats yet) get 0 — that is
	// the honest answer, not a guess.
	realTargets, realSamples := s.collectRealCoverage(snap.tags)
	now := time.Now().Unix()
	result := make([]smart.NodeRank, 0, len(rows))
	for _, r := range rows {
		var raw, pct float64
		if r.alive {
			// Raw synthetic weight: 1000ms latency → ~1.0 (treat as unit),
			// so faster nodes land above 1.0 and slower below. Matches the
			// magnitude of CalculateWeight output so delay-fallback
			// weights are visually comparable to stats-derived weights.
			raw = 1000.0 / float64(r.delay)
			pct = (1.0 - float64(r.delay)/float64(maxDelay+1)) * 100
			pct = math.Round(pct*100) / 100
			raw = math.Round(raw*10000) / 10000
		}
		result = append(result, smart.NodeRank{
			Name:        r.name,
			Weight:      raw,
			Score:       pct,
			TargetCount: realTargets[r.name],
			SampleCount: realSamples[r.name],
			LastUpdated: now,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		// Stable split: alive-first, then higher weight first.
		ai := result[i].Weight > 0
		aj := result[j].Weight > 0
		if ai != aj {
			return ai
		}
		return result[i].Weight > result[j].Weight
	})
	aliveCount := 0
	for _, r := range result {
		if r.Weight > 0 {
			aliveCount++
		}
	}
	if aliveCount == 0 {
		// Every node had zero delay — signal is useless; let caller skip.
		return nil
	}
	result[0].Rank = smart.RankMostUsed
	if aliveCount == 2 {
		result[1].Rank = smart.RankOccasional
	} else if aliveCount >= 3 {
		mostUsedBound := int(float64(aliveCount) * 0.2)
		if mostUsedBound < 1 {
			mostUsedBound = 1
		}
		occasionalBound := mostUsedBound + int(float64(aliveCount)*0.5)
		for i := 1; i < mostUsedBound && i < aliveCount; i++ {
			result[i].Rank = smart.RankMostUsed
		}
		for i := mostUsedBound; i < occasionalBound && i < aliveCount; i++ {
			result[i].Rank = smart.RankOccasional
		}
		for i := occasionalBound; i < aliveCount; i++ {
			result[i].Rank = smart.RankRarelyUsed
		}
	}
	for i := 0; i < aliveCount; i++ {
		if result[i].Rank == "" {
			result[i].Rank = smart.RankRarelyUsed
		}
	}
	for i := aliveCount; i < len(result); i++ {
		result[i].Rank = smart.RankRarelyUsed
	}
	return result
}

// collectRealCoverage walks the bbolt stats table once and returns, per
// node tag, (a) the number of distinct targets it has been observed
// on and (b) the lifetime sum of success+failure samples across those
// targets. Restricted to tags in `wanted` so we don't pay for nodes
// that aren't members of the calling group.
//
// Used by delayBasedRanking to populate NodeRank.TargetCount /
// SampleCount with REAL counts instead of placeholder values, so the
// dashboard's confidence indicator stays honest even on the cold-start
// fallback. Returns (nil, nil) when the store is unavailable or has no
// data — callers must handle that as "all zeros, no coverage yet".
func (s *Smart) collectRealCoverage(wanted []string) (targets, samples map[string]int) {
	if s.store == nil || len(wanted) == 0 {
		return nil, nil
	}
	wantSet := make(map[string]struct{}, len(wanted))
	for _, t := range wanted {
		wantSet[t] = struct{}{}
	}
	targets = make(map[string]int, len(wanted))
	samples = make(map[string]int, len(wanted))
	// Per-node set of (target) tuples already counted, so the two
	// data sources don't double-add the same pair. atomic record
	// cache wins on conflict — it's ALWAYS at least as fresh as
	// bbolt (bbolt is the lagging copy after BatchSave).
	seen := make(map[string]map[string]struct{}, len(wanted))
	addPair := func(node, target string, count int) {
		if count <= 0 {
			return
		}
		ts := seen[node]
		if ts == nil {
			ts = make(map[string]struct{}, 4)
			seen[node] = ts
		}
		if _, dup := ts[target]; dup {
			return
		}
		ts[target] = struct{}{}
		targets[node]++
		samples[node] += count
	}

	// Source 1: in-memory atomic records — reflects success/failure
	// increments the moment recordStats runs, before BatchSave has
	// flushed to bbolt. Without this the diag endpoint reports zero
	// coverage on a busy group right after dials succeed.
	s.store.IterateAtomicRecords(s.Tag(), smartConfigName, func(target, node string, rec *smart.AtomicStatsRecord) bool {
		if _, want := wantSet[node]; !want {
			return true
		}
		count := int(rec.GetInt64("success") + rec.GetInt64("failure"))
		addPair(node, target, count)
		return true
	})

	// Source 2: bbolt — covers entries that were evicted from the
	// in-memory recordCache (LRU pressure) but still persist on disk.
	if allStats, err := s.store.GetAllStats(s.Tag(), smartConfigName); err == nil {
		for target, nodeStats := range allStats {
			for nodeName, data := range nodeStats {
				if _, want := wantSet[nodeName]; !want {
					continue
				}
				var rec smart.StatsRecord
				if smart.UnmarshalStatsRecord(data, &rec) != nil {
					continue
				}
				count := int(rec.Success + rec.Failure)
				addPair(nodeName, target, count)
			}
		}
	}
	return targets, samples
}

// FlushStore wipes all Smart persistent data for this specific group AND
// resets every piece of in-process runtime state that could otherwise
// make a flushed group still "feel" populated: manual pin, cold-start
// log latch, knownDead map, short-life counters, and the last-selected
// tag. Without this, /proxies/<tag>/weights would go empty-then-reappear
// because live stats from existing connections keep feeding in, and the
// operator would see "the flush didn't work".
//
// Returns flush statistics (deleted key counts per bucket) so operators
// hitting /cache/smart/flush/{name} can verify the operation was effective.
func (s *Smart) FlushStore() (smart.FlushStats, error) {
	if s.store == nil {
		return smart.FlushStats{}, nil
	}
	// In-process runtime reset
	s.manualSelected.Store("")
	s.lastSelectedTag.Store("")
	s.coldStartLogged.Store(false)

	s.knownDead.Clear()
	s.breakers.Clear()
	s.aliveAt.Clear()
	if s.pinEndorsements != nil {
		s.pinEndorsements.Clear()
	}

	s.shortLifeMu.Lock()
	s.shortLife = make(map[string][]time.Time)
	s.shortLifeMu.Unlock()
	if s.resetEvents != nil {
		s.resetEvents.reset()
	}

	// Drop per-target registry so a subsequent mass-close doesn't chase
	// pointers to conns that were relevant only to the pre-flush state.
	s.targetConnsMu.Lock()
	s.targetConns = make(map[string]map[*smartTrackedConn]struct{})
	s.targetConnsCount.Store(0)
	s.targetConnsMu.Unlock()

	smart.ClearBlockedNodesCache(s.Tag(), smartConfigName)
	return s.store.FlushByGroup(s.Tag(), smartConfigName)
}

// SmartStore exposes the underlying store for global-flush operations.
// Returns nil if the cache file was not configured.
func (s *Smart) SmartStore() *smart.Store { return s.store }

// ClearSelectionResult describes what ClearSelection actually changed, so
// the ClashAPI handler can surface a useful response instead of a bare 204.
// Fields are intentionally lowercase-JSON to match dashboard conventions.
type ClearSelectionResult struct {
	Group          string `json:"group"`
	PreviousPin    string `json:"previous_pin,omitempty"`
	Now            string `json:"now,omitempty"`
	InterruptedMux bool   `json:"interrupted_mux"`
	UnwrapCleared  bool   `json:"unwrap_cleared"`
}

// ClearSelection performs a full manual-pin release on this Smart group.
// Simple "clear pin" isn't enough — without the full set of side effects,
// the group keeps feeling pinned:
//
//  1. Clear manualSelected            — obvious, without it SelectOutbound
//                                       keeps short-circuiting to the pin.
//  2. Reset lastSelectedTag           — Now() surfaced the old pin as the
//                                       "current" node until the next dial.
//  3. Drop unwrap cache for this grp  — the unwrap LRU held (target → pin)
//                                       mappings, so subsequent dials
//                                       bypassed fresh selection.
//  4. Interrupt active connections    — existing conns routed via the pin
//                                       would keep flowing through it
//                                       forever; parity with Selector's
//                                       SelectOutbound → Interrupt path.
//  5. Async RunPrefetch + ranking     — kick the ranking pipeline so the
//                                       next dial already sees fresh
//                                       weights instead of delay-fallback.
//
// Returns a summary of what changed. Always succeeds (a Smart group always
// accepts an unpin operation, even if no pin was active).
func (s *Smart) ClearSelection() ClearSelectionResult {
	prev := s.getManualSelected()
	res := ClearSelectionResult{Group: s.Tag(), PreviousPin: prev}

	s.manualSelected.Store("")
	s.lastSelectedTag.Store("")
	s.persistManualPinDelete()

	if s.store != nil {
		s.store.ClearUnwrapByGroup(s.Tag(), smartConfigName)
		res.UnwrapCleared = true
	}

	if s.interruptGroup != nil {
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
		res.InterruptedMux = true
	}

	s.logger.Info("smart[", s.Tag(), "] manual pin cleared (previous=[", prev,
		"]); unwrap cache dropped, active connections interrupted")

	// Kick the ranking pipeline asynchronously so the next /weights or
	// DialContext sees fresh data. Cheap: goroutines are work-stealing and
	// the functions are idempotent.
	getSmartWorker().submit(func() {
		s.runPrefetch()
		s.updateNodeRanking()
	})

	res.Now = s.Now()
	return res
}

// RecomputeWeights kicks off an async refresh of the group's ranking pipeline:
// runPrefetch (aggregates per-target history) followed by updateNodeRanking
// (derives the overall node ranking from prefetch output). Used right after
// a flush so /proxies/<tag>/weights reflects post-flush state within seconds
// instead of waiting for the next scheduled tick. Safe to call concurrently;
// the background task loop tolerates overlapping invocations.
func (s *Smart) RecomputeWeights() {
	if s.store == nil {
		return
	}
	getSmartWorker().submit(func() {
		s.runPrefetch()
		s.updateNodeRanking()
	})
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
//  1. Active manual pin — reflects the user's explicit choice immediately,
//     even before the first dial has landed. Without this, the dashboard
//     "now" field lagged behind the "fixed" field for several seconds
//     after pinning, which users interpreted as "the pin didn't take".
//  2. Last successful dial's winning tag.
//  3. Top-ranked node from the pre-sorted ranking cache, if any.
//  4. Lowest URLTest latency among alive outbounds (cold-start signal).
//  5. First outbound in the snapshot (best-effort guess).
//  6. Empty string — OutboundGroup helpers fall back to the group's own tag.
func (s *Smart) Now() string {
	if pinned := s.getManualSelected(); pinned != "" {
		return pinned
	}
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
	// Third-best: fastest node by URLTest latency so the dashboard shows
	// something meaningful before any user traffic has touched the group.
	if snap := s.state.Load(); snap != nil && len(snap.tags) > 0 && s.history != nil {
		var bestTag string
		var bestDelay uint16
		for _, tag := range snap.tags {
			h := s.history.LoadURLTestHistory(tag)
			if h == nil || h.Delay == 0 {
				continue
			}
			if bestTag == "" || h.Delay < bestDelay {
				bestTag = tag
				bestDelay = h.Delay
			}
		}
		if bestTag != "" {
			return bestTag
		}
	}
	// Fourth: first available node from the snapshot.
	if snap := s.state.Load(); snap != nil && len(snap.tags) > 0 {
		return snap.tags[0]
	}
	return ""
}

// setLastSelected records a successful dial winner for Now() reporting
// AND bumps the activity timestamp used by the idle-aware task
// scheduler. Called from every successful DialContext / ListenPacket
// path so the group is considered "active" while traffic is flowing.
func (s *Smart) setLastSelected(tag string) {
	if tag == "" {
		return
	}
	s.lastSelectedTag.Store(tag)
	s.lastDialAt.Store(time.Now().UnixNano())
	// First successful dial of this process lifetime: kick the ranking
	// pipeline immediately instead of waiting up to 45 s for the
	// scheduled "nodes-ranking" task to fire. Without this, a fresh
	// process serves /weights from delayBasedRanking for nearly a
	// minute even when stats already exist on disk and the user is
	// actively dialing. The kick runs on the shared worker pool so
	// it doesn't block this dial, and Once-gating ensures we pay the
	// scan cost only once per restart.
	s.rankingKickOnce.Do(func() {
		if s.store == nil {
			return
		}
		// Defer slightly so the very first dial's stats record has
		// time to land in the queue (BatchSave threshold kicks in for
		// the synchronous path; otherwise the 5 s flush task picks it
		// up). 2 s is enough for both paths and keeps the kick well
		// inside the 45 s window we're cutting short.
		w := getSmartWorker()
		w.scheduleTask(2*time.Second, 0, s.updateNodeRanking, true, s.taskCtx)
	})
}

// idleThresholdNanos — how long without a successful dial before the
// group's periodic tasks (health-check / prefetch / ranking / cache-adjust)
// are skipped. Queue-flush still runs so any pending writes land on disk,
// but the CPU-heavy scans are skipped entirely. Chosen at 2 minutes —
// short enough that "phone in pocket" idles catch within one probe
// cycle, long enough that brief pauses in browsing don't cause
// measurable extra probes on resume.
const idleThresholdNanos = int64(2 * time.Minute)

// isGroupIdle reports whether the group has seen no successful dial in
// the last idleThresholdNanos and its periodic tasks can safely skip.
// A group that's never dialed (lastDialAt == 0) is considered idle too —
// the scheduler will skip until the first real dial wakes it.
func (s *Smart) isGroupIdle() bool {
	last := s.lastDialAt.Load()
	if last == 0 {
		return true
	}
	return time.Now().UnixNano()-last > idleThresholdNanos
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
	host := pickHostFromMetadata(metadata)
	ips := pickIPsFromMetadata(metadata)
	var firstIP string
	if len(ips) > 0 {
		firstIP = ips[0].String()
	}

	target := normaliseDialTarget(host, firstIP)
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

// pickHostFromMetadata walks every InboundContext field that can carry
// a hostname for the dial target and returns the first non-empty one.
//
// The router doesn't always populate the same field — TUN inbounds
// rely on sniff, DNS rules expose Domain, and rule-action redirects
// move the original target into OriginDestination /
// RouteOriginalDestination. Reading only the first source (as the
// previous version did) silently dropped target context for whole
// classes of connections, leaving recordStats with no key under
// which to record success / failure.
func pickHostFromMetadata(m adapter.InboundContext) string {
	if m.Destination.Fqdn != "" {
		return m.Destination.Fqdn
	}
	if m.SniffHost != "" {
		return m.SniffHost
	}
	if m.Domain != "" {
		return m.Domain
	}
	if m.OriginDestination.Fqdn != "" {
		return m.OriginDestination.Fqdn
	}
	if m.RouteOriginalDestination.Fqdn != "" {
		return m.RouteOriginalDestination.Fqdn
	}
	return ""
}

// pickIPsFromMetadata aggregates every IP candidate carried by the
// InboundContext into one ordered, de-duplicated list. DestinationAddresses
// (post-DNS) goes first; the bare Destination.Addr (when Destination is
// already an IP literal) is next; CacheIPs / OriginDestination /
// RouteOriginalDestination cover redirected and dns-cache paths the
// previous single-source read missed entirely.
func pickIPsFromMetadata(m adapter.InboundContext) []netip.Addr {
	cap := len(m.DestinationAddresses) + len(m.CacheIPs) + 3
	out := make([]netip.Addr, 0, cap)
	seen := make(map[netip.Addr]struct{}, cap)
	add := func(a netip.Addr) {
		if !a.IsValid() {
			return
		}
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range m.DestinationAddresses {
		add(a)
	}
	add(m.Destination.Addr)
	for _, a := range m.CacheIPs {
		add(a)
	}
	add(m.OriginDestination.Addr)
	add(m.RouteOriginalDestination.Addr)
	return out
}

// normaliseDialTarget produces the target key fed into the stats
// store. Three-tier resolution:
//
//  1. GetEffectiveTarget normalises the hostname into a wildcard form
//     (e.g. a1b2.example.com → *.example.com) so unrelated subdomains
//     of the same site share a single bucket.
//  2. If the host turns out to be an IP literal (ParseAddr succeeds)
//     and we already have an IP fallback, route that through directly
//     instead of letting it fall into a degenerate wildcard like
//     "*.4" (publicsuffix mis-handling) and split a single endpoint
//     into multiple stats keys.
//  3. Final fallback ladder: host → IP → "_unbound_" sentinel so
//     recordStats never sees an empty target. The empty-target
//     early-return in recordStats was the single biggest cause of
//     "TargetCount stays 0 in /weights" reports.
func normaliseDialTarget(host, firstIP string) string {
	// IP literal in the host slot: short-circuit so it doesn't go
	// through the wildcard normaliser (which assumes domain shape).
	if host != "" {
		if _, err := netip.ParseAddr(host); err == nil {
			return host
		}
	}
	target := smart.GetEffectiveTarget(host, firstIP)
	if target != "" {
		return target
	}
	if host != "" {
		return host
	}
	if firstIP != "" {
		return firstIP
	}
	return "_unbound_"
}

// metaFromDestination synthesizes a smartDialMeta directly from the
// socksaddr argument when the per-conn meta wasn't populated by
// NewConnectionEx — typical when an upper-level group (Selector / URLTest /
// LoadBalance) routes through this Smart group via a direct DialContext
// call. Without this, smartTarget would be empty, every selectProxies hit
// the "fallback" tier, and recordStats dropped all events.
//
// existing != nil means we have a partial meta from ctx — reuse its host /
// destGeoIP / asnCode if present so we don't lose data the upstream layer
// might have populated.
func (s *Smart) metaFromDestination(existing *smartDialMeta, destination M.Socksaddr, isUDP bool) *smartDialMeta {
	// Host preference: existing meta (already-resolved upstream
	// context) wins over the bare destination Fqdn so a Selector →
	// Smart chain doesn't lose the SniffHost or Domain that the
	// inbound originally provided.
	host := ""
	if existing != nil && existing.host != "" {
		host = existing.host
	} else if destination.IsFqdn() {
		host = destination.Fqdn
	}

	// IP list: union of existing.resolvedIPs and destination.Addr,
	// de-duplicated. Existing IPs come first because they typically
	// reflect the real DNS resolution; the bare destination.Addr is
	// kept as a last-resort literal.
	var ips []netip.Addr
	seen := make(map[netip.Addr]struct{}, 4)
	if existing != nil {
		for _, a := range existing.resolvedIPs {
			if a.IsValid() {
				if _, dup := seen[a]; !dup {
					seen[a] = struct{}{}
					ips = append(ips, a)
				}
			}
		}
	}
	if destination.Addr.IsValid() {
		if _, dup := seen[destination.Addr]; !dup {
			seen[destination.Addr] = struct{}{}
			ips = append(ips, destination.Addr)
		}
	}
	firstIP := ""
	if len(ips) > 0 {
		firstIP = ips[0].String()
	}

	target := normaliseDialTarget(host, firstIP)
	asnCode := ""
	if existing != nil && existing.asnCode != "" {
		asnCode = existing.asnCode
	} else {
		asnCode = s.lookupASN(ips)
	}
	geoIP := []string(nil)
	if existing != nil && len(existing.destGeoIP) > 0 {
		geoIP = existing.destGeoIP
	} else {
		geoIP = s.lookupCountry(ips)
	}

	return &smartDialMeta{
		host:        host,
		smartTarget: target,
		asnCode:     asnCode,
		destGeoIP:   geoIP,
		resolvedIPs: ips,
		isUDP:       isUDP,
		destPort:    destination.Port,
	}
}

// DialContext implements the race-dial with retry logic.
func (s *Smart) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	isUDP := N.NetworkName(network) == N.NetworkUDP

	// Register with the network-change dial cancel set so a
	// mid-dial InterfaceUpdated aborts us instead of letting the
	// dial sit on the old interface until its natural timeout. The
	// caller (upstream client) will see ErrNetworkChanged and retry
	// immediately against the new interface — smoother than a 10s
	// stall the user would otherwise perceive as "stuck loading".
	ctx, cleanup := s.registerDial(ctx)
	defer cleanup()

	// Recover meta from ctx (set by NewConnectionEx) OR synthesize from
	// the raw destination when this Smart group is dialed directly by an
	// upper-level group (Selector / URLTest / LoadBalance). The previous
	// code left meta empty in that case, breaking selectProxiesTraced
	// (always fell through to "fallback") and recordStats (early-return
	// on empty target swallowed all stats).
	meta, _ := ctx.Value(smartMetaCtxKey{}).(*smartDialMeta)
	if meta == nil || meta.smartTarget == "" {
		meta = s.metaFromDestination(meta, destination, isUDP)
	}

	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return nil, E.New("smart: no outbounds available")
	}
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
		": target=", displayTarget(meta, destination), " asn=", displayASN(meta),
		" candidates=", proxyTagsPreview(selectedOutbounds, 5))

	if !isUnwrap && s.store != nil && meta.smartTarget != "" {
		names := outboundNames(selectedOutbounds)
		s.store.StoreUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP, names)
	}

	// Request-level scene rerank: reorder the top few candidates by
	// what THIS request actually needs (streaming → peak bandwidth,
	// realtime → lowest latency) rather than just the historical
	// node-level score. Cached unwrap result is persisted BEFORE
	// this rerank so the cache stays stable; the rerank only biases
	// dial order on this specific attempt.
	selectedOutbounds = s.reorderForRequestScene(selectedOutbounds, meta)

	conn, proxyTag, connectTime, err := s.dialWithRetry(ctx, network, destination, selectedOutbounds, meta)
	if err != nil {
		s.logger.WarnContext(ctx, "smart[", s.Tag(), "] dial failed to ", destination,
			" after retries: ", err)
		return nil, err
	}
	s.setLastSelected(proxyTag)
	s.rememberStickyChoice(meta.smartTarget, proxyTag, isUDP)
	s.rememberHysteresisChoice(meta.smartTarget, proxyTag, isUDP)
	s.markAlive(proxyTag) // successful dial = confirmed alive; clears knownDead
	s.logger.InfoContext(ctx, "smart[", s.Tag(), "] ", network, " → ", destination,
		" via [", proxyTag, "] in ", connectTime, "ms (target=",
		displayTarget(meta, destination), " asn=", displayASN(meta), " source=", source, ")")

	return s.wrapConn(conn, proxyTag, meta, connectTime, isUDP), nil
}

// ListenPacket implements UDP race-dial.
func (s *Smart) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if s.disableUDP {
		return nil, E.New("smart: UDP disabled")
	}

	// Same cancel-set registration as DialContext — a UDP "dial"
	// (ListenPacket + probe) stuck on the old interface is aborted
	// by InterfaceUpdated so the caller can retry cleanly.
	ctx, cleanup := s.registerDial(ctx)
	defer cleanup()

	meta, _ := ctx.Value(smartMetaCtxKey{}).(*smartDialMeta)
	if meta == nil || meta.smartTarget == "" {
		meta = s.metaFromDestination(meta, destination, true)
	}

	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return nil, E.New("smart: no outbounds available")
	}

	selectedOutbounds, isUnwrap, source := s.selectProxiesTraced(meta, snap.outbounds, true)

	s.logger.DebugContext(ctx, "smart[", s.Tag(), "] select via ", source,
		" (UDP): target=", displayTarget(meta, destination), " asn=", displayASN(meta),
		" candidates=", proxyTagsPreview(selectedOutbounds, 5))

	if !isUnwrap && s.store != nil && meta.smartTarget != "" {
		names := outboundNames(selectedOutbounds)
		s.store.StoreUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, true, names)
	}

	// Request-level scene rerank — same contract as DialContext,
	// biases top-K dial order by what THIS request needs.
	selectedOutbounds = s.reorderForRequestScene(selectedOutbounds, meta)

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
			s.rememberStickyChoice(meta.smartTarget, ob.Tag(), true)
			s.rememberHysteresisChoice(meta.smartTarget, ob.Tag(), true)
			s.markAlive(ob.Tag())
			s.logger.InfoContext(ctx, "smart[", s.Tag(), "] UDP → ", destination,
				" via [", ob.Tag(), "] in ", connectTime, "ms (target=",
				displayTarget(meta, destination), " asn=", displayASN(meta),
				" source=", source, ")")
			return s.wrapPacketConn(pc, ob.Tag(), meta, connectTime), nil
		}
		finalErr = err
		s.markDead(ob.Tag())
		s.logger.DebugContext(ctx, "smart[", s.Tag(), "] UDP probe [", ob.Tag(),
			"] failed in ", connectTime, "ms: ", err)
		tag, ct, m := ob.Tag(), connectTime, meta
		getSmartWorker().submit(func() {
			s.recordStats("failed", m, tag, ct, 0, 0, 0, 0, 0, 0)
		})
	}

	return nil, finalErr
}

// selectProxiesTraced performs the tiered selection and returns which tier
// produced the result. Used for user-visible logging. Tier names:
//   - "manual"   : user-pinned via SetSelected (ClashAPI)
//   - "unwrap"   : hot cache of a recently-used node list for this target
//   - "prefetch" : periodically pre-computed best-node list
//   - "weight"   : realtime computation from the weight store
//   - "delay"    : URLTest-latency-based ordering (cold-start fallback so we
//                  still bias toward fast nodes before any stats accumulate)
//   - "fallback" : no signal at all; random pick filtered by alive/blocked
// selectProxiesTraced's bypassManualPin parameter asks the function to
// skip the manual-pin short-circuit and fall through to the normal
// tier logic (unwrap / prefetch / weight / delay / fallback). Used by
// dialWithRetry's hot-reselect path when the pin node just failed to
// dial but its breaker hasn't tripped yet (cbMaxConsecFail=2 means
// ONE failure leaves the breaker closed). Without bypassing, the hot
// reselect would keep returning the same single-element pin list, the
// sameOutboundSet check would declare "nothing fresh" and the whole
// DialContext would fail back to the caller — the user experiences
// "pin node is dead and Smart doesn't try anything else" until they
// manually retry. With bypassManualPin=true on the fallback pass, we
// get algorithm-selected candidates this one dial; the pin is NOT
// cleared, so the NEXT user request still enters the pin path first.
func (s *Smart) selectProxiesTraced(meta *smartDialMeta, all []adapter.Outbound, isUDP bool) ([]adapter.Outbound, bool, string) {
	return s.selectProxiesTracedOpts(meta, all, isUDP, false)
}

// selectProxiesTracedOpts is the full-option form. Keep the public
// zero-arg selectProxiesTraced for every existing caller; only
// dialWithRetry's pin-fallback path needs to opt in.
func (s *Smart) selectProxiesTracedOpts(meta *smartDialMeta, all []adapter.Outbound, isUDP bool, bypassManualPin bool) ([]adapter.Outbound, bool, string) {
	// Manual selection short-circuit — respects the user's pin.
	//
	// Three cases:
	//
	//   a) Pin points at an existing node AND the breaker is closed →
	//      honour the pin, exclusive dial. Matches mihomo Set/ForceSet
	//      semantics.
	//
	//   b) Pin points at an existing node BUT its circuit breaker has
	//      tripped → temporarily bypass to the algorithm path so the
	//      user's request still completes. The pin state is LEFT
	//      INTACT — the moment the breaker cools down, the next dial
	//      snaps back to the pin automatically. "User pinned JP but
	//      it literally can't dial right now" should feel like this.
	//
	//      NOTE: we deliberately do NOT gate on isAlive() here (unlike
	//      earlier versions). isAlive tests URLTestHistory + knownDead
	//      + breaker, and the first two are INDIRECT probe-layer
	//      signals — the pin's testURL could be unreachable (Google-
	//      block, captive portal) even while the pin CAN route real
	//      user traffic. Using isAlive here meant a single failed
	//      urltest OR a warmup probe after a network switch would
	//      silently bypass the pin for up to knownDeadTTL (5 min),
	//      completely contradicting the "it's pinned, use it" intent.
	//      Only the circuit breaker — which trips on actual dial
	//      failures observed by Smart itself — is strong enough
	//      evidence to override the user's explicit pin.
	//
	//   c) Pin points at a non-existent node (provider reloaded,
	//      subscription refreshed) → clear the pin outright and
	//      fall through; the pin has no meaning any more.
	if selected := s.getManualSelected(); selected != "" && !bypassManualPin {
		var pinnedOb adapter.Outbound
		for _, ob := range all {
			if ob.Tag() == selected {
				pinnedOb = ob
				break
			}
		}
		switch {
		case pinnedOb == nil:
			s.manualSelected.Store("")
			s.persistManualPinDelete()
			s.logger.Warn("smart[", s.Tag(), "] pinned node [", selected,
				"] no longer exists, clearing pin")
		case s.isBreakerOpen(selected):
			// Log once-per-event so operators see the bypass happen
			// without spamming on every dial to a still-broken pin.
			if s.pinBypassLogged.CompareAndSwap(false, true) {
				s.logger.Warn("smart[", s.Tag(), "] pinned node [", selected,
					"] circuit breaker OPEN; bypassing to algorithm until it recovers")
			}
		default:
			// Pin honoured — reset the bypass-log latch so the NEXT
			// outage gets its own log line.
			s.pinBypassLogged.Store(false)
			return []adapter.Outbound{pinnedOb}, true, "manual"
		}
	}

	target := ""
	if meta != nil {
		target = meta.smartTarget
	}

	if s.store == nil || meta == nil || meta.smartTarget == "" {
		// No store AND no target — try delay tier anyway before giving up.
		if names, weights := s.delayRankedNames(all, isUDP); len(names) > 0 {
			out := s.fillProxies(target, names, weights, all, smartMaxSelected, isUDP, false)
			return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "delay"
		}
		out := s.fillProxies(target, nil, nil, all, smartMaxSelected, isUDP, false)
		return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "fallback"
	}

	// Tier 1: unwrap cache
	if names := s.store.GetUnwrapResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); len(names) > 0 {
		out := s.fillProxies(target, names, nil, all, smartMaxSelected, isUDP, true)
		return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), true, "unwrap"
	}

	// Tier 2: prefetch cache
	if names, weights := s.store.GetPrefetchResult(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); len(names) > 0 {
		out := s.fillProxies(target, names, weights, all, smartMaxSelected, isUDP, false)
		return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "prefetch"
	}

	// Tier 3: real-time computation from stats
	if names, weights, err := s.store.GetBestProxyForTarget(s.Tag(), smartConfigName, meta.smartTarget, meta.asnCode, isUDP); err == nil && len(names) > 0 {
		out := s.fillProxies(target, names, weights, all, smartMaxSelected, isUDP, false)
		return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "weight"
	}

	// Tier 4: URLTest-delay ranking (cold-start / no-stats path).
	// Health check produces delays every ~10 s, so this tier is usable as
	// soon as the first probe cycle finishes. Without it every (target,
	// node) pair that hadn't yet seen traffic would dial randomly.
	if names, weights := s.delayRankedNames(all, isUDP); len(names) > 0 {
		out := s.fillProxies(target, names, weights, all, smartMaxSelected, isUDP, false)
		return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "delay"
	}

	out := s.fillProxies(target, nil, nil, all, smartMaxSelected, isUDP, false)
	return s.applyHysteresis(s.reorderForAlgorithm(s.reorderByPriority(out, meta), target, isUDP), target, isUDP), false, "fallback"
}

// delayRankedNames returns (names, synthetic-weights) sorted by URLTest
// latency ascending — fastest first. Synthetic weights are scaled to sit
// above AllowedWeight so fillProxies doesn't drop every candidate as
// "weight too low" (the real weight store uses AllowedWeight≈0.1 as the
// minimum acceptable score).
//
// Returns (nil, nil) when URLTestHistoryStorage has no usable data for any
// candidate (i.e., health check hasn't run yet or every probe has failed).
func (s *Smart) delayRankedNames(all []adapter.Outbound, isUDP bool) ([]string, []float64) {
	if s.history == nil {
		return nil, nil
	}
	type row struct {
		name  string
		delay uint16
	}
	rows := make([]row, 0, len(all))
	for _, ob := range all {
		if isUDP && !s.supportsUDP(ob) {
			continue
		}
		h := s.history.LoadURLTestHistory(ob.Tag())
		if h == nil || h.Delay == 0 {
			continue
		}
		rows = append(rows, row{ob.Tag(), h.Delay})
	}
	if len(rows) == 0 {
		return nil, nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].delay != rows[j].delay {
			return rows[i].delay < rows[j].delay
		}
		return rows[i].name < rows[j].name
	})
	names := make([]string, len(rows))
	weights := make([]float64, len(rows))
	// Synthetic weight: fastest node gets 1.0, slowest gets just above
	// AllowedWeight. Keeps the relative ranking intact while guaranteeing
	// fillProxies' weight>=AllowedWeight filter passes.
	maxDelay := float64(rows[len(rows)-1].delay)
	minAccept := smart.AllowedWeight + 0.01
	for i, r := range rows {
		names[i] = r.name
		// Linear interpolation between 1.0 and minAccept, so fastest→1.0,
		// slowest→minAccept. Avoids divide-by-zero when all delays equal.
		if maxDelay <= 1 {
			weights[i] = 1.0
		} else {
			frac := float64(r.delay) / maxDelay
			weights[i] = 1.0 - frac*(1.0-minAccept)
		}
	}
	return names, weights
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

// fillProxies assembles the final candidate list with alive/blocked checks, debargo checks, and fallback.
func (s *Smart) fillProxies(target string, names []string, weights []float64, all []adapter.Outbound, minCount int, isUDP bool, unwrap bool) []adapter.Outbound {
	var blockedNodes map[string]bool
	if s.store != nil {
		blockedNodes, _ = s.store.GetBlockedNodes(s.Tag(), smartConfigName)
	}

	proxyByNamePtr := getStringOutboundMap()
	defer putStringOutboundMap(proxyByNamePtr)
	proxyByName := *proxyByNamePtr
	for _, ob := range all {
		proxyByName[ob.Tag()] = ob
	}

	var selected []adapter.Outbound
	for i, name := range names {
		ob := proxyByName[name]
		if ob == nil || blockedNodes[name] || !s.isAlive(name) || (isUDP && !s.supportsUDP(ob)) || s.isTargetDebargoed(target, name) {
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
	inNamedPtr := getStringBoolMap()
	defer putStringBoolMap(inNamedPtr)
	inNamed := *inNamedPtr
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
		sorted := false
		if ranking, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName); err == nil && len(ranking) > 0 {
			rankMapPtr := getStringFloatMap()
			rankMap := *rankMapPtr
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
			putStringFloatMap(rankMapPtr)
			sorted = true
		}
		if !sorted && s.history != nil {
			// Ranking cache not warmed yet — bias supplemental ordering by
			// URLTest delay so cold-start dials still prefer fast nodes over
			// a purely random shuffle (mihomo parity).
			delayMapPtr := getStringUint16Map()
			delayMap := *delayMapPtr
			anyDelay := false
			for _, ob := range filteredAll {
				if h := s.history.LoadURLTestHistory(ob.Tag()); h != nil && h.Delay > 0 {
					delayMap[ob.Tag()] = h.Delay
					anyDelay = true
				}
			}
			if anyDelay {
				sort.Slice(filteredAll, func(i, j int) bool {
					di, oki := delayMap[filteredAll[i].Tag()]
					dj, okj := delayMap[filteredAll[j].Tag()]
					if oki && okj {
						if di != dj {
							return di < dj
						}
						return filteredAll[i].Tag() < filteredAll[j].Tag()
					}
					return oki // nodes with a measured delay outrank unmeasured ones
				})
				sorted = true
			}
			putStringUint16Map(delayMapPtr)
		}
		if !sorted {
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
		if blockedNodes[ob.Tag()] || !s.isAlive(ob.Tag()) || (isUDP && !s.supportsUDP(ob)) || s.isTargetDebargoed(target, ob.Tag()) {
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
		// Last resort: any alive outbound not blocked for this target
		for _, ob := range all {
			if s.isAlive(ob.Tag()) && !s.isTargetDebargoed(target, ob.Tag()) {
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
// dialWithRetry drives the multi-round dial pipeline. Design priorities:
//
//  1. FAST FAILOVER. Round 0 races the top smartRound0Parallel (=2) nodes
//     in parallel so a broken primary costs us the WINNER's dial time,
//     not the loser's full timeout. Round 1+ moves the window further
//     down the candidate list in batches of smartParallelDials.
//
//  2. NO BACKOFF WHEN THE FAILURE WAS FAST. If the whole round failed in
//     <smartFastFailThreshold (200ms), the network is fine and only these
//     specific nodes are broken. Skipping the backoff lets us burn
//     through 3-4 bad candidates in under a second.
//
//  3. BACKOFF ONLY ON TRUE TIMEOUT. If the round exceeded its deadline,
//     the upstream path probably has congestion — a short jittered
//     backoff (20-80ms) helps avoid hammering a degraded network.
//
//  4. HOT RE-SELECTION. When every batch fails and we've exhausted the
//     candidate list, trigger a fresh selectProxiesTraced that respects
//     the freshly-tripped circuit breakers — the candidates we just
//     failed against are now excluded, so fresh alternatives surface.
func (s *Smart) dialWithRetry(ctx context.Context, network string, dest M.Socksaddr, outbounds []adapter.Outbound, meta *smartDialMeta) (net.Conn, string, int64, error) {
	var finalErr error
	reselectTried := false

	for i := 0; i < smartMaxRetries; i++ {
		batch, timeout := s.getBatch(outbounds, meta, i)
		if len(batch) == 0 {
			// Candidate list exhausted. One-time hot re-selection with
			// circuit-breakers now honoured — this is the "make sure the
			// node is usable, otherwise switch again" path.
			if !reselectTried {
				reselectTried = true
				snap := s.state.Load()
				if snap != nil && len(snap.outbounds) > 0 {
					// Pin-fallback detection: when the initial candidate
					// list is a SINGLE node matching the user's manual
					// pin AND it just failed to dial, we MUST escape the
					// pin short-circuit on this retry. Otherwise:
					//   - cbMaxConsecFail=2 means ONE failure leaves the
					//     breaker closed, so selectProxiesTraced keeps
					//     returning [pin]
					//   - sameOutboundSet sees identical list, declares
					//     "nothing fresh", breaks the retry loop
					//   - user sees "dial failed" on a truly-dead pin
					//     until they manually retry enough times to
					//     accumulate 2 failures and trip the breaker
					// Passing bypassManualPin=true for THIS dial only
					// sidesteps the pin path and gives the algorithm a
					// chance to surface alive nodes. The pin state is
					// untouched — the next user request still enters
					// the pin path first and snaps back the moment A
					// recovers. This complements (not conflicts with)
					// the breaker-based bypass: breakers catch repeated
					// failures for long-term pin unhealth; this catches
					// the FIRST failure on a newly-dead pin so the user
					// gets immediate service instead of a raw error.
					bypassPin := false
					if len(outbounds) == 1 {
						if pin := s.getManualSelected(); pin != "" && outbounds[0].Tag() == pin {
							bypassPin = true
						}
					}
					fresh, _, source := s.selectProxiesTracedOpts(meta, snap.outbounds,
						N.NetworkName(network) == N.NetworkUDP, bypassPin)
					if len(fresh) > 0 && !sameOutboundSet(outbounds, fresh) {
						if bypassPin {
							s.logger.InfoContext(ctx, "smart[", s.Tag(),
								"] pin [", outbounds[0].Tag(),
								"] failed; temporarily falling back to algorithm-selected candidates (source=",
								source, ", fresh=", proxyTagsPreview(fresh, 5),
								"); pin state preserved for future dials")
						} else {
							s.logger.DebugContext(ctx, "smart[", s.Tag(),
								"] hot re-selection after all candidates failed; fresh=",
								proxyTagsPreview(fresh, 5))
						}
						outbounds = fresh
						i = -1 // restart loop, round 0 on fresh set
						continue
					}
				}
			}
			break
		}

		s.logger.DebugContext(ctx, "smart[", s.Tag(), "] round ", i, " batch=",
			proxyTagsPreview(batch, 5), " timeout=", timeout)

		roundStart := time.Now()
		ctxDial, cancel := context.WithTimeout(ctx, timeout)
		conn, proxyTag, connectTime, err := s.parallelDial(ctxDial, network, dest, batch, meta)
		cancel()
		roundDur := time.Since(roundStart)

		if err == nil {
			return conn, proxyTag, connectTime, nil
		}
		finalErr = err

		// Decide whether to backoff. Fast failures (= not the round
		// timeout expiring) get NO backoff — we burn through candidates
		// immediately. Slow failures (timeout-based) get a short jittered
		// backoff to avoid thrashing a congested path.
		if i+1 < smartMaxRetries && roundDur >= timeout-10*time.Millisecond {
			// Round timed out — apply one jittered backoff before next round.
			base := smartBaseBackoff << i // exponential 20/40/80/160ms
			if base > 200*time.Millisecond {
				base = 200 * time.Millisecond
			}
			jitter := 1.0 + (rand.Float64()*2-1)*0.2
			delay := time.Duration(float64(base) * jitter)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, "", 0, ctx.Err()
			}
		}
	}

	return nil, "", 0, E.New("smart: all retries failed: ", finalErr)
}

// sameOutboundSet is a cheap inequality check — if the tags and order match,
// hot re-selection found the same list and there's no point retrying.
func sameOutboundSet(a, b []adapter.Outbound) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Tag() != b[i].Tag() {
			return false
		}
	}
	return true
}

// getBatch returns the batch for retry round i and the dial timeout.
//
// Round 0 races smartRound0Parallel top candidates instead of dialing
// solo — the minor parallel-dial overhead (wasted connect attempt on
// the loser) is more than paid back when the top candidate is broken
// and we'd otherwise eat its full timeout before retrying.
func (s *Smart) getBatch(outbounds []adapter.Outbound, meta *smartDialMeta, round int) ([]adapter.Outbound, time.Duration) {
	var batch []adapter.Outbound
	if round == 0 {
		// Algorithm decides the race width: selection-style algorithms
		// (sticky / RR / p2c / weighted-random) already chose ONE
		// specific node, so racing a second candidate would discard
		// that choice on the loser dial. Ranking-style algorithms
		// keep the legacy 2-wide race for fast-failover.
		n := s.algoRound0Width()
		// Adaptive narrowing: when the ranking algorithm picked a
		// top candidate with a VERY high short-window success rate,
		// spend only one dial slot on it — the parallel race buys
		// almost nothing when the lead is reliable, and the wasted
		// concurrent dial on position 1 burns CPU / battery and
		// pollutes upstream stats with loser failures. Below 95%
		// short success rate we keep the original race width.
		//
		// Only applied to ranking-style algos (width > 1); selection
		// algos already return 1 from algoRound0Width.
		if n > 1 && len(outbounds) > 0 {
			sr := s.shortSuccessRateFor(outbounds[0].Tag())
			if sr >= 0.95 {
				n = 1
			}
		}
		if n > len(outbounds) {
			n = len(outbounds)
		}
		if n > 0 {
			batch = outbounds[:n]
		}
	} else {
		// Rounds 1+ advance further down the ranked list in batches.
		begin := smartRound0Parallel + (round-1)*smartParallelDials
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
// their failure recorded against the real meta so weight history updates,
// AND their circuit breaker gets incremented — two failures within cbWindow
// opens the breaker so the node is skipped by future selections until the
// cooldown expires. This is the "真正的smart" fast-demotion path.
func (s *Smart) parallelDial(ctx context.Context, network string, dest M.Socksaddr, outbounds []adapter.Outbound, meta *smartDialMeta) (net.Conn, string, int64, error) {
	if len(outbounds) == 1 {
		start := time.Now()
		conn, err := outbounds[0].DialContext(ctx, network, dest)
		ct := time.Since(start).Milliseconds()
		if err != nil && err != context.Canceled && !errors.Is(err, context.Canceled) {
			tag := outbounds[0].Tag()
			if s.recordDialFailure(tag) {
				s.logger.DebugContext(ctx, "smart[", s.Tag(), "] circuit-breaker OPEN for [", tag,
					"] after ", cbMaxConsecFail, " consecutive failures in ", cbWindow)
			}
			ct2, tag2, meta2 := ct, tag, meta
			getSmartWorker().submit(func() { s.recordFailedDial(tag2, meta2, ct2) })
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
			if s.recordDialFailure(r.tag) {
				s.logger.DebugContext(ctx, "smart[", s.Tag(), "] circuit-breaker OPEN for [", r.tag,
					"] after ", cbMaxConsecFail, " consecutive failures in ", cbWindow)
			}
			rtag, rct, rmeta := r.tag, r.connectTime, meta
			getSmartWorker().submit(func() { s.recordFailedDial(rtag, rmeta, rct) })
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
	currentFirstByteTimeout time.Duration
	firstReadOnce  atomic.Bool
	firstReadMs    atomic.Int64   // latency in ms from dial-success
	firstReadErr   atomic.Pointer[error]
	firstWriteOnce atomic.Bool
	firstWriteErr  atomic.Pointer[error]

	// lastIOErr is the most recent non-nil error observed on Read or
	// Write, regardless of whether the conn had already produced bytes.
	// Fills the gap firstReadErr/firstWriteErr leave open: once the
	// conn produces its first byte, firstReadOnce flips to true and
	// firstReadErr is never written again — so a mid-transfer
	// ECONNRESET after a successful TLS ServerHello wouldn't be seen
	// by classifyStatus and Close would mis-classify the conn as
	// "closed" (clean) instead of "failed" (RST). Updating lastIOErr
	// on every error surfaces the truth to the Close path.
	//
	// Stored as *error (atomic.Pointer) so the read side can do one
	// Load without taking a mutex on the hot IO path. Load returns nil
	// when no error has ever been observed.
	lastIOErr atomic.Pointer[error]

	// lastReadAt is the unix-nano timestamp of the most recent successful
	// Read (n > 0). Drives the stalled-transfer watchdog: when a conn
	// has data but stops moving for stalledTransferTimeout the watchdog
	// force-closes it and triggers an algorithm-aware node switch.
	// 0 means no successful read yet — first-byte watchdog handles that.
	lastReadAt atomic.Int64

	// watchdogTriggered guards against double-handling when the
	// watchdog and a natural close race. Set the moment the watchdog
	// decides to evict the conn so the close path's recordStats
	// classifies it as failed even though Conn.Close was caller-initiated.
	watchdogTriggered atomic.Bool

	// peak byte-rate tracking (sampled on each IO call)
	rateMu        sync.Mutex
	rateLastTime  time.Time
	rateLastUp    int64
	rateLastDown  int64
	maxUpBps      atomic.Int64
	maxDownBps    atomic.Int64
	// nextSampleNS is a lock-free short-circuit for sampleRate: it stores
	// the earliest unix-nano at which a new sample should be taken
	// (rateLastTime + 1s). Every Read/Write compares time.Now() against
	// it atomically — only when the budget is actually reached do we
	// acquire rateMu. On a fast stream this cuts the per-IO overhead
	// from one mutex-acquire to one atomic-load.
	nextSampleNS atomic.Int64

	closeOnce sync.Once
}

func (c *smartTrackedConn) Read(b []byte) (int, error) {
	// Capture the pre-CAS state so the pre-first-byte fatal-error
	// branch below can tell whether THIS Read is the one that's
	// supposed to deliver the first byte. Using firstReadOnce.Load()
	// after the CAS would always observe true and miss the case.
	wasPreFirstByte := !c.firstReadOnce.Load()
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.download.Add(int64(n))
		// Stamp last-active for the stalled-transfer watchdog. Atomic
		// store on every payload Read is cheap; the watchdog reads it
		// at most once per scan tick.
		c.lastReadAt.Store(time.Now().UnixNano())
	}
	firstByteJustNow := false
	if c.firstReadOnce.CompareAndSwap(false, true) {
		c.firstReadMs.Store(time.Since(c.startTime).Milliseconds())
		if err != nil {
			e := err // copy to heap before pointer-atomic Store
			c.firstReadErr.Store(&e)
		} else if n > 0 {
			firstByteJustNow = true
		}
	}
	// Always surface the latest error to lastIOErr — firstReadErr only
	// captures the first-byte instant; mid-transfer errors land here so
	// classifyStatus can see them at Close.
	if err != nil {
		e := err
		c.lastIOErr.Store(&e)
	}
	// Real-time RST detection. Three layered triggers:
	//
	//   - isPreFirstByteFatal: the conn NEVER produced a payload byte
	//     and Read returned a non-EOF error. Pre-first-byte semantics
	//     let us be aggressive — we already waited firstByteWatchdog
	//     for a byte, anything other than clean EOF means the node
	//     didn't deliver.
	//
	//   - isTransferFatalErr: after first-byte, the conn got a wider
	//     set of "dirty RST" errors — TLS record-layer damage, h2
	//     stream reset / non-graceful GOAWAY, QUIC CRYPTO_ERROR /
	//     CONNECTION_CLOSE, mux protocol framing errors. These all
	//     signal upstream disruption at the proxy-stack layer when
	//     the raw syscall errno is lost in translation. isTransferFatalErr
	//     includes isResetErr so the classic kernel-level RST path
	//     is still covered when it reaches mid-transfer.
	//
	// All triggers funnel through the CAS-guarded
	// triggerInstantResetEviction so a follow-up Write(EPIPE) or
	// Close(reset) can't double-handle the same conn.
	if err != nil {
		switch {
		case wasPreFirstByte && isPreFirstByteFatal(err):
			c.s.triggerInstantResetEviction(c, "read-prefirst", err)
		case isTransferFatalErr(err):
			c.s.triggerInstantResetEviction(c, "read", err)
		}
	}
	// Kernel-driven watchdog: Read returned a deadline-style timeout.
	// Decide between (a) a genuine stall (no recent activity) → trigger
	// the same eviction sequence as a TCP RST so the algorithm picks
	// a different node on the very next dial; or (b) a benign deadline
	// fire (we just had real bytes a moment ago — the deadline simply
	// hasn't been re-armed yet) → push the deadline forward and let
	// the caller decide whether to retry. This is the "极速响应"
	// path: the trigger fires the instant the kernel observes the
	// stall, no goroutine sleep / wakeup involved.
	if err != nil && isWatchdogDeadlineErr(err) && !c.watchdogTriggered.Load() {
		lastNS := c.lastReadAt.Load()
		idle := time.Since(c.startTime)
		if lastNS != 0 {
			idle = time.Since(time.Unix(0, lastNS))
		}
		genuineStall := !c.firstReadOnce.Load() ||
			idle >= stalledTransferTimeout-stalledTransferGrace
		if genuineStall && c.watchdogTriggered.CompareAndSwap(false, true) {
			c.s.logger.Warn("smart[", c.s.Tag(), "] kernel watchdog evicting [",
				c.proxyTag, "] target=[", c.meta.smartTarget,
				"] reason=", classifyWatchdogStall(c), " idle=", idle.Truncate(time.Millisecond))
			// Don't close the conn here — the caller will hit our
			// Close() through their normal flow once Read returns,
			// and that path runs recordStats. We DO need to fire
			// the eviction so the breaker / unwrap-cache / ranking
			// catch up before the user's next dial.
			c.s.handleResetThresholdCrossed(c.meta, c.proxyTag)
		} else if !genuineStall {
			// Push the deadline forward and let the read loop retry.
			c.rearmTransferStalledDeadline()
		}
	}
	if firstByteJustNow {
		c.armTransferStalledDeadline()
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
	// Mirror Read: every Write error (not only the first) must surface
	// to lastIOErr so classifyStatus sees the real reason on Close.
	if err != nil {
		e := err
		c.lastIOErr.Store(&e)
	}
	// Symmetric to Read: a Write returning EPIPE / ECONNRESET / etc
	// means the kernel has already torn down the socket on its end.
	// Fire the same instant-eviction path so the next dial sees the
	// new selection without waiting for the caller's Close.
	if err != nil && isResetErr(err) {
		c.s.triggerInstantResetEviction(c, "write", err)
	}
	c.sampleRate()
	return n, err
}

// sampleRate updates maxUpBps / maxDownBps when at least 1 second has elapsed
// since the last sample. Hot path on every Read/Write — a lock-free atomic
// short-circuit keeps the common case (dt<1s) to a single atomic-load. Only
// once per second do we enter the mutex critical section to refresh the
// counters.
func (c *smartTrackedConn) sampleRate() {
	nowNS := time.Now().UnixNano()
	next := c.nextSampleNS.Load()
	if next != 0 && nowNS < next {
		return
	}
	// Claim the sampling slot: whoever wins the CAS actually does the
	// sample; late callers in the same second see the updated next and
	// return on the fast-path above.
	if next != 0 && !c.nextSampleNS.CompareAndSwap(next, nowNS+int64(time.Second)) {
		return
	}
	c.rateMu.Lock()
	now := time.Unix(0, nowNS)
	if c.rateLastTime.IsZero() {
		c.rateLastTime = c.startTime
	}
	dt := now.Sub(c.rateLastTime).Seconds()
	if dt < 1.0 {
		// Another caller raced us and already refreshed; just make sure
		// nextSampleNS points past the freshly-sampled moment.
		newNext := c.rateLastTime.Add(time.Second).UnixNano()
		c.nextSampleNS.Store(newNext)
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
	c.nextSampleNS.Store(nowNS + int64(time.Second))
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
	// Priority: the latest mid-transfer error beats the first-byte
	// snapshot. A conn that produced bytes cleanly and then hit RST at
	// byte 500k must NOT be reported as "closed" — that's how broken
	// nodes leak past the eviction path.
	if p := c.lastIOErr.Load(); p != nil {
		e := *p
		// io.EOF / io.ErrUnexpectedEOF are clean half-closes — well,
		// EOF is. ErrUnexpectedEOF on upstream can mean "RST cut the
		// stream", but since downstream libraries routinely paper
		// over it we keep the older semantics: treat as "closed" here
		// so we don't over-trigger on legitimate stream ends.
		if errors.Is(e, io.EOF) {
			// Fall through to first-byte-snapshot logic so a clean
			// EOF with an earlier firstWriteErr still surfaces.
		} else {
			return "failed", e
		}
	}
	var rErr, wErr error
	if p := c.firstReadErr.Load(); p != nil {
		rErr = *p
	}
	if p := c.firstWriteErr.Load(); p != nil {
		wErr = *p
	}
	if rErr == nil {
		if wErr != nil && !errors.Is(wErr, io.EOF) {
			return "failed", wErr
		}
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
		// Clear the kernel watchdog deadline before any post-close
		// cleanup so a stale deadline doesn't surface as a spurious
		// timeout during downstream EOF propagation.
		c.clearReadDeadline()
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

			// Upstream-initiated reset detection. The Read/Write paths
			// already fire the eviction the moment the kernel returns
			// the error — `triggerInstantResetEviction` is idempotent
			// via CAS, so this Close-time call is just a safety net
			// for transports that surface RST only at close (rare:
			// some mux layers buffer the error until session cleanup).
			// Use the wider isTransferFatalErr here so TLS / h2 /
			// QUIC / protocol-framing errors that the narrower
			// isResetErr misses still get caught at close.
			if c.meta != nil && isTransferFatalErr(reason) {
				c.s.triggerInstantResetEviction(c, "close", reason)
			}
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

		cs, meta, tag, ctime := c.s, c.meta, c.proxyTag, c.connectTime
		statusCopy := status
		latCopy, upCopy, downCopy, muCopy, mdCopy, durCopy := latency, up, down, maxUpBps, maxDownBps, durMS
		getSmartWorker().submit(func() {
			cs.recordStats(statusCopy, meta, tag, ctime,
				latCopy, upCopy, downCopy, muCopy, mdCopy, durCopy)
		})
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
	nextSampleNS atomic.Int64

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
	nowNS := time.Now().UnixNano()
	next := c.nextSampleNS.Load()
	if next != 0 && nowNS < next {
		return
	}
	if next != 0 && !c.nextSampleNS.CompareAndSwap(next, nowNS+int64(time.Second)) {
		return
	}
	c.rateMu.Lock()
	now := time.Unix(0, nowNS)
	if c.rateLastTime.IsZero() {
		c.rateLastTime = c.startTime
	}
	dt := now.Sub(c.rateLastTime).Seconds()
	if dt < 1.0 {
		c.nextSampleNS.Store(c.rateLastTime.Add(time.Second).UnixNano())
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
	c.nextSampleNS.Store(nowNS + int64(time.Second))
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
		cs, meta, tag, ctime := c.s, c.meta, c.proxyTag, c.connectTime
		latCopy, upCopy, downCopy, muCopy, mdCopy, durCopy := latency, up, down, maxUpBps, maxDownBps, durMS
		getSmartWorker().submit(func() {
			cs.recordStats("closed", meta, tag, ctime,
				latCopy, upCopy, downCopy, muCopy, mdCopy, durCopy)
		})
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
	// Arm the kernel-level read deadline so a silent node returns
	// from the very next Read instead of hanging until the kernel /
	// TLS timeout. This is the "real-time" detection path — the
	// periodic watchdog is just a backstop for transports that
	// silently ignore SetReadDeadline.
	tracked.applyFirstByteDeadline()
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
// Also bumps the global per-node load counter consulted by the
// least-loaded algorithm — kept in lock-step with deregisterTargetConn
// so the count stays accurate across the conn lifetime.
func (s *Smart) registerTargetConn(target string, c *smartTrackedConn) {
	if target == "" {
		return
	}
	s.targetConnsMu.Lock()
	set := s.targetConns[target]
	if set == nil {
		set = make(map[*smartTrackedConn]struct{})
		s.targetConns[target] = set
	}
	if _, dup := set[c]; !dup {
		set[c] = struct{}{}
		s.targetConnsCount.Add(1)
	}
	s.targetConnsMu.Unlock()
	if s.nodeLoad != nil {
		s.nodeLoad.inc(c.proxyTag)
	}
}

// deregisterTargetConn removes a tracked conn from the registry at Close time.
func (s *Smart) deregisterTargetConn(target string, c *smartTrackedConn) {
	if target == "" {
		return
	}
	s.targetConnsMu.Lock()
	if set := s.targetConns[target]; set != nil {
		if _, exists := set[c]; exists {
			delete(set, c)
			s.targetConnsCount.Add(-1)
		}
		if len(set) == 0 {
			delete(s.targetConns, target)
		}
	}
	s.targetConnsMu.Unlock()
	if s.nodeLoad != nil {
		s.nodeLoad.dec(c.proxyTag)
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
		cntCopy := cnt
		getSmartWorker().submit(func() {
			defer s.recheckOnce.Store(false)
			s.logger.Info("smart[", s.Tag(), "] accumulated ", cntCopy,
				" dial failures in short window; triggering emergency prefetch refresh")
			s.runPrefetch()
		})
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

	// Hot-patch ML features for domain-only requests (e.g. AsIs strategy where 
	// IP resolution is deferred to the remote endpoint).
	// Without this, LightGBM features 16 (ASN) and 17 (GeoIP) are zero-filled.
	// Since recordStats runs post-connection, we can afford a tiny 200ms 
	// lookup block to drastically improve ML model accuracy and CSV collection.
	if len(meta.resolvedIPs) == 0 && meta.host != "" && (s.useASN || s.useLightGBM || s.collectData) {
		if dnsRouter := service.FromContext[adapter.DNSRouter](s.ctx); dnsRouter != nil {
			lookupCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			if ips, err := dnsRouter.Lookup(lookupCtx, meta.host, adapter.DNSQueryOptions{}); err == nil && len(ips) > 0 {
				meta.resolvedIPs = ips
				meta.asnCode = s.lookupASN(ips)
				meta.destGeoIP = s.lookupCountry(ips)
			}
			cancel()
		}
	}

	// recordPinEndorsement logic moved below record initialisation

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

	if s.getManualSelected() == proxyTag {
		s.recordPinEndorsement(proxyTag, meta, status != "failed", record.ShortRTT())
	}

	if connectTime > 0 {
		old := record.GetInt64("connectTime")
		record.SetInt64("connectTime", smart.UpdateAverageInt(old, connectTime))
		// Feed Welford accumulator so jitter (stddev) is available at
		// weight-compute time. This tracks distribution, not just mean.
		record.UpdateConnectTimeSample(connectTime)
	}
	if latency > 0 {
		old := record.GetInt64("latency")
		record.SetInt64("latency", smart.UpdateAverageInt(old, latency))
		record.UpdateLatencySample(latency)
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

	// Inject dynamic Pin-Endorsement Learning contextual boost!
	// Without this, the LightGBM data collection mechanism and offline model
	// prediction are completely blind to user's habitual routing pins.
	priorityFactor *= s.applyPinEndorsementBoost(proxyTag, meta, float64(latency))

	// Manual-pin learning: user explicitly chose this node, so treat
	// every sample as carrying extra confidence. Multiplied onto
	// priorityFactor BEFORE CalculateWeight / PredictWeight so both
	// traditional and ML paths see the uplift, and the uplift persists
	// into the stored finalWeight — ensuring that when the user later
	// unpins, the auto-selector biases toward the previously-pinned
	// node rather than acting as if the pin never happened.
	//
	// Training target math below divides priorityFactor back out, so
	// LightGBM does NOT learn pin-biased labels — we want the model to
	// learn the raw algorithmic signal and let runtime priority factors
	// (including this boost) compose on top at selection time.
	isPinnedDial := s.getManualSelected() == proxyTag
	if isPinnedDial {
		priorityFactor *= manualPinWeightBoost
	}

	// Pool-acquired ModelInput — eliminates ~512-byte allocation per
	// closed connection. Released at end of recordStats; the async
	// dataCollector path takes a stack-local copy before submit.
	// Snapshot std-dev + first-difference together so the trend signal is
	// taken at the same instant as the absolute value (avoids torn reads
	// when another goroutine updates the variance between two RPCs).
	ctStdDev, ctStdDevDelta := record.ConnectTimeStdDevAndDelta()
	latStdDev, latStdDevDelta := record.LatencyStdDevAndDelta()

	input := smart.AcquireModelInput()
	*input = smart.ModelInput{
		Success:                record.GetInt64("success"),
		Failure:                record.GetInt64("failure"),
		ConnectTime:            record.GetInt64("connectTime"),
		Latency:                record.GetInt64("latency"),
		ConnectTimeStdDev:      ctStdDev,
		LatencyStdDev:          latStdDev,
		FirstByteLatency:       latency,
		ShortRTT:               record.ShortRTT(),
		ShortSuccessRate:       record.ShortSuccessRate(),
		IsUDP:                  meta.isUDP,
		IsTCP:                  !meta.isUDP,
		UploadTotal:            uploadMB,
		HistoryUploadTotal:     historyUploadTotal,
		MaxuploadRate:          maxUpKB,
		HistoryMaxUploadRate:   historyMaxUploadRate,
		DownloadTotal:          downloadMB,
		HistoryDownloadTotal:   historyDownloadTotal,
		MaxdownloadRate:        maxDownKB,
		HistoryMaxDownloadRate: historyMaxDownloadRate,
		ConnectionDuration:     record.GetFloat64("duration"),
		LastUsed:               record.GetInt64("lastUsed"),
		DestIPASN:              meta.asnCode,
		Host:                   meta.host,
		DestIP:                 firstValidIPString(meta.resolvedIPs),
		DestPort:               meta.destPort,
		DestGeoIP:              meta.destGeoIP,
		GroupName:              s.Tag(),
		NodeName:               proxyTag,

		// xiaobaf14g v2 extended dimensions — strategy / collector only.
		LatencyStdDevDelta:     latStdDevDelta,
		ConnectTimeStdDevDelta: ctStdDevDelta,
		ActiveConns:            int32(s.nodeLoad.get(proxyTag)),
		// HTTP3FallbackCount / LightGBMConfidence / HourBucket / HourFrequency
		// are filled in by their respective subsystems below — left zero here
		// so the assignment above remains a single self-contained literal.
	}
	// Enrich with the last URLTest phase-timing detail cached by
	// smartSharedWorker (see smart_shared.go LastProbeDetail). Cold-start
	// and probe-failure paths return ok=false → fields stay zero.
	if detail, ok := getSmartWorker().LastProbeDetail(proxyTag); ok {
		input.DNSResolveTime = detail.DNSResolveMS
		input.TLSHandshakeTime = detail.TLSHandshakeMS
		input.TLSSessionResumed = detail.DidResume
		// xiaobaf14g v3 TCP-kernel signals — filled only when the probe
		// reached a real fd (Linux direct outbounds and similar). Zero on
		// every other platform / wrapped proxy conn, documented as
		// "unknown" at the ModelInput level.
		input.TCPRetransmissions = detail.TCPRetransmissions
		input.TCPLosses = detail.TCPLosses
		input.PathMTU = detail.PathMTU
	}
	// Time-of-day signal: HourBucket lets the strategy / collector slice
	// success/failure stats by 24 hour-of-day buckets (catches "this node
	// is great off-peak but melts during local rush hour" patterns).
	// HourFrequency stays 0 in v2 because that needs a per-group cross-node
	// comparison cache; the field is shipped now so the v2 collector CSV
	// is forward-compatible with the v2.1 implementation.
	input.HourBucket = int8(time.Now().Hour())
	input.HTTP3FallbackCount = s.http3FallbackCount(proxyTag)
	// Long-horizon EWMA companions to ShortRTT / ShortSuccessRate. Cold-
	// start (no samples) returns 0 — strategies must guard against that.
	input.LongRTT = record.LongRTT()
	input.LongSuccessRate = record.LongSuccessRate()
	defer smart.ReleaseModelInput(input)

	// ML prediction path (LightGBM) with automatic fallback to traditional algorithm.
	var calculatedWeight float64
	var mlPredicted bool
	if s.useLightGBM && s.weightModel != nil && s.weightModel.IsLoaded() {
		var conf float64
		calculatedWeight, mlPredicted, conf = s.weightModel.PredictWeight(input, priorityFactor)
		// Surface inter-tree agreement to strategies (and the v2 collector
		// CSV) so downstream code can decide whether to trust this weight.
		input.LightGBMConfidence = conf
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
		// Tag user-endorsed samples so retraining can weight them
		// distinctly (or filter them out for a pure-algorithmic model).
		// The suffix preserves the weight-computation channel — a grep
		// for `lightgbm` / `traditional` still groups everything.
		if isPinnedDial {
			source += ":manual"
		}
		baseWeight := finalWeight
		if priorityFactor > 0 {
			baseWeight = finalWeight / priorityFactor
		}
		cmeta := &lightgbm.CollectorMeta{
			DestASN:   meta.asnCode,
			Host:      meta.host,
			DestPort:  meta.destPort,
			DestGeoIP: meta.destGeoIP,
		}
		for _, ip := range meta.resolvedIPs {
			if ip.IsValid() {
				cmeta.DestIP = ip.String()
				break
			}
		}
		// Route sample collection through the shared ants pool so a high-
		// throughput config doesn't spawn thousands of goroutines.
		// Must COPY the ModelInput by value — `input` gets released back
		// to the pool when recordStats returns (via defer), and the
		// async goroutine can't hold a reference to pooled memory.
		inputSnap := *input
		cmetaCopy, w, srcCopy := cmeta, baseWeight, source
		getSmartWorker().submit(func() {
			s.dataCollector.AddSample(&inputSnap, cmetaCopy, w, srcCopy)
		})
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
	// msgpack instead of JSON — ~3× smaller per record on disk and in
	// the pending-write queue. The read path (UnmarshalStatsRecord)
	// sniffs the first byte and still handles legacy JSON rows.
	data, err := smart.MarshalStatsRecord(snapshot)
	smart.ReleaseStatsRecord(snapshot) // safe: marshal copies bytes
	if err == nil {
		// AppendToGlobalQueue is O(1) and takes a short mutex; routing
		// through the shared pool bounds concurrency so the burst of
		// N closed conns doesn't spawn N goroutines simultaneously.
		op := smart.StoreOperation{
			Type:   smart.OpSaveStats,
			Group:  s.Tag(),
			Config: smartConfigName,
			Target: target,
			Node:   proxyTag,
			Data:   data,
		}
		getSmartWorker().submit(func() {
			s.store.AppendToGlobalQueue(op)
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

// runHealthCheck actively probes every outbound and writes the result into
// URLTestHistoryStorage. This populates the isAlive/selectFullScan/ranking
// inputs. Without it, a standalone Smart group has no idea which of its
// members are actually reachable.
//
// Concurrency + de-duplication is delegated to the process-wide
// smartSharedWorker:
//
//   - singleflight collapses concurrent probes of the SAME node tag
//     across all Smart groups into a single HTTP request. A node shared
//     by 16 groups used to be probed 16 times per interval — now once.
//
//   - ants.Pool caps total concurrent probe goroutines to 64 across the
//     whole process so a "all-groups tick at once" burst doesn't thrash
//     the CPU / test-URL host.
//
//   - 1-second freshness cache short-circuits back-to-back identical
//     probes even across sequential calls (singleflight only dedupes
//     concurrent in-flight requests).
func (s *Smart) runHealthCheck() {
	if s.history == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return
	}

	worker := getSmartWorker()
	ctx, cancel := context.WithTimeout(s.taskCtx, s.interval)
	defer cancel()

	var wg sync.WaitGroup
	start := time.Now()

	var alive, dead, skipped atomic.Int32
	// Freshness window = max(configured interval, 5 min). A node is
	// considered fresh if EITHER:
	//   1. URLTestHistory has a recent probe entry (real measured latency
	//      that the dashboard displays), OR
	//   2. aliveAt has a recent dial-heartbeat timestamp (real traffic
	//      successfully routed through this node recently — no need to
	//      re-verify via an HTTP probe).
	// Cuts Android CPU/network by ~80% during active browsing because
	// dial-heartbeats obviate most scheduled probes.
	freshWindow := s.interval
	if freshWindow < 5*time.Minute {
		freshWindow = 5 * time.Minute
	}
	freshWindowNS := int64(freshWindow)
	nowNS := time.Now().UnixNano()
	for _, ob := range snap.outbounds {
		ob := ob
		tag := ob.Tag()
		if smartSkipType(ob.Type()) {
			continue
		}
		// Check #2 first — dial heartbeats are cheapest to consult and
		// most authoritative (a real TCP handshake just succeeded).
		if ts, ok := s.aliveAt.Load(tag); ok && nowNS-ts < freshWindowNS {
			alive.Add(1)
			skipped.Add(1)
			continue
		}
		if h := s.history.LoadURLTestHistory(tag); h != nil && time.Since(h.Time) < freshWindow {
			if h.Delay > 0 {
				alive.Add(1)
				skipped.Add(1)
			}
			continue
		}

		wg.Add(1)
		worker.submit(func() {
			defer wg.Done()

			probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
			delay, err := worker.probeOnce(probeCtx, s.testURL, ob)
			probeCancel()

			if err != nil || delay == 0 {
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
		})
	}
	wg.Wait()

	s.logger.Info("smart[", s.Tag(), "] health-check in ",
		time.Since(start).Round(time.Millisecond), ": ",
		alive.Load(), " alive, ", dead.Load(), " dead, ",
		skipped.Load(), " skipped (fresh via recent dial)")
}

// cleanupOrphanedGroups removes Smart store data for group tags that no
// longer exist in the live outbound manager. Handles the case where a user
// renames / removes a Smart group between runs — without this the bbolt
// bucket grows unbounded.
//
// Gated process-wide: the list of "live groups" is identical from every
// Smart's point of view (they all query the same outboundMgr), so
// running this per-group scans the bbolt store N times for no benefit.
// On Android where every bbolt scan reads mmap pages into memory, this
// matters for RSS stability.
func (s *Smart) cleanupOrphanedGroups() {
	if s.store == nil {
		return
	}
	if !claimGlobalTask("cleanup-orphan-groups", globalCleanupOrphanGroupsInterval) {
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
		if _, err := s.store.FlushByGroup(g, smartConfigName); err != nil {
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

	tags := snap.tags

	// mihomo-parity shortcut: skip ranking recompute when we already have
	// a recent cache that covers every current proxy and contains no dead
	// ranked node. Saves bbolt scans on every tick in steady-state.
	if cached, err := s.store.GetNodeWeightRankingCache(s.Tag(), smartConfigName); err == nil && len(cached) > 0 {
		nowUnix := time.Now().Unix()
		cacheAge := time.Duration(nowUnix-cached[0].LastUpdated) * time.Second

		if cacheAge < 30*time.Minute {
			ranked := make(map[string]bool, len(cached))
			for _, r := range cached {
				ranked[r.Name] = true
			}
			hasUnranked := false
			for _, t := range tags {
				if !ranked[t] {
					hasUnranked = true
					break
				}
			}
			hasDeadRanked := false
			for _, r := range cached {
				if r.Rank != smart.RankRarelyUsed && !s.isAlive(r.Name) {
					hasDeadRanked = true
					break
				}
			}
			// Cache is still authoritative iff the proxy set matches and
			// no top-ranked node has gone dead, OR the cache is still fresh.
			if !hasUnranked && (!hasDeadRanked || cacheAge <= 10*time.Minute) {
				return
			}
		}
	}

	start := time.Now()
	ranking, err := s.store.GetNodeWeightRanking(s.Tag(), smartConfigName, s.testURL, s.isAlive, tags)
	if err != nil {
		s.logger.Debug("smart[", s.Tag(), "] ranking update failed: ", err)
		return
	}

	// Empty ranking during cold-start is EXPECTED (mihomo parity): the
	// prefetch chain needs per-target history, which accumulates only as
	// traffic flows. WeightRanking() handles the API surface with a live
	// stats-based fallback, so this path just skips the persisted ranking
	// write until we have real aggregated data. Log once per process so
	// operators see the state without spam.
	if len(ranking) == 0 {
		if s.coldStartLogged.CompareAndSwap(false, true) {
			s.logger.Debug("smart[", s.Tag(),
				"] no prefetch-derived ranking yet; /weights serving live stats fallback until the first prefetch cycle completes")
		}
		// Even when prefetch hasn't yielded data, GetLiveNodeRanking can
		// often produce a real ranking from the raw stats table. Cache
		// that in the snapshot so /weights doesn't keep re-scanning
		// allStats on every dashboard refresh.
		if live := s.store.GetLiveNodeRanking(s.Tag(), smartConfigName, s.isAlive, tags); len(live) > 0 {
			s.publishRankingSnapshot(live)
		}
		return
	}
	// Prefetch-derived ranking is ready: publish to the in-process
	// snapshot BEFORE the bbolt write so WeightRanking sees the new
	// data immediately instead of waiting for BatchSave to flush.
	s.publishRankingSnapshot(ranking)
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
	s.logger.Info("smart[", s.Tag(), "] ranking updated in ", time.Since(start).Round(time.Millisecond),
		": ", len(ranking), " nodes (most=", most, " occasional=", occ,
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
	// A 0-count prefetch during cold start just means no traffic has closed
	// through this group yet — expected, not an error. The /weights endpoint
	// uses the URLTest-delay fallback in WeightRanking to stay non-empty.
	// Demote the log to Debug so operators only see it when they're
	// actively diagnosing, not on every warm-up cycle.
	if count == 0 {
		s.logger.Debug("smart[", s.Tag(), "] prefetch completed in ", time.Since(start).Round(time.Millisecond),
			": 0 targets (no closed connections yet; /weights serving delay-based ranking) alive=", alive, " skipped=", skipped)
		return
	}
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

// displayTarget renders a human-readable target for log output. When the
// Smart-effective target is empty (rare: both Destination.Fqdn and all IPs
// absent), falls back to the socksaddr string so the log still pinpoints
// the destination the user is trying to reach.
func displayTarget(meta *smartDialMeta, dest M.Socksaddr) string {
	if meta != nil && meta.smartTarget != "" {
		return meta.smartTarget
	}
	if dest.IsValid() {
		return dest.String()
	}
	return "unknown"
}

// displayASN renders the ASN code for logging, using a placeholder when
// unavailable so the field is never an empty "[]" hint.
func displayASN(meta *smartDialMeta) string {
	if meta == nil || meta.asnCode == "" {
		return "[none]"
	}
	return "[" + meta.asnCode + "]"
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

// flushQueue runs the shared bbolt write-flush. Gated to once-per-interval
// process-wide — the queue is global, so N Smart groups all calling this
// would race to drain the same data. First caller wins; rest return
// immediately without paying the mutex cost.
func (s *Smart) flushQueue() {
	if s.store == nil {
		return
	}
	if !claimGlobalTask("flush-queue", globalFlushQueueInterval) {
		return
	}
	s.store.FlushQueue(true)
}

// adjustCache sizes the process-wide LRU caches based on heap pressure.
// Gated to once-per-interval across all groups because:
//  1. The caches are process-global, so only one resize is meaningful.
//  2. runtime.ReadMemStats is a STW operation. Running it 16 times per
//     5-min interval = 16 stop-the-world pauses. On Android that's a
//     direct UX cost. Gating cuts it to 1 STW per interval.
func (s *Smart) adjustCache() {
	if s.store == nil {
		return
	}
	if !claimGlobalTask("cache-adjust", globalCacheAdjustInterval) {
		return
	}
	s.store.AdjustCacheParameters()
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
	// Source 0 (freshest): circuit breaker. A dial failure is newer
	// evidence than URLTest history, so honour the breaker first.
	if s.isBreakerOpen(tag) {
		return false
	}
	// Source 1: known-dead set. xsync Load is lock-free on the hot path.
	if deadAt, isDead := s.knownDead.Load(tag); isDead {
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

// circuitBreakerState tracks per-node failure state for the
// fast-failover pipeline. All fields are atomic — reads from the dial
// hot path are lock-free.
//
// State machine:
//
//	Closed   : openUntil == 0, consecFails may be accumulating in the
//	           current streak window.
//	Open     : openUntil != 0, now <  openUntil. isOpen() returns true.
//	HalfOpen : openUntil != 0, now >= openUntil. isOpen() returns false
//	           (allowing one trial dial). A trial failure calls
//	           recordFailure which detects the half-open condition and
//	           re-trips with escalated backoff; a trial success is
//	           usually surfaced via markAlive → reset().
//
// tripCount is the consecutive-trip counter used for exponential
// backoff: every trip within the same "open-period chain" (i.e.
// without an intervening reset() via markAlive) escalates the
// cooldown by 2× up to an 8× cap. Combined with ±20 % jitter, this
// prevents a flapping node from pinning down the selector at exactly
// cbOpenDuration and also avoids a herd of nodes recovering
// simultaneously after a shared outage.
type circuitBreakerState struct {
	consecFails atomic.Int32 // consecutive failures since last success
	firstFailAt atomic.Int64 // unix-nano of first failure in current streak
	openUntil   atomic.Int64 // unix-nano; non-zero = breaker has been tripped at least once
	tripCount   atomic.Int32 // consecutive trips (cleared by reset())
}

// isOpen reports whether the breaker is currently tripped (node should
// be excluded from candidate lists).
func (c *circuitBreakerState) isOpen(now int64) bool {
	ou := c.openUntil.Load()
	return ou != 0 && now < ou
}

// recordFailure records one failure event.
//
// Two code paths:
//
//   - Half-open trial failure (openUntil > 0 && now >= openUntil):
//     re-trip immediately with escalated backoff. The trial dial has
//     proven the node is still broken; waiting for another
//     consecutive-failure streak would waste time.
//
//   - Normal failure: accumulate consecFails within the streak window.
//     Once the count reaches `limit`, trip the breaker. Streaks older
//     than windowNS are discarded so a failure after a long quiet
//     period restarts the counter (matches pre-PR3 behaviour).
func (c *circuitBreakerState) recordFailure(now int64, windowNS, baseOpenForNS int64, limit int32) (justTripped bool) {
	// Half-open trial re-trip. openUntil != 0 means we have tripped at
	// least once before; now >= openUntil means the cooldown elapsed
	// and this failure is the half-open probe outcome.
	if openUntil := c.openUntil.Load(); openUntil != 0 && now >= openUntil {
		trip := c.tripCount.Add(1)
		dur := expBackoffJitter(baseOpenForNS, trip)
		c.openUntil.Store(now + dur)
		return true
	}

	firstAt := c.firstFailAt.Load()
	if firstAt == 0 || now-firstAt > windowNS {
		c.firstFailAt.Store(now)
		c.consecFails.Store(1)
		return false
	}
	n := c.consecFails.Add(1)
	if n >= limit {
		trip := c.tripCount.Add(1)
		dur := expBackoffJitter(baseOpenForNS, trip)
		old := c.openUntil.Swap(now + dur)
		return old == 0 || now >= old
	}
	return false
}

// reset clears the failure streak after a successful dial. Drops
// tripCount too — markAlive uses this to signal the node has fully
// recovered, so the next failure cycle starts from the base cooldown.
func (c *circuitBreakerState) reset() {
	c.consecFails.Store(0)
	c.firstFailAt.Store(0)
	c.openUntil.Store(0)
	c.tripCount.Store(0)
}

// expBackoffJitter returns a cooldown duration in nanoseconds derived
// from the base and the current trip ordinal:
//
//	trip=1 → base × 1
//	trip=2 → base × 2
//	trip=3 → base × 4
//	trip≥4 → base × 8  (capped)
//
// Multiplied by a uniform random jitter in [0.8, 1.2] to prevent a
// thundering-herd recovery when many nodes tripped together.
//
// Deterministic for tests: seed math/rand if you need repeatable runs;
// the jitter envelope is narrow enough (±20 %) that non-determinism
// never breaks the ordering-based assertions the test suite relies on.
func expBackoffJitter(baseNS int64, trip int32) int64 {
	if trip < 1 {
		trip = 1
	}
	exp := trip - 1
	if exp > 3 {
		exp = 3
	}
	scaled := baseNS << uint(exp) // × 2^exp
	jitter := 0.8 + rand.Float64()*0.4
	return int64(float64(scaled) * jitter)
}

// breakerFor returns (or lazily creates) the circuit breaker for tag.
func (s *Smart) breakerFor(tag string) *circuitBreakerState {
	if cb, ok := s.breakers.Load(tag); ok {
		return cb
	}
	cb := &circuitBreakerState{}
	actual, _ := s.breakers.LoadOrStore(tag, cb)
	return actual
}

// isBreakerOpen reports whether node tag's breaker is currently tripped.
// Cheap enough to call on every selectProxiesTraced filter pass.
func (s *Smart) isBreakerOpen(tag string) bool {
	cb, ok := s.breakers.Load(tag)
	if !ok {
		return false
	}
	return cb.isOpen(breakerNow())
}

// recordDialFailure updates the circuit breaker for tag. Returns true if
// the breaker just tripped — callers use this to log the demotion and
// optionally kick off a re-selection for in-flight dials.
//
// Persists the post-mutation breaker state so a restart-within-15s
// doesn't silently re-open the breaker and let a just-tripped node be
// retried immediately.
func (s *Smart) recordDialFailure(tag string) (tripped bool) {
	if tag == "" {
		return false
	}
	cb := s.breakerFor(tag)
	tripped = cb.recordFailure(breakerNow(),
		int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	s.persistBreaker(tag, cb)
	return tripped
}

// markDead records a probe / dial failure for tag. Persists the
// "last-failed-at" timestamp so the next-boot hydrate path can honour
// knownDeadTTL without waiting a full probe cycle to re-learn.
func (s *Smart) markDead(tag string) {
	if tag == "" {
		return
	}
	now := time.Now()
	s.knownDead.Store(tag, now)
	s.persistKnownDead(tag, now)
}

// targetDebargoTTL is how long a node is excluded from a specific target
// after a target-level failure (WatchDog/RST).
const targetDebargoTTL = 10 * time.Minute

// markDeadForTarget soft-breaks a proxy node for a specific target.
// Used when a node is globally healthy but fails to dial or stalls out 
// on a specific target (e.g. SNI blocking or IP ban).
func (s *Smart) markDeadForTarget(target, proxyTag string) {
	if target == "" || proxyTag == "" {
		return
	}
	s.targetDebargo.Store(target+"|"+proxyTag, time.Now())
	s.logger.Warn("smart[", s.Tag(), "] target debargo enacted for [", proxyTag, "] on target [", target, "]")
}

// isTargetDebargoed returns true if the node is currently soft-broken
// for this specific target.
func (s *Smart) isTargetDebargoed(target, proxyTag string) bool {
	if target == "" || proxyTag == "" {
		return false
	}
	key := target + "|" + proxyTag
	at, ok := s.targetDebargo.Load(key)
	if !ok {
		return false
	}
	if time.Since(at) > targetDebargoTTL {
		s.targetDebargo.Delete(key)
		return false
	}
	return true
}

// markAlive clears tag from knownDead and resets its circuit breaker.
// Called on successful probe or dial. Emits delete-tombstones for both
// bbolt key types so the in-memory "alive" consensus survives restart.
//
// Also stamps `aliveAt[tag]` with the current time so `runHealthCheck`
// can skip probing nodes that just proved alive via real user traffic.
// We deliberately do NOT write to URLTestHistory — that would pollute
// the dashboard's latency column with a sentinel value (previously
// Delay=1 displayed as 1ms everywhere, which users misread as the real
// probe result).
func (s *Smart) markAlive(tag string) {
	if tag == "" {
		return
	}
	_, wasDead := s.knownDead.LoadAndDelete(tag)
	var hadBreaker bool
	if cb, ok := s.breakers.Load(tag); ok {
		cb.reset()
		hadBreaker = true
	}
	// Record the dial heartbeat — runHealthCheck consults this BEFORE
	// URLTestHistory so the probe gets skipped while keeping the history
	// (and thus the dashboard) untouched by synthetic values.
	s.aliveAt.Store(tag, time.Now().UnixNano())
	// Only enqueue tombstones when there WAS a persisted state — avoids
	// flooding the queue with deletes for nodes that were never failed.
	if wasDead {
		s.persistKnownDeadDelete(tag)
	}
	if hadBreaker {
		s.persistBreakerDelete(tag)
	}
	// A successful dial also clears any short-life AND reset history
	// for this node so a previously-problematic node that's recovered
	// doesn't keep counting toward a future threshold.
	s.shortLifeMu.Lock()
	for k := range s.shortLife {
		if strings.HasSuffix(k, "|"+tag) {
			delete(s.shortLife, k)
		}
	}
	s.shortLifeMu.Unlock()
	if s.resetEvents != nil {
		s.resetEvents.resetForNode(tag)
	}
}

// ─── runtime-state persistence helpers ────────────────────────────────────────
//
// These helpers push in-memory runtime state (manual pin, known-dead
// nodes, circuit breakers) through the existing bbolt write queue so the
// state survives process restart. Every helper is nil-safe on s.store and
// the async queue path — none of them block the dialer or the health
// probe for more than an O(1) mutex acquire on globalQueueMu.

// persistManualPin writes or deletes the group's manual-pin record based
// on whether tag is set. Called whenever s.manualSelected.Store() fires
// so the bbolt view stays in sync with the in-memory atomic.
func (s *Smart) persistManualPin(tag string) {
	if s.store == nil {
		return
	}
	if tag == "" {
		s.persistManualPinDelete()
		return
	}
	rec := smart.ManualPinRecord{Tag: tag, UpdatedAt: time.Now().Unix()}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveManualPin,
		Group:  s.Tag(),
		Config: smartConfigName,
		Data:   data,
	})
}

// persistManualPinDelete emits a tombstone for the group's manual-pin slot.
func (s *Smart) persistManualPinDelete() {
	if s.store == nil {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpDeleteManualPin,
		Group:  s.Tag(),
		Config: smartConfigName,
	})
}

// persistKnownDead persists "node is dead as of at" for the given tag.
// Paired with persistKnownDeadDelete on recovery.
func (s *Smart) persistKnownDead(tag string, at time.Time) {
	if s.store == nil || tag == "" {
		return
	}
	rec := smart.KnownDeadRecord{DeadAt: at.Unix()}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveKnownDead,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
		Data:   data,
	})
}

func (s *Smart) persistKnownDeadDelete(tag string) {
	if s.store == nil || tag == "" {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpDeleteKnownDead,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
	})
}

// persistBreaker snapshots the current circuit-breaker state. Called
// right after recordFailure bumps the atomic counters so restart within
// cbOpenDuration restores the OPEN state.
func (s *Smart) persistBreaker(tag string, cb *circuitBreakerState) {
	if s.store == nil || tag == "" || cb == nil {
		return
	}
	rec := smart.BreakerRecord{
		ConsecFails: cb.consecFails.Load(),
		FirstFailAt: cb.firstFailAt.Load(),
		OpenUntil:   cb.openUntil.Load(),
		TripCount:   cb.tripCount.Load(),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveBreaker,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
		Data:   data,
	})
}

func (s *Smart) persistBreakerDelete(tag string) {
	if s.store == nil || tag == "" {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpDeleteBreaker,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
	})
}

// hydratePersistedState reads the three persisted maps back from bbolt
// and seeds the in-memory structures. Called from PostStart AFTER the
// store is wired and BEFORE background tasks begin firing.
//
// Expired entries (outside TTL / breaker window) are NOT restored, and
// lazy-GC tombstones are enqueued for them so the bbolt cleanup happens
// opportunistically on the next flush without needing a dedicated task.
//
// Manual-pin restoration also validates that the persisted tag is still
// in the current outbound set — a config change that removed the node
// makes a stale pin meaningless, so we drop it explicitly.
func (s *Smart) hydratePersistedState() {
	if s.store == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil {
		return
	}

	// 1. Manual pin
	pinRows, err := s.store.GetSubBytesByPath(
		smart.FormatDBKey(smart.KeyTypeManualPin, smartConfigName, s.Tag()))
	if err == nil {
		for _, data := range pinRows {
			var rec smart.ManualPinRecord
			if err := json.Unmarshal(data, &rec); err != nil || rec.Tag == "" {
				continue
			}
			// Confirm the pinned node still exists in the live outbound set.
			found := false
			for _, t := range snap.tags {
				if t == rec.Tag {
					found = true
					break
				}
			}
			if !found {
				s.logger.Info("smart[", s.Tag(), "] discarded stale persisted pin [", rec.Tag,
					"] — node no longer in outbound set")
				s.persistManualPinDelete()
				continue
			}
			s.manualSelected.Store(rec.Tag)
			s.logger.Info("smart[", s.Tag(), "] restored manual pin [", rec.Tag,
				"] from persisted state (pinned ", time.Since(time.Unix(rec.UpdatedAt, 0)).Round(time.Second), " ago)")
			break // only one pin per group
		}
	}

	// 2. knownDead — drop anything beyond knownDeadTTL, emit tombstone.
	deadRows, err := s.store.GetSubBytesByPath(
		smart.FormatDBKey(smart.KeyTypeKnownDead, smartConfigName, s.Tag()))
	restored, expired := 0, 0
	if err == nil {
		now := time.Now()
		for key, data := range deadRows {
			var rec smart.KnownDeadRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			// The key is smart/dead/<cfg>/<grp>/<node>; node is the last
			// segment. Unescape because FormatDBKey percent-escaped the
			// node tag — outbound tags can contain `/` (subscription
			// naming) and we'd otherwise compare against the wrong
			// substring downstream.
			parts := strings.Split(key, "/")
			if len(parts) == 0 {
				continue
			}
			node := smart.UnescapeKeyPart(parts[len(parts)-1])
			if node == "" {
				continue
			}
			deadAt := time.Unix(rec.DeadAt, 0)
			if now.Sub(deadAt) >= knownDeadTTL {
				expired++
				s.persistKnownDeadDelete(node)
				continue
			}
			s.knownDead.Store(node, deadAt)
			restored++
		}
	}

	// 3. breakers — restore if still within window, else tombstone.
	breakerRows, err := s.store.GetSubBytesByPath(
		smart.FormatDBKey(smart.KeyTypeBreaker, smartConfigName, s.Tag()))
	breakerRestored, breakerExpired := 0, 0
	if err == nil {
		now := breakerNow()
		for key, data := range breakerRows {
			var rec smart.BreakerRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			parts := strings.Split(key, "/")
			if len(parts) == 0 {
				continue
			}
			node := smart.UnescapeKeyPart(parts[len(parts)-1])
			if node == "" {
				continue
			}
			// Case 1: breaker is open and cooldown hasn't elapsed.
			if rec.OpenUntil != 0 && now < rec.OpenUntil {
				cb := &circuitBreakerState{}
				cb.consecFails.Store(rec.ConsecFails)
				cb.firstFailAt.Store(rec.FirstFailAt)
				cb.openUntil.Store(rec.OpenUntil)
				cb.tripCount.Store(rec.TripCount)
				s.breakers.Store(node, cb)
				breakerRestored++
				continue
			}
			// Case 2: open window expired — drop it.
			if rec.OpenUntil != 0 && now >= rec.OpenUntil {
				breakerExpired++
				s.persistBreakerDelete(node)
				continue
			}
			// Case 3: streak started but not yet tripped; keep only if within cbWindow.
			if rec.OpenUntil == 0 && rec.ConsecFails > 0 && rec.FirstFailAt > 0 {
				if now-rec.FirstFailAt >= int64(cbWindow) {
					breakerExpired++
					s.persistBreakerDelete(node)
					continue
				}
				cb := &circuitBreakerState{}
				cb.consecFails.Store(rec.ConsecFails)
				cb.firstFailAt.Store(rec.FirstFailAt)
				cb.tripCount.Store(rec.TripCount)
				s.breakers.Store(node, cb)
				breakerRestored++
			}
		}
	}

	if restored+expired+breakerRestored+breakerExpired > 0 {
		s.logger.Info("smart[", s.Tag(), "] hydrated runtime state: knownDead=",
			restored, " (dropped ", expired, " expired), breakers=",
			breakerRestored, " (dropped ", breakerExpired, " expired)")
	}
}

// Short-life connection parameters — tuned so 3 consecutive "user gave up
// quickly" closes within a minute mark a node dead for half a minute.
const (
	shortLifeDurationLimit = 2 * time.Second // below this = gave up
	shortLifeBytesLimit    = int64(4096)     // below this = effectively no data
	shortLifeThreshold     = 3               // events before banning the node
	shortLifeWindow        = 60 * time.Second
)

// handleResetThresholdCrossed runs the decisive cleanup when the
// per-(target, node) RST counter has crossed resetEventThreshold within
// the sliding window. Three actions, in dependency order:
//
//  1. recordDialFailure → kicks the circuit breaker so isAlive drops
//     the node from candidate lists for cbOpenDuration immediately.
//     Also persists the breaker state so a restart during cooldown
//     doesn't silently re-elect the same node.
//
//  2. markDead → writes the per-node "known bad" tombstone so
//     selectProxiesTraced excludes this node even before the next
//     health check cycle catches up.
//
//  3. DeleteUnwrapResult + meta target/ASN → invalidates any sticky
//     "this target prefers this node" cache so the user's next dial
//     starts fresh from the candidate list.
//
//  4. Async kick of updateNodeRanking — refreshes the ranking
//     snapshot so /weights surfaces the new ordering within seconds
//     instead of waiting for the next 1-min scheduled tick.
//
// All steps are best-effort: a nil store (test setup) is tolerated.
func (s *Smart) handleResetThresholdCrossed(meta *smartDialMeta, proxyTag string) {
	if proxyTag == "" {
		return
	}
	tripped := s.recordDialFailure(proxyTag)
	s.markDead(proxyTag)
	if s.store != nil && meta != nil && meta.smartTarget != "" {
		s.store.DeleteUnwrapResult(s.Tag(), smartConfigName,
			meta.smartTarget, meta.asnCode, meta.isUDP)
	}
	target := ""
	if meta != nil && meta.smartTarget != "" {
		target = meta.smartTarget
		// Critical: Execute the target-level soft break so this dead node
		// isn't continuously repicked via the generic URLTest default tier!
		s.markDeadForTarget(target, proxyTag)
	}
	s.logger.Info("smart[", s.Tag(), "] node [", proxyTag,
		"] marked dead after ", resetEventThreshold,
		" upstream resets on target [", target,
		"] within ", resetEventWindow,
		" (breaker tripped=", tripped, ")")

	// Kick the ranking refresh on the shared worker so the next
	// /weights call and the next selectProxies pass both see the
	// post-eviction state. Bounded by the worker pool — never
	// spawns an unbounded goroutine even under reset storms.
	if w := getSmartWorker(); w != nil {
		w.submit(s.updateNodeRanking)
	}
}

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

// getPriorityFactor moved to smart_priority.go.

func (s *Smart) getHistoryConnectTime(meta *smartDialMeta, proxyTag string) int64 {
	if s.store == nil || meta.smartTarget == "" {
		return 0
	}
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, smartConfigName, s.Tag(), meta.smartTarget, proxyTag)
	record := s.store.GetOrCreateAtomicRecord(cacheKey, s.Tag(), smartConfigName, meta.smartTarget, proxyTag)
	return record.GetInt64("connectTime")
}

// lookupASN resolves an ASN code for the first valid public destination IP.
// Iterates s.asnDBs in priority order — when one provider lacks coverage
// for an IP (e.g. small allocations / new ranges), the next is tried.
// Returns the FIRST non-zero ASN found by ANY (db, ip) pair tried.
func (s *Smart) lookupASN(ips []netip.Addr) string {
	if !s.useASN || len(s.asnDBs) == 0 {
		return ""
	}
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() {
			continue
		}
		ipBytes := ip.AsSlice()
		for _, db := range s.asnDBs {
			var record struct {
				AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
			}
			if err := db.Lookup(ipBytes, &record); err == nil && record.AutonomousSystemNumber != 0 {
				return strconv.FormatUint(uint64(record.AutonomousSystemNumber), 10)
			}
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
	db, err := getSharedMMDB(mmdbPath)
	if err != nil {
		return // file still not present; try again next time
	}
	s.countryDB = db
	s.logger.Info("smart[", s.Tag(), "] country mmdb lazily opened from ",
		mmdbPath, " (shared via mmdbPool)")
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

	// Intern tag strings so N Smart groups sharing the same node hold
	// pointers to ONE backing byte slice — saves ~1 KB per overlapping
	// node across the process (13 KB → ~1 KB on a 15-group × 30-node
	// overlap scenario).
	for i := range tags {
		tags[i] = internTag(tags[i])
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
