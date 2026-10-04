package group

import (
	"context"
	"io"
	"maps"
	"net"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// manualPinData holds the user's temporary manual selection on a URLTest group.
// The pin is released automatically when the user triggers another manual speed
// test (clash API /group/{name}/delay or libbox URLTest RPC), so periodic
// health checks and dial-failure auto-rechecks never silently unpin.
type manualPinData struct {
	tag      string
	outbound adapter.Outbound
}

const (
	maxScreeningConcurrency = 16 // Phase 1: coarse screening — balanced speed vs memory
	maxPrecisionConcurrency = 2  // Phase 2: precision retest — minimal concurrency for accuracy
	maxPrecisionCandidates  = 8  // Number of top candidates to retest
	maxFailoverCandidates   = 10

	// Consecutive health-check failures before we stop trusting a node.
	// Unlike mihomo, we don't delete history — we mark it stale by zeroing delay.
	// This keeps the node in the ranked list for failover but deprioritizes it.
	healthCheckFailThreshold = 3

	// Dial failures that trigger a proactive re-check (mihomo parity).
	dialFailureThreshold = 5

	// When current selection's history is missing, how long to trust it anyway
	// before considering a switch. Prevents flapping on transient test-URL blockage.
	staleHistoryGrace = 2 * time.Minute
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.PreMatchOutboundGroup   = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
	_ adapter.Referrer                = (*URLTest)(nil)
	_ adapter.DialingOutboundGroup    = (*URLTest)(nil)
)

// groupState is a single immutable snapshot containing ALL group data.
// ONE atomic pointer instead of three — reduces memory and GC pressure.
type groupState struct {
	outbounds []adapter.Outbound
	tags      []string
	rankedTCP []rankedOutbound // pre-sorted by delay
	rankedUDP []rankedOutbound // pre-sorted by delay
}

// rankedOutbound is a delay-sorted outbound for O(1) selection.
type rankedOutbound struct {
	outbound adapter.Outbound
	delay    uint16
}

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	fallback                     URLTestFallback
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
	// expectedStatus mihomo 对齐的状态码 matcher。nil = 旧启发式。
	// NewURLTest 时 Parse，失败阻断启动；loopCheckOutbounds 里每次探测透传。
	expectedStatus *urltest.StatusMatcher

	providerAccess      sync.Mutex
	providerUpdateCheck providerUpdateCheckScheduler
	provider            adapter.ProviderManager
	providers           map[string]adapter.Provider
	outboundsCache      map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
	hidden          bool
	icon            string
}

type URLTestFallback struct {
	enabled  bool
	maxDelay int64
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
		hidden:          options.Hidden,
		icon:            options.Icon,
	}
	if options.Fallback.Enabled {
		outbound.fallback = URLTestFallback{
			enabled:  true,
			maxDelay: time.Duration(options.Fallback.MaxDelay).Milliseconds(),
		}
	}
	// 解析 expected_status。用户写错立即报错，避免启动后每次探测才发现。
	matcher, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, err
	}
	outbound.expectedStatus = matcher
	return outbound, nil
}

// Hidden / Icon expose the dashboard hints from option.GroupCommonOption.
// See adapter.OutboundGroup interface for the semantic contract.
func (s *URLTest) Hidden() bool { return s.hidden }
func (s *URLTest) Icon() string { return s.icon }

func (s *URLTest) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		return s.startGroup()
	case adapter.StartStateStarted:
		s.postStart()
		scope.Add(func() error {
			return common.Close(common.PtrOrNil(s.group))
		})
	}
	return nil
}

func (s *URLTest) startGroup() error {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
		}
	}
	tags := s.Dependencies()
	if len(tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(tags))
	for i, tag := range tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	if len(tags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, tags, s.link, s.interval, s.tolerance, s.idleTimeout, s.fallback, s.interruptExternalConnections, s.expectedStatus)
	if err != nil {
		return err
	}
	s.group = group
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	return nil
}

func (s *URLTest) postStart() {
	// Restore the manually-pinned outbound (if any) from CacheFile before
	// the group starts dispatching dials. Mirrors Selector's
	// cacheFile.LoadSelected path but only applies when the pinned tag
	// still exists in the current snapshot (a re-subscribe may have
	// dropped it; in that case we silently fall back to auto-selection
	// rather than dialling a vanished node).
	//
	// Why at the started stage and not start: the group's state is populated
	// in startGroup; postStart is the earliest point at which findOutboundByTag
	// can resolve the pin tag. Reloading here also means the
	// user-visible Selected() / PinnedTag() reflect the pin immediately
	// after startup, before any health-check runs.
	if s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if saved := cacheFile.LoadSelected(s.Tag()); saved != "" {
				if detour := s.group.findOutboundByTag(saved); detour != nil {
					s.group.manualPin.Store(&manualPinData{tag: saved, outbound: detour})
					// Pre-seed the cached selectedOutboundTCP/UDP so the very
					// first DialContext after startup sees the pin even
					// before Select() runs. Network-gated to avoid poisoning
					// the other-network slot.
					if common.Contains(detour.Network(), N.NetworkTCP) {
						s.group.selectedOutboundTCP.Store(detour)
					}
					if common.Contains(detour.Network(), N.NetworkUDP) {
						s.group.selectedOutboundUDP.Store(detour)
					}
					s.logger.Info("restored manual pin [", saved, "] from cache")
				} else {
					// Pin target removed from the group (provider dropped the
					// tag or config changed). Wipe the stale entry so a future
					// restart won't keep attempting to restore a ghost.
					_ = cacheFile.StoreSelected(s.Tag(), "")
					s.logger.Debug("cached manual pin [", saved,
						"] no longer present in snapshot, cleared")
				}
			}
		}
	}
	s.group.PostStart()
}

// persistManualPin writes the pin tag to CacheFile so it survives core
// restart. Empty tag clears the persisted entry (auto-selection resumes
// after the next restart). Errors are logged but not propagated —
// persistence failure degrades to "temporary pin" gracefully rather than
// breaking the user-facing SelectOutbound call.
func (s *URLTest) persistManualPin(tag string) {
	if s.Tag() == "" {
		return
	}
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile == nil {
		return
	}
	if err := cacheFile.StoreSelected(s.Tag(), tag); err != nil {
		s.logger.Error("persist manual pin: ", err)
	}
}

// Selected returns the member traffic for network is routed through: the
// manual pin when it supports the network, otherwise the cached automatic
// selection, falling back to a fresh Select before the first health check.
func (s *URLTest) Selected(network string) adapter.Outbound {
	if network != N.NetworkUDP {
		network = N.NetworkTCP
	}
	if pinned := s.group.pinnedOutbound(network); pinned != nil {
		return pinned
	}
	var outbound adapter.Outbound
	if network == N.NetworkUDP {
		outbound = s.group.selectedOutboundUDP.Load()
	} else {
		outbound = s.group.selectedOutboundTCP.Load()
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	return outbound
}

// PinnedTag reports the user's manually-pinned outbound tag, or "" when the
// group is running on automatic selection. Mirrors Smart.PinnedTag semantics so
// dashboards can render the pinned / fixed state uniformly across group types.
func (s *URLTest) PinnedTag() string {
	if pin := s.group.manualPin.Load(); pin != nil {
		return pin.tag
	}
	return ""
}

// DialThroughGroup keeps URLTest in the dial path so DialContext / ListenPacket
// can fail over to the next ranked member and track dial failures.
func (s *URLTest) DialThroughGroup() {}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	var references []string
	if pin := group.manualPin.Load(); pin != nil {
		references = append(references, pin.tag)
	}
	selectedOutboundTCP := group.selectedOutboundTCP.Load()
	selectedOutboundUDP := group.selectedOutboundUDP.Load()
	if selectedOutboundTCP != nil && !common.Contains(references, selectedOutboundTCP.Tag()) {
		references = append(references, selectedOutboundTCP.Tag())
	}
	if selectedOutboundUDP != nil && !common.Contains(references, selectedOutboundUDP.Tag()) {
		references = append(references, selectedOutboundUDP.Tag())
	}
	return references
}

func (s *URLTest) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	s.group.Touch()
	network := metadata.Network
	if network == N.NetworkICMP {
		network = N.NetworkTCP
	}
	return selectOutbound(s.Selected(network))
}

// SelectOutbound pins a node as the temporary manual selection, or clears the
// pin when tag == "". Returns false only when tag is non-empty and not a
// member of the current group snapshot. The pin survives periodic health
// checks and dial-failure-triggered rechecks, and is released automatically on
// the next user-triggered URL test (see URLTestGroup.URLTest /
// URLTest.CheckOutbounds). New dials see the pin immediately; active
// connections are interrupted when interruptExistConnections is enabled
// (mirrors Selector.SelectOutbound).
func (s *URLTest) SelectOutbound(tag string) bool {
	if tag == "" {
		if s.group.clearManualPin() {
			s.logger.Info("manual pin released")
			if s.interruptExternalConnections {
				s.group.interruptGroup.Interrupt(true)
			}
		}
		// Persist the cleared state unconditionally (even when there was
		// no in-memory pin) — after a restart with a previously persisted
		// pin, clearManualPin would return false (no in-memory state)
		// but we still need to wipe the cache entry so auto-selection
		// really takes over next boot. Persist idempotent so redundant
		// writes are cheap.
		s.persistManualPin("")
		return true
	}
	detour := s.group.findOutboundByTag(tag)
	if detour == nil {
		return false
	}
	prev := s.group.manualPin.Swap(&manualPinData{tag: tag, outbound: detour})
	// Persist even when prev.outbound == detour — restart resilience
	// takes priority over skipping a no-op disk write; StoreSelected is
	// cheap (bbolt key-value write, bounded by disk cache flush).
	s.persistManualPin(tag)
	if prev != nil && prev.outbound == detour {
		return true
	}
	s.logger.Info("manual pin set to ", tag)
	// Make the pin visible to cached-select fast paths and any code reading
	// selectedOutboundTCP/UDP directly (DialContext/ListenPacket). Only
	// overwrite when the pin supports the network so UDP-only / TCP-only
	// nodes don't poison the other-network cached slot.
	if common.Contains(detour.Network(), N.NetworkTCP) {
		s.group.selectedOutboundTCP.Store(detour)
	}
	if common.Contains(detour.Network(), N.NetworkUDP) {
		s.group.selectedOutboundUDP.Store(detour)
	}
	s.group.interruptGroup.Interrupt(s.interruptExternalConnections)
	return true
}

func (s *URLTest) All() []string {
	snap := s.group.state.Load()
	if snap == nil {
		return nil
	}
	result := make([]string, len(snap.tags))
	copy(result, snap.tags)
	return result
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	// User-triggered manual test — release the manual pin so selection
	// returns to the best measured node after this cycle completes.
	// Persist the cleared state too, otherwise the pin would come back
	// on next core restart (cached tag still pointing at the released
	// node). Persist is idempotent so calling on every user test is
	// cheap and matches the "release on next manual speedtest" contract
	// even across restarts.
	if s.group.clearManualPin() {
		s.logger.Info("manual pin released by user speed test")
	}
	s.persistManualPin("")
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	// User-triggered via gRPC/libbox — release the manual pin before
	// running. Internal callers use g.CheckOutbounds directly and must
	// preserve the pin.
	if s.group.clearManualPin() {
		s.logger.Info("manual pin released by user speed test")
	}
	s.persistManualPin("")
	s.group.CheckOutbounds(true)
}

// urlTest lets an enclosing group's URLTestOutbounds recurse into this group
// without releasing the manual pin (only user-triggered tests release it).
func (s *URLTest) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	return s.group.urlTest(ctx, force)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		_, _ = group.urlTest(ctx, true)
	}()
}

func (s *URLTest) isGroupActive() bool {
	if !s.group.started.Load() {
		return false
	}
	return time.Since(s.group.lastActive.Load()) <= s.group.idleTimeout
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if pinned := s.group.pinnedOutbound(N.NetworkName(network)); pinned != nil {
		outbound = pinned
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			outbound = s.group.selectedOutboundTCP.Load()
		case N.NetworkUDP:
			outbound = s.group.selectedOutboundUDP.Load()
		}
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	// Failover: try top-N ranked healthy outbounds (not all 3000+)
	candidates := s.group.getFailoverCandidates(N.NetworkName(network), outbound.Tag())
	for _, detour := range candidates {
		conn, err = detour.DialContext(ctx, network, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, E.New("all outbounds failed for ", network, " to ", destination)
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	if pinned := s.group.pinnedOutbound(N.NetworkUDP); pinned != nil {
		outbound = pinned
	} else {
		outbound = s.group.selectedOutboundUDP.Load()
	}
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	// Failover: try top-N ranked healthy outbounds
	candidates := s.group.getFailoverCandidates(N.NetworkUDP, outbound.Tag())
	for _, detour := range candidates {
		conn, err = detour.ListenPacket(ctx, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, E.New("all outbounds failed for UDP to ", destination)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	tags, outbounds, outboundsCache, err := collectProviderOutbounds(
		tag,
		s.Dependencies(),
		s.outbound,
		s.providers,
		s.providerTags,
		s.outboundsCache,
		s.exclude,
		s.include,
	)
	if err != nil {
		s.providerAccess.Unlock()
		return E.Cause(err, s.Tag())
	}
	s.outboundsCache = outboundsCache
	s.group.replaceOutbounds(outbounds)
	s.providerAccess.Unlock()
	s.group.pruneFailureCounters(tags)
	if s.isGroupActive() {
		s.group.access.Lock()
		if s.group.ticker != nil {
			s.group.ticker.Reset(s.group.interval)
		}
		s.group.access.Unlock()
		// 直接走 group 层的 URLTest —— 上层 s.URLTest 会把 pin 清掉，
		// 但 provider 刷新不是"用户手动测速"，该触发点必须保留 pin
		// 以满足"仅用户手动测速后自动解锁"的契约。
		s.providerUpdateCheck.Schedule(func() {
			_, _ = s.group.urlTestWait(s.ctx, false)
		})
	}
	return nil
}

type URLTestGroup struct {
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     sync.Mutex
	updateAccess                 sync.Mutex
	selectedOutboundTCP          common.TypedValue[adapter.Outbound]
	selectedOutboundUDP          common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	// Single atomic state — replaces 3 separate atomic pointers
	state atomic.Pointer[groupState]

	access     sync.Mutex
	ticker     *time.Ticker
	close      chan struct{}
	started    atomic.Bool
	lastActive common.TypedValue[time.Time]

	// Failure tracking — regular map + mutex (lower overhead than sync.Map)
	failureMu    sync.Mutex
	failureCount map[string]int32

	// Dial-failure tracking: counts user-facing dial failures per tag.
	// When threshold exceeded, triggers async health re-check (mihomo onDialFailed parity).
	dialFailureMu    sync.Mutex
	dialFailureCount map[string]int32
	dialFailureAt    time.Time // last time we bumped failures; clears periodically
	dialRecheckOnce  atomic.Bool

	// Reusable maps — allocated once, cleared each cycle (avoid per-check allocation)
	reusableChecked map[string]bool
	reusableResult  map[string]uint16

	fallback URLTestFallback

	// expectedStatus: 上层 URLTest.NewURLTest 在构造 group 之前解析好
	// 再传进来；每次 URL 探测透传给 urltest.URLTestWithStatus。nil = 旧启发式。
	expectedStatus *urltest.StatusMatcher

	// manualPin: user's temporary manual selection. nil = auto.
	// Set via SelectOutbound, cleared at the next user-triggered URL test.
	manualPin atomic.Pointer[manualPinData]
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, tags []string, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, fallback URLTestFallback, interruptExternalConnections bool, expectedStatus *urltest.StatusMatcher) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	group := &URLTestGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		fallback:                     fallback,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		failureCount:                 make(map[string]int32),
		dialFailureCount:             make(map[string]int32),
		reusableChecked:              make(map[string]bool, len(outbounds)),
		reusableResult:               make(map[string]uint16, len(outbounds)),
		expectedStatus:               expectedStatus,
	}
	group.state.Store(&groupState{outbounds: outbounds, tags: tags})
	return group, nil
}

func (g *URLTestGroup) getState() *groupState {
	return g.state.Load()
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *URLTestGroup) Touch() {
	if !g.started.Load() {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	g.ticker = time.NewTicker(g.interval)
	go g.loopCheck()
	g.pauseCallback = pause.RegisterTicker(g.pause, g.ticker, g.interval, nil)
	g.logger.Info("health check resumed")
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.pause.UnregisterCallback(g.pauseCallback)
	close(g.close)
	urltest.PruneSessionCaches()
	return nil
}

// Select picks the best outbound from the pre-sorted ranked list — O(1) for the common case.
// Falls back to full scan only when ranked list is empty (before first health check).
//
// Disconnect-prevention rules (mihomo-parity):
//  1. If current selection still has valid (fresh) history within tolerance, keep it.
//  2. If current has stale/missing history but is still in the outbound set AND we
//     haven't seen too many dial failures on it, give it a grace period. Avoids
//     thrash when the test URL is temporarily blocked while traffic still works.
//  3. Only switch when current is truly unusable (dropped from set, or marked bad).
//
// pinnedOutbound returns the manually-pinned outbound when it is still a
// member of the snapshot and supports the requested network; nil otherwise.
// When the pin has been removed from the snapshot (provider update dropped
// it), the pin is auto-cleared so selection falls back to automatic.
func (g *URLTestGroup) pinnedOutbound(network string) adapter.Outbound {
	pin := g.manualPin.Load()
	if pin == nil {
		return nil
	}
	st := g.getState()
	if st == nil || !g.outboundStillPresent(st, pin.outbound) {
		g.manualPin.CompareAndSwap(pin, nil)
		return nil
	}
	if network != "" && !common.Contains(pin.outbound.Network(), network) {
		return nil
	}
	return pin.outbound
}

// clearManualPin drops the pin if one is set. Returns true when a pin was
// actually cleared so callers can log / interrupt conditionally.
func (g *URLTestGroup) clearManualPin() bool {
	return g.manualPin.Swap(nil) != nil
}

// findOutboundByTag walks the current snapshot looking for tag. Used by
// SelectOutbound so the pin only accepts tags that actually belong to this
// group (mirrors Selector.SelectOutbound's membership guard).
func (g *URLTestGroup) findOutboundByTag(tag string) adapter.Outbound {
	st := g.getState()
	if st == nil {
		return nil
	}
	for _, o := range st.outbounds {
		if o.Tag() == tag {
			return o
		}
	}
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	if pin := g.pinnedOutbound(network); pin != nil {
		return pin, true
	}
	if g.fallback.enabled {
		return g.selectFallback(network)
	}
	st := g.getState()
	var candidates []rankedOutbound
	if st != nil {
		switch network {
		case N.NetworkTCP:
			candidates = st.rankedTCP
		case N.NetworkUDP:
			candidates = st.rankedUDP
		}
	}

	var current adapter.Outbound
	switch network {
	case N.NetworkTCP:
		current = g.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		current = g.selectedOutboundUDP.Load()
	}

	if len(candidates) > 0 {
		best := candidates[0]

		// Rule 1: current still within tolerance → stick with it (prevents delay-jitter flapping).
		if current != nil {
			if currentHistory := g.history.LoadURLTestHistory(RealTag(current, network)); currentHistory != nil {
				if currentHistory.Delay <= best.delay+g.tolerance {
					return current, true
				}
			} else {
				// Rule 2: current has no history (either first run or failed-stripped).
				// If current is still in the snapshot and hasn't accumulated dial failures,
				// give it a grace period instead of hard-switching.
				if st != nil && g.outboundStillPresent(st, current) && !g.hasExcessiveDialFailures(current.Tag()) {
					return current, true
				}
			}
		}

		return best.outbound, true
	}

	// No ranked data yet — try to hold current if it's still in the snapshot.
	if current != nil && st != nil && g.outboundStillPresent(st, current) {
		return current, true
	}

	return g.selectFullScan(network)
}

// selectFallback implements fallback mode: members are tried in configured
// order and the first one with a delay within max_delay wins, regardless of
// the current selection. When every tested member exceeds max_delay, the
// fastest of them is used.
func (g *URLTestGroup) selectFallback(network string) (adapter.Outbound, bool) {
	st := g.getState()
	if st == nil {
		return nil, false
	}
	var (
		minOutbound                 adapter.Outbound
		fallbackIgnoreOutbound      adapter.Outbound
		fallbackIgnoreOutboundDelay uint16
	)
	for _, detour := range st.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if g.fallback.maxDelay > 0 && int64(history.Delay) > g.fallback.maxDelay {
			if fallbackIgnoreOutbound == nil || history.Delay < fallbackIgnoreOutboundDelay {
				fallbackIgnoreOutboundDelay = history.Delay
				fallbackIgnoreOutbound = detour
			}
			continue
		}
		minOutbound = detour
		if history.Delay != 0 {
			break
		}
	}
	if minOutbound != nil {
		return minOutbound, true
	}
	if fallbackIgnoreOutbound != nil {
		return fallbackIgnoreOutbound, true
	}
	for _, detour := range st.outbounds {
		if common.Contains(detour.Network(), network) {
			return detour, false
		}
	}
	return nil, false
}

// outboundStillPresent reports whether `ob` is part of the current snapshot.
func (g *URLTestGroup) outboundStillPresent(st *groupState, ob adapter.Outbound) bool {
	for _, o := range st.outbounds {
		if o == ob || o.Tag() == ob.Tag() {
			return true
		}
	}
	return false
}

// hasExcessiveDialFailures reports whether tag has exceeded dial-failure threshold.
func (g *URLTestGroup) hasExcessiveDialFailures(tag string) bool {
	g.dialFailureMu.Lock()
	defer g.dialFailureMu.Unlock()
	return g.dialFailureCount[tag] >= dialFailureThreshold
}

// reportDialFailure is called by DialContext/ListenPacket on a failed dial.
// Mihomo-parity: bumps failure counter and triggers async health-check when excessive.
func (g *URLTestGroup) reportDialFailure(tag string) {
	g.dialFailureMu.Lock()
	// Decay stale counters if last bump was long ago
	if !g.dialFailureAt.IsZero() && time.Since(g.dialFailureAt) > g.interval {
		for k := range g.dialFailureCount {
			delete(g.dialFailureCount, k)
		}
	}
	g.dialFailureCount[tag]++
	count := g.dialFailureCount[tag]
	g.dialFailureAt = time.Now()
	g.dialFailureMu.Unlock()

	if count >= dialFailureThreshold {
		// Rate-limit: only one async re-check in flight at a time
		if g.dialRecheckOnce.CompareAndSwap(false, true) {
			go func() {
				defer g.dialRecheckOnce.Store(false)
				g.CheckOutbounds(true)
			}()
		}
	}
}

// reportDialSuccess is called when a dial succeeds — clears the failure counter.
func (g *URLTestGroup) reportDialSuccess(tag string) {
	g.dialFailureMu.Lock()
	delete(g.dialFailureCount, tag)
	g.dialFailureMu.Unlock()
}

// selectFullScan is the original O(N) selection, used only before the first health check completes.
// Prefers outbounds with recent history; falls back to any with any history; finally to any at all.
func (g *URLTestGroup) selectFullScan(network string) (adapter.Outbound, bool) {
	snap := g.getState()
	if snap == nil {
		return nil, false
	}
	var (
		minDelay     uint16
		minOutbound  adapter.Outbound
		anyWithHist  adapter.Outbound
		anyAvailable adapter.Outbound
	)
	now := time.Now()
	for _, detour := range snap.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		if anyAvailable == nil {
			anyAvailable = detour
		}
		history := g.history.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if anyWithHist == nil {
			anyWithHist = detour
		}
		// Only consider "fresh" history for ranking
		if now.Sub(history.Time) > 2*g.interval+staleHistoryGrace {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound != nil {
		return minOutbound, true
	}
	if anyWithHist != nil {
		return anyWithHist, true
	}
	return anyAvailable, anyAvailable != nil
}

// getFailoverCandidates returns up to maxFailoverCandidates from the ranked list, excluding the failed one.
func (g *URLTestGroup) getFailoverCandidates(network string, excludeTag string) []adapter.Outbound {
	st := g.getState()
	if st == nil {
		return nil
	}
	var ranked []rankedOutbound
	switch network {
	case N.NetworkTCP:
		ranked = st.rankedTCP
	case N.NetworkUDP:
		ranked = st.rankedUDP
	}
	if len(ranked) == 0 {
		return nil
	}
	result := make([]adapter.Outbound, 0, maxFailoverCandidates)
	for _, r := range ranked {
		if r.outbound.Tag() == excludeTag {
			continue
		}
		result = append(result, r.outbound)
		if len(result) >= maxFailoverCandidates {
			break
		}
	}
	return result
}

// rebuildRankedCandidates sorts all healthy outbounds by delay and stores atomically.
// Called after each health check batch completes.
func (g *URLTestGroup) rebuildRankedCandidates() {
	for {
		snap := g.getState()
		if snap == nil {
			return
		}
		var tcpRanked, udpRanked []rankedOutbound
		for _, detour := range snap.outbounds {
			history := g.history.LoadURLTestHistory(RealTag(detour, N.NetworkTCP))
			if history == nil {
				continue
			}
			r := rankedOutbound{outbound: detour, delay: history.Delay}
			if common.Contains(detour.Network(), N.NetworkTCP) {
				tcpRanked = append(tcpRanked, r)
			}
			if common.Contains(detour.Network(), N.NetworkUDP) {
				udpRanked = append(udpRanked, r)
			}
		}
		sort.Slice(tcpRanked, func(i, j int) bool { return tcpRanked[i].delay < tcpRanked[j].delay })
		sort.Slice(udpRanked, func(i, j int) bool { return udpRanked[i].delay < udpRanked[j].delay })
		// Atomic swap: single pointer update replaces all ranked data. A
		// concurrent provider update may have replaced the member list
		// meanwhile; rebuild against it instead of resurrecting old members.
		if g.state.CompareAndSwap(snap, &groupState{
			outbounds: snap.outbounds,
			tags:      snap.tags,
			rankedTCP: tcpRanked,
			rankedUDP: udpRanked,
		}) {
			return
		}
	}
}

func (g *URLTestGroup) loopCheck() {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		g.access.Lock()
		tickerChan := g.ticker.C
		g.access.Unlock()

		select {
		case <-g.close:
			return
		case <-tickerChan:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			g.ticker.Stop()
			g.ticker = nil
			g.pause.UnregisterCallback(g.pauseCallback)
			g.pauseCallback = nil
			g.access.Unlock()
			g.logger.Info("health check paused due to idle timeout")
			return
		}
		g.CheckOutbounds(false)
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, false)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	if !g.checking.TryLock() {
		return nil, nil
	}
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

// urlTestWait waits for an in-flight check instead of skipping, so members
// added by a provider update are tested right after the current round.
func (g *URLTestGroup) urlTestWait(ctx context.Context, force bool) (map[string]uint16, error) {
	g.checking.Lock()
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *URLTestGroup) urlTestLocked(ctx context.Context, force bool) (map[string]uint16, error) {
	snap := g.getState()
	if snap == nil {
		return nil, nil
	}
	outbounds := snap.outbounds
	outboundCount := len(outbounds)
	// Reuse maps — clear instead of allocate
	for k := range g.reusableResult {
		delete(g.reusableResult, k)
	}
	for k := range g.reusableChecked {
		delete(g.reusableChecked, k)
	}
	result := g.reusableResult

	// ═══ Phase 1: Coarse screening ═══
	// Higher concurrency, acceptable inaccuracy — filters out dead nodes
	screenTimeout := g.interval
	if scaled := time.Duration(outboundCount/maxScreeningConcurrency+1) * C.TCPTimeout * 2; scaled > screenTimeout {
		screenTimeout = scaled
	}
	if screenTimeout > 10*time.Minute {
		screenTimeout = 10 * time.Minute
	}
	if screenTimeout < 2*C.TCPTimeout {
		screenTimeout = 2 * C.TCPTimeout
	}
	screenCtx, screenCancel := context.WithTimeout(g.ctx, screenTimeout)
	defer screenCancel()
	// Share probes with sibling groups tested in the same recursive round
	// (URLTestOutbounds), so a leaf reachable from several groups is only
	// measured once per URL.
	_, session := urlTestSessionFromContext(ctx)

	concurrency := outboundCount
	if concurrency > maxScreeningConcurrency {
		concurrency = maxScreeningConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}
	b, _ := batch.New(screenCtx, batch.WithConcurrencyNum[any](concurrency))
	checked := g.reusableChecked
	var resultAccess sync.Mutex
	for _, detour := range outbounds {
		tag := detour.Tag()
		realTag := RealTag(detour, N.NetworkTCP)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			testResult := session.test(screenCtx, urlTestSessionKey{tag: realTag, link: g.link, matcher: g.expectedStatus}, func() urlTestResult {
				testCtx, cancel := context.WithTimeout(screenCtx, C.TCPTimeout)
				defer cancel()
				delay, err := urlTestBounded(testCtx, g.link, p, g.expectedStatus)
				return urlTestResult{delay, err}
			})
			t, err := testResult.delay, testResult.err
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				// DO NOT delete history on failure — mihomo never does this, and deleting
				// it causes the group to aggressively switch away from the current
				// selection, killing all active user connections via Interrupt.
				// Just track the failure count for logging; the stale-but-present
				// history will let Select() keep the current choice under Rule 2.
				if cnt := g.incrementFailure(realTag); cnt == healthCheckFailThreshold {
					g.logger.Info("outbound ", tag, " test failed ", cnt, " times (keeping history stale-valid)")
				}
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms (screening)")
				g.resetFailure(realTag)
				g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()

	select {
	case <-ctx.Done():
		return result, nil
	default:
	}

	// ═══ Phase 2: Precision retest on top candidates ═══
	// Low concurrency for accurate measurement — only retests the fastest nodes
	g.rebuildRankedCandidates()
	if len(result) > maxPrecisionCandidates {
		var precisionTargets []rankedOutbound
		if st := g.getState(); st != nil && len(st.rankedTCP) > 0 {
			precisionTargets = st.rankedTCP
		}
		if len(precisionTargets) > maxPrecisionCandidates {
			precisionTargets = precisionTargets[:maxPrecisionCandidates]
		}
		if len(precisionTargets) > 0 {
			precisionCtx, precisionCancel := context.WithTimeout(g.ctx, time.Duration(len(precisionTargets)+1)*C.TCPTimeout)
			defer precisionCancel()
			pb, _ := batch.New(precisionCtx, batch.WithConcurrencyNum[any](maxPrecisionConcurrency))
			for _, candidate := range precisionTargets {
				tag := candidate.outbound.Tag()
				realTag := RealTag(candidate.outbound, N.NetworkTCP)
				p, loaded := g.outbound.Outbound(realTag)
				if !loaded {
					continue
				}
				pb.Go(realTag, func() (any, error) {
					testCtx, cancel := context.WithTimeout(precisionCtx, C.TCPTimeout)
					defer cancel()
					t, err := urlTestBounded(testCtx, g.link, p, g.expectedStatus)
					if err != nil {
						return nil, nil
					}
					g.logger.Debug("outbound ", tag, " precision: ", t, "ms")
					g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: t,
					})
					resultAccess.Lock()
					result[tag] = t
					resultAccess.Unlock()
					return nil, nil
				})
			}
			pb.Wait()
			g.rebuildRankedCandidates()
		}
	}

	g.logger.Info("health check completed: ", len(result), "/", outboundCount, " outbounds available")
	select {
	case <-ctx.Done():
	default:
		g.performUpdateCheck()
	}
	// Hint GC to reclaim batch/goroutine/transport memory after large health check
	if outboundCount > 100 {
		debug.FreeOSMemory()
	}
	return result, nil
}

// storeOutbounds swaps in a new member snapshot (ranking is rebuilt lazily by
// the next health check).
func (g *URLTestGroup) storeOutbounds(outbounds []adapter.Outbound) {
	tags := make([]string, 0, len(outbounds))
	for _, detour := range outbounds {
		tags = append(tags, detour.Tag())
	}
	g.state.Store(&groupState{outbounds: outbounds, tags: tags})
}

// replaceOutbounds applies a provider update. Providers may recreate
// outbound instances under unchanged tags, so the cached selection, ranking
// and manual pin are re-pointed at the new instances; keeping a stale
// instance would dial through an outbound the provider already closed.
func (g *URLTestGroup) replaceOutbounds(outbounds []adapter.Outbound) {
	g.updateAccess.Lock()
	selectedOutboundTCP := g.selectedOutboundTCP.Load()
	selectedOutboundUDP := g.selectedOutboundUDP.Load()
	g.storeOutbounds(outbounds)
	g.rebuildRankedCandidates()
	if pin := g.manualPin.Load(); pin != nil && !containsOutbound(outbounds, pin.outbound) {
		if replacement := outboundByTag(outbounds, pin.tag); replacement != nil {
			g.manualPin.CompareAndSwap(pin, &manualPinData{tag: pin.tag, outbound: replacement})
		} else {
			g.manualPin.CompareAndSwap(pin, nil)
		}
	}
	if !containsOutbound(outbounds, selectedOutboundTCP) {
		g.selectedOutboundTCP.Store(nil)
	}
	if !containsOutbound(outbounds, selectedOutboundUDP) {
		g.selectedOutboundUDP.Store(nil)
	}
	if g.selectedOutboundTCP.Load() == nil {
		if outbound, _ := g.Select(N.NetworkTCP); outbound != nil {
			g.selectedOutboundTCP.Store(outbound)
		}
	}
	if g.selectedOutboundUDP.Load() == nil {
		if outbound, _ := g.Select(N.NetworkUDP); outbound != nil {
			g.selectedOutboundUDP.Store(outbound)
		}
	}
	updated := (selectedOutboundTCP != nil && g.selectedOutboundTCP.Load() != selectedOutboundTCP) ||
		(selectedOutboundUDP != nil && g.selectedOutboundUDP.Load() != selectedOutboundUDP)
	selected := g.selectedOutboundTCP.Load() != selectedOutboundTCP || g.selectedOutboundUDP.Load() != selectedOutboundUDP
	g.updateAccess.Unlock()
	// Same policy as performUpdateCheck: only interrupt when the user opts in.
	if updated && g.interruptExternalConnections {
		g.interruptGroup.Interrupt(true)
	}
	if selected && g.history != nil {
		g.history.NotifyUpdated()
	}
}

// pruneFailureCounters drops health-check and dial failure counters of tags
// that are no longer members.
func (g *URLTestGroup) pruneFailureCounters(tags []string) {
	activeTagSet := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		activeTagSet[tag] = struct{}{}
	}
	g.failureMu.Lock()
	for tag := range g.failureCount {
		if _, exists := activeTagSet[tag]; !exists {
			delete(g.failureCount, tag)
		}
	}
	g.failureMu.Unlock()
	g.dialFailureMu.Lock()
	for tag := range g.dialFailureCount {
		if _, exists := activeTagSet[tag]; !exists {
			delete(g.dialFailureCount, tag)
		}
	}
	g.dialFailureMu.Unlock()
}

func containsOutbound(outbounds []adapter.Outbound, selected adapter.Outbound) bool {
	if selected == nil {
		return true
	}
	return slices.Contains(outbounds, selected)
}

func outboundByTag(outbounds []adapter.Outbound, tag string) adapter.Outbound {
	for _, detour := range outbounds {
		if detour.Tag() == tag {
			return detour
		}
	}
	return nil
}

// urlTestBounded returns once ctx is done even if the outbound ignores
// cancellation, so one unresponsive member cannot hang the whole check.
func urlTestBounded(ctx context.Context, link string, detour N.Dialer, matcher *urltest.StatusMatcher) (uint16, error) {
	testChan := make(chan urlTestResult, 1)
	go func() {
		delay, err := urltest.URLTestWithStatus(ctx, link, detour, matcher)
		testChan <- urlTestResult{delay, err}
	}()
	select {
	case result := <-testChan:
		return result.delay, result.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (g *URLTestGroup) incrementFailure(tag string) int32 {
	g.failureMu.Lock()
	g.failureCount[tag]++
	count := g.failureCount[tag]
	g.failureMu.Unlock()
	return count
}

func (g *URLTestGroup) resetFailure(tag string) {
	g.failureMu.Lock()
	delete(g.failureCount, tag)
	g.failureMu.Unlock()
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	var updated, selected bool
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil {
		currentTCP := g.selectedOutboundTCP.Load()
		if currentTCP == nil || (exists && outbound != currentTCP) {
			if currentTCP != nil {
				updated = true
			}
			g.selectedOutboundTCP.Store(outbound)
			selected = true
		}
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil {
		currentUDP := g.selectedOutboundUDP.Load()
		if currentUDP == nil || (exists && outbound != currentUDP) {
			if currentUDP != nil {
				updated = true
			}
			g.selectedOutboundUDP.Store(outbound)
			selected = true
		}
	}
	if selected {
		g.history.NotifyUpdated()
	}
	if updated {
		var tcpTag, udpTag string
		if tcp := g.selectedOutboundTCP.Load(); tcp != nil {
			tcpTag = tcp.Tag()
		}
		if udp := g.selectedOutboundUDP.Load(); udp != nil {
			udpTag = udp.Tag()
		}
		g.logger.Info("selected outbound updated, TCP: ", tcpTag, ", UDP: ", udpTag)
		// Only interrupt existing connections when the user opts in.
		// Mihomo's urltest never interrupts active connections on selection change —
		// new connections use the new choice, in-flight ones finish naturally.
		// Unconditional Interrupt here was the primary cause of "connection drops
		// every few minutes" reported by users.
		if g.interruptExternalConnections {
			g.interruptGroup.Interrupt(true)
		}
	}
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestSessionKey struct {
	tag     string
	link    string
	matcher *urltest.StatusMatcher
}

type urlTestSessionCall struct {
	done   chan struct{}
	result urlTestResult
}

type urlTestSession struct {
	access sync.Mutex
	calls  map[urlTestSessionKey]*urlTestSessionCall
}

type urlTestSessionContextKey struct{}

type recursiveURLTestGroup interface {
	adapter.OutboundGroup
	urlTest(ctx context.Context, force bool) (map[string]uint16, error)
}

func urlTestSessionFromContext(ctx context.Context) (context.Context, *urlTestSession) {
	if session, loaded := ctx.Value(urlTestSessionContextKey{}).(*urlTestSession); loaded {
		return ctx, session
	}
	session := &urlTestSession{calls: make(map[urlTestSessionKey]*urlTestSessionCall)}
	return context.WithValue(ctx, urlTestSessionContextKey{}, session), session
}

func (s *urlTestSession) test(ctx context.Context, key urlTestSessionKey, test func() urlTestResult) (result urlTestResult) {
	s.access.Lock()
	call, loaded := s.calls[key]
	if !loaded {
		call = &urlTestSessionCall{done: make(chan struct{})}
		s.calls[key] = call
	}
	s.access.Unlock()
	if loaded {
		select {
		case <-call.done:
			return call.result
		case <-ctx.Done():
			return urlTestResult{err: ctx.Err()}
		}
	}
	defer func() {
		call.result = result
		close(call.done)
	}()
	return test()
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  adapter.URLTestHistoryStorage
	logger   log.Logger
	session  *urlTestSession
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history adapter.URLTestHistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	ctx, session := urlTestSessionFromContext(ctx)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		session:  session,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundGroup, N.NetworkTCP))
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case recursiveURLTestGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nestedResult, _ := nested.urlTest(b.ctx, force)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				testResult := b.session.test(b.ctx, urlTestSessionKey{tag: tag, link: link}, func() urlTestResult {
					testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
					defer cancel()
					testChan := make(chan urlTestResult, 1)
					go func() {
						delay, testErr := urltest.URLTest(testCtx, link, detour)
						testChan <- urlTestResult{delay, testErr}
					}()
					select {
					case testResult := <-testChan:
						return testResult
					case <-testCtx.Done():
						return urlTestResult{err: testCtx.Err()}
					}
				})
				if testResult.err != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.history.DeleteURLTestHistory(tag)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}
