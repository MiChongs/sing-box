package group

import (
	"context"
	"net"
	"regexp"
	"runtime/debug"
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
	tun "github.com/sagernet/sing-tun"
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

var _ adapter.OutboundGroup = (*URLTest)(nil)

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
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	fallback                     URLTestFallback
	group                        *URLTestGroup
	interruptExternalConnections bool
	// expectedStatus mihomo 对齐的状态码 matcher。nil = 旧启发式。
	// NewURLTest 时 Parse，失败阻断启动；loopCheckOutbounds 里每次探测透传。
	expectedStatus *urltest.StatusMatcher

	provider         adapter.ProviderManager
	providers        map[string]adapter.Provider
	outboundsCacheMu sync.Mutex
	outboundsCache   map[string][]adapter.Outbound
	cancelAccess     sync.Mutex
	cancel           context.CancelFunc

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
	hidden          bool
	icon            string
}

type URLTestFallback struct {
	enabled  bool
	maxDelay uint16
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
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
			maxDelay: uint16(time.Duration(options.Fallback.MaxDelay).Milliseconds()),
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

func (s *URLTest) Start() error {
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			provider.RegisterCallback(s.onProviderUpdated)
		}
		s.providerTags = providerTags
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
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) Now() string {
	if pin := s.group.manualPin.Load(); pin != nil {
		return pin.tag
	}
	if tcp := s.group.selectedOutboundTCP.Load(); tcp != nil {
		return tcp.Tag()
	} else if udp := s.group.selectedOutboundUDP.Load(); udp != nil {
		return udp.Tag()
	}
	return ""
}

// Selected reports the user's manually-pinned outbound tag, or "" when the
// group is running on automatic selection. Mirrors Smart.Selected semantics so
// dashboards can render the pinned / fixed state uniformly across group types.
func (s *URLTest) Selected() string {
	if pin := s.group.manualPin.Load(); pin != nil {
		return pin.tag
	}
	return ""
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
		return true
	}
	detour := s.group.findOutboundByTag(tag)
	if detour == nil {
		return false
	}
	prev := s.group.manualPin.Swap(&manualPinData{tag: tag, outbound: detour})
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
	if s.group.clearManualPin() {
		s.logger.Info("manual pin released by user speed test")
	}
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	// User-triggered via gRPC/libbox — release the manual pin before
	// running. Internal callers use g.CheckOutbounds directly and must
	// preserve the pin.
	if s.group.clearManualPin() {
		s.logger.Info("manual pin released by user speed test")
	}
	s.group.CheckOutbounds(true)
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
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
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
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
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
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
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
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, E.New("all outbounds failed for UDP to ", destination)
}

func (s *URLTest) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	s.group.Touch()
	var selected adapter.Outbound
	if pinned := s.group.pinnedOutbound(metadata.Network); pinned != nil {
		selected = pinned
	} else {
		selected = s.group.selectedOutboundTCP.Load()
	}
	if selected == nil {
		selected, _ = s.group.Select(N.NetworkTCP)
	}
	if selected == nil {
		return nil, E.New("missing supported outbound")
	}
	if !common.Contains(selected.Network(), metadata.Network) {
		return nil, E.New(metadata.Network, " is not supported by outbound: ", selected.Tag())
	}
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	_, loaded := s.providers[tag]
	if !loaded {
		return E.New("outbound provider not found: ", tag)
	}
	var (
		tags      = s.Dependencies()
		outbounds []adapter.Outbound
	)
	for _, tag := range tags {
		detour, _ := s.outbound.Outbound(tag)
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
			tag := detour.Tag()
			if s.exclude != nil && s.exclude.MatchString(tag) {
				continue
			}
			if s.include != nil && !s.include.MatchString(tag) {
				continue
			}
			tags = append(tags, tag)
			cache = append(cache, detour)
		}
		outbounds = append(outbounds, cache...)
		s.outboundsCache[providerTag] = cache
	}
	s.outboundsCacheMu.Unlock()
	if len(tags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	// Atomic snapshot swap — no lock needed on read path
	s.group.state.Store(&groupState{outbounds: outbounds, tags: tags})
	// Clean stale failure counters
	activeTagSet := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		activeTagSet[t] = struct{}{}
	}
	s.group.failureMu.Lock()
	for k := range s.group.failureCount {
		if _, exists := activeTagSet[k]; !exists {
			delete(s.group.failureCount, k)
		}
	}
	s.group.failureMu.Unlock()
	s.group.dialFailureMu.Lock()
	for k := range s.group.dialFailureCount {
		if _, exists := activeTagSet[k]; !exists {
			delete(s.group.dialFailureCount, k)
		}
	}
	s.group.dialFailureMu.Unlock()
	if s.isGroupActive() {
		s.group.access.Lock()
		if s.group.ticker != nil {
			s.group.ticker.Reset(s.group.interval)
		}
		s.group.access.Unlock()
		s.cancelAccess.Lock()
		ctx, cancel := context.WithCancel(s.ctx)
		if s.cancel != nil {
			s.cancel()
		}
		s.cancel = cancel
		s.cancelAccess.Unlock()
		s.URLTest(ctx)
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
	history                      adapter.URLTestHistoryStorage
	checking                     atomic.Bool
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
	var history adapter.URLTestHistoryStorage
	if historyFromCtx := service.PtrFromContext[urltest.HistoryStorage](ctx); historyFromCtx != nil {
		history = historyFromCtx
	} else if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
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
			if currentHistory := g.history.LoadURLTestHistory(RealTag(current)); currentHistory != nil {
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

		// Rule 3: apply fallback filtering
		if g.fallback.enabled && g.fallback.maxDelay > 0 {
			for _, c := range candidates {
				if c.delay <= g.fallback.maxDelay {
					return c.outbound, true
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
		history := g.history.LoadURLTestHistory(RealTag(detour))
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
	snap := g.getState()
	if snap == nil {
		return
	}
	var tcpRanked, udpRanked []rankedOutbound
	for _, detour := range snap.outbounds {
		history := g.history.LoadURLTestHistory(RealTag(detour))
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
	// Atomic swap: single pointer update replaces all ranked data
	g.state.Store(&groupState{
		outbounds: snap.outbounds,
		tags:      snap.tags,
		rankedTCP: tcpRanked,
		rankedUDP: udpRanked,
	})
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
	if g.checking.Swap(true) {
		return nil, nil
	}
	defer g.checking.Store(false)

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
		realTag := RealTag(detour)
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
			testCtx, cancel := context.WithTimeout(screenCtx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTestWithStatus(testCtx, g.link, p, g.expectedStatus)
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
				realTag := RealTag(candidate.outbound)
				p, loaded := g.outbound.Outbound(realTag)
				if !loaded {
					continue
				}
				pb.Go(realTag, func() (any, error) {
					testCtx, cancel := context.WithTimeout(precisionCtx, C.TCPTimeout)
					defer cancel()
					t, err := urltest.URLTestWithStatus(testCtx, g.link, p, g.expectedStatus)
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
	var updated bool
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil {
		currentTCP := g.selectedOutboundTCP.Load()
		if currentTCP == nil || (exists && outbound != currentTCP) {
			if currentTCP != nil {
				updated = true
			}
			g.selectedOutboundTCP.Store(outbound)
		}
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil {
		currentUDP := g.selectedOutboundUDP.Load()
		if currentUDP == nil || (exists && outbound != currentUDP) {
			if currentUDP != nil {
				updated = true
			}
			g.selectedOutboundUDP.Store(outbound)
		}
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
