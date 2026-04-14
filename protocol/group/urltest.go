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

const (
	maxScreeningConcurrency = 16 // Phase 1: coarse screening — balanced speed vs memory
	maxPrecisionConcurrency = 2  // Phase 2: precision retest — minimal concurrency for accuracy
	maxPrecisionCandidates  = 8  // Number of top candidates to retest
	maxFailoverCandidates   = 10
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
	}
	if options.Fallback.Enabled {
		outbound.fallback = URLTestFallback{
			enabled:  true,
			maxDelay: uint16(time.Duration(options.Fallback.MaxDelay).Milliseconds()),
		}
	}
	return outbound, nil
}

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
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, tags, s.link, s.interval, s.tolerance, s.idleTimeout, s.fallback, s.interruptExternalConnections)
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
	if tcp := s.group.selectedOutboundTCP.Load(); tcp != nil {
		return tcp.Tag()
	} else if udp := s.group.selectedOutboundUDP.Load(); udp != nil {
		return udp.Tag()
	}
	return ""
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
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
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
	case N.NetworkTCP:
		outbound = s.group.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		outbound = s.group.selectedOutboundUDP.Load()
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	// Failover: try top-N ranked healthy outbounds (not all 3000+)
	candidates := s.group.getFailoverCandidates(N.NetworkName(network), outbound.Tag())
	for _, detour := range candidates {
		conn, err = detour.DialContext(ctx, network, destination)
		if err == nil {
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
	}
	return nil, E.New("all outbounds failed for ", network, " to ", destination)
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.selectedOutboundUDP.Load()
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	// Failover: try top-N ranked healthy outbounds
	candidates := s.group.getFailoverCandidates(N.NetworkUDP, outbound.Tag())
	for _, detour := range candidates {
		conn, err = detour.ListenPacket(ctx, destination)
		if err == nil {
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
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
	selected := s.group.selectedOutboundTCP.Load()
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

	// Reusable maps — allocated once, cleared each cycle (avoid per-check allocation)
	reusableChecked map[string]bool
	reusableResult  map[string]uint16

	fallback URLTestFallback
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, tags []string, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, fallback URLTestFallback, interruptExternalConnections bool) (*URLTestGroup, error) {
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
		reusableChecked:              make(map[string]bool, len(outbounds)),
		reusableResult:               make(map[string]uint16, len(outbounds)),
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
func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	// Fast path: use pre-sorted ranked candidates from state
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
	if len(candidates) > 0 {
		best := candidates[0]
		// Check if current selection is still within tolerance
		var current adapter.Outbound
		switch network {
		case N.NetworkTCP:
			current = g.selectedOutboundTCP.Load()
		case N.NetworkUDP:
			current = g.selectedOutboundUDP.Load()
		}
		if current != nil {
			if currentHistory := g.history.LoadURLTestHistory(RealTag(current)); currentHistory != nil {
				if currentHistory.Delay <= best.delay+g.tolerance {
					return current, true
				}
			}
		}
		// Apply fallback filtering
		if g.fallback.enabled && g.fallback.maxDelay > 0 {
			for _, c := range candidates {
				if c.delay <= g.fallback.maxDelay {
					return c.outbound, true
				}
			}
			// All exceed maxDelay — return best anyway
		}
		return best.outbound, true
	}
	// Slow path: no ranked data yet — full scan (only on startup before first check)
	return g.selectFullScan(network)
}

// selectFullScan is the original O(N) selection, used only before the first health check completes.
func (g *URLTestGroup) selectFullScan(network string) (adapter.Outbound, bool) {
	snap := g.getState()
	if snap == nil {
		return nil, false
	}
	var minDelay uint16
	var minOutbound adapter.Outbound
	for _, detour := range snap.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour))
		if history == nil {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range snap.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
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
			t, err := urltest.URLTest(testCtx, g.link, p)
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				if g.incrementFailure(realTag) >= 3 {
					g.history.DeleteURLTestHistory(realTag)
					g.logger.Info("outbound ", tag, " marked unavailable after consecutive failures")
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
					t, err := urltest.URLTest(testCtx, g.link, p)
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
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}
