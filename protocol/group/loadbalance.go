package group

import (
	"context"
	"net"
	"net/netip"
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
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/net/publicsuffix"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.LoadBalanceOutboundOptions](registry, C.TypeLoadBalance, NewLoadBalance)
}

var _ adapter.OutboundGroup = (*LoadBalance)(nil)

const (
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"

	lbMaxBatchConcurrency   = 16
	lbMaxFailoverCandidates = 10

	// Dial failures that trigger a proactive re-check (mihomo parity).
	lbDialFailureThreshold = 5

	// Lenient alive window: mihomo doesn't hard-expire history; we use
	// a wider window than the original 2*interval to prevent flapping
	// when the test URL is temporarily blocked.
	lbAliveGraceMultiplier = 4
)

type LoadBalance struct {
	outbound.Adapter
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	ttl                          time.Duration
	group                        *LoadBalanceGroup
	interruptExternalConnections bool
	strategy                     string

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

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.LoadBalanceOutboundOptions) (adapter.Outbound, error) {
	strategy := options.Strategy
	if strategy == "" {
		strategy = StrategyRoundRobin
	}
	switch strategy {
	case StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions:
	default:
		return nil, E.New("load-balance strategy not found: ", strategy)
	}
	outbound := &LoadBalance{
		Adapter:                      outbound.NewAdapter(C.TypeLoadBalance, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		ttl:                          time.Duration(options.TTL),
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
		strategy:                     strategy,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	return outbound, nil
}

func (s *LoadBalance) Start() error {
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
	group, err := NewLoadBalanceGroup(s.ctx, s.outbound, s.logger, outbounds, tags, s.link, s.interval, s.idleTimeout, s.ttl, s.interruptExternalConnections, s.strategy)
	if err != nil {
		return err
	}
	s.group = group
	return nil
}

func (s *LoadBalance) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *LoadBalance) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *LoadBalance) Now() string {
	return ""
}

func (s *LoadBalance) All() []string {
	snap := s.group.state.Load()
	if snap == nil {
		return nil
	}
	result := make([]string, len(snap.tags))
	copy(result, snap.tags)
	return result
}

func (s *LoadBalance) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *LoadBalance) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

func (s *LoadBalance) isGroupActive() bool {
	if !s.group.started.Load() {
		return false
	}
	return time.Since(s.group.lastActive.Load()) <= s.group.idleTimeout
}

func (s *LoadBalance) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	metadata := adapter.ContextFrom(ctx)
	outbound := s.group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), network) {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.AppendRealOutbound(outbound.Tag())
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	// Failover from alive list
	failedTag := outbound.Tag()
	candidates := s.group.getFailoverCandidates(failedTag)
	for _, detour := range candidates {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		conn, err = detour.DialContext(ctx, network, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			if metadata != nil {
				metadata.AppendRealOutbound(detour.Tag())
			}
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, E.New("all outbounds failed for ", network, " to ", destination)
}

func (s *LoadBalance) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	metadata := adapter.ContextFrom(ctx)
	outbound := s.group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), N.NetworkUDP) {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.AppendRealOutbound(outbound.Tag())
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, "primary outbound ", outbound.Tag(), " failed: ", err)
	failedTag := outbound.Tag()
	candidates := s.group.getFailoverCandidates(failedTag)
	for _, detour := range candidates {
		if !common.Contains(detour.Network(), N.NetworkUDP) {
			continue
		}
		conn, err = detour.ListenPacket(ctx, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			if metadata != nil {
				metadata.AppendRealOutbound(detour.Tag())
			}
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, E.New("all outbounds failed for UDP to ", destination)
}

func (s *LoadBalance) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	s.group.Touch()
	selected := s.group.Unwrap(&metadata, true)
	if selected == nil {
		return nil, E.New("missing supported outbound")
	}
	if !common.Contains(selected.Network(), metadata.Network) {
		return nil, E.New(metadata.Network, " is not supported by outbound: ", selected.Tag())
	}
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
}

func (s *LoadBalance) onProviderUpdated(tag string) error {
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
	// Atomic snapshot swap
	s.group.state.Store(&lbState{outbounds: outbounds, tags: tags, outboundByTag: make(map[string]adapter.Outbound)})
	// Build tag→outbound index for strategies
	s.group.rebuildOutboundIndex()
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

type strategyFn = func(metadata *adapter.InboundContext, touch bool) adapter.Outbound

// lbState is a single immutable snapshot containing ALL LoadBalance group data.
type lbState struct {
	outbounds     []adapter.Outbound
	tags          []string
	alive         []adapter.Outbound          // sorted by delay
	outboundByTag map[string]adapter.Outbound // for sticky-sessions tag lookup
}

type LoadBalanceGroup struct {
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	ttl                          time.Duration
	history                      adapter.URLTestHistoryStorage
	checking                     atomic.Bool
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	// Single atomic state — all group data in one pointer
	state atomic.Pointer[lbState]

	access       sync.Mutex
	ticker       *time.Ticker
	close        chan struct{}
	started      atomic.Bool
	lastActive   common.TypedValue[time.Time]
	failureMu    sync.Mutex
	failureCount map[string]int32

	// Dial-failure tracking for proactive health re-check (mihomo parity).
	dialFailureMu    sync.Mutex
	dialFailureCount map[string]int32
	dialFailureAt    time.Time
	dialRecheckOnce  atomic.Bool

	strategyFn strategyFn
}

func NewLoadBalanceGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, tags []string, link string, interval time.Duration, idleTimeout time.Duration, ttl time.Duration, interruptExternalConnections bool, strategy string) (*LoadBalanceGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if ttl == 0 {
		ttl = time.Minute * 10
	}
	var history adapter.URLTestHistoryStorage
	if historyFromCtx := service.PtrFromContext[urltest.HistoryStorage](ctx); historyFromCtx != nil {
		history = historyFromCtx
	} else if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	g := &LoadBalanceGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		link:                         link,
		interval:                     interval,
		idleTimeout:                  idleTimeout,
		ttl:                          ttl,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		failureCount:                 make(map[string]int32),
		dialFailureCount:             make(map[string]int32),
	}
	index := make(map[string]adapter.Outbound, len(outbounds))
	for _, o := range outbounds {
		index[o.Tag()] = o
	}
	g.state.Store(&lbState{outbounds: outbounds, tags: tags, outboundByTag: index})
	switch strategy {
	case StrategyRoundRobin:
		g.strategyFn = strategyRoundRobin(g)
	case StrategyConsistentHashing:
		g.strategyFn = strategyConsistentHashing(g)
	case StrategyStickySessions:
		lruSize := uint32(len(outbounds) * 2)
		if lruSize < 4096 {
			lruSize = 4096
		}
		g.strategyFn = strategyStickySessions(g, lruSize)
	}
	return g, nil
}

func (g *LoadBalanceGroup) rebuildOutboundIndex() {
	st := g.state.Load()
	if st == nil {
		return
	}
	index := make(map[string]adapter.Outbound, len(st.outbounds))
	for _, o := range st.outbounds {
		index[o.Tag()] = o
	}
	g.state.Store(&lbState{
		outbounds:     st.outbounds,
		tags:          st.tags,
		alive:         st.alive,
		outboundByTag: index,
	})
}

// IsAlive checks if an outbound has a recent successful health check.
// Uses a lenient window (lbAliveGraceMultiplier * interval) to match mihomo's
// resilience: a single test-URL blockage shouldn't make all nodes look dead.
// Dial-failure tracking (see reportDialFailure) provides a faster feedback loop
// for nodes that are actually broken.
func (g *LoadBalanceGroup) IsAlive(proxy adapter.Outbound) bool {
	history := g.history.LoadURLTestHistory(RealTag(proxy))
	if history == nil {
		// No history at all — for a node that's never been tested, assume it might
		// work (mihomo behaviour). The alive-list rebuild will eventually refine.
		return false
	}
	// Also exclude nodes with excessive dial failures.
	if g.hasExcessiveDialFailures(proxy.Tag()) {
		return false
	}
	return time.Since(history.Time) < time.Duration(lbAliveGraceMultiplier)*g.interval
}

func (g *LoadBalanceGroup) hasExcessiveDialFailures(tag string) bool {
	g.dialFailureMu.Lock()
	defer g.dialFailureMu.Unlock()
	return g.dialFailureCount[tag] >= lbDialFailureThreshold
}

// reportDialFailure is called by DialContext/ListenPacket on a failed dial.
func (g *LoadBalanceGroup) reportDialFailure(tag string) {
	g.dialFailureMu.Lock()
	if !g.dialFailureAt.IsZero() && time.Since(g.dialFailureAt) > g.interval {
		for k := range g.dialFailureCount {
			delete(g.dialFailureCount, k)
		}
	}
	g.dialFailureCount[tag]++
	count := g.dialFailureCount[tag]
	g.dialFailureAt = time.Now()
	g.dialFailureMu.Unlock()

	if count >= lbDialFailureThreshold {
		if g.dialRecheckOnce.CompareAndSwap(false, true) {
			go func() {
				defer g.dialRecheckOnce.Store(false)
				g.CheckOutbounds(true)
			}()
		}
	}
}

// reportDialSuccess clears the dial-failure counter for tag.
func (g *LoadBalanceGroup) reportDialSuccess(tag string) {
	g.dialFailureMu.Lock()
	delete(g.dialFailureCount, tag)
	g.dialFailureMu.Unlock()
}

// rebuildAliveList filters alive outbounds and stores in a single atomic state swap.
// Fallback tier: if no outbound passes IsAlive, include those with any history at all —
// better to route through a questionable node than to drop the connection entirely.
func (g *LoadBalanceGroup) rebuildAliveList() {
	st := g.state.Load()
	if st == nil {
		return
	}
	alive := make([]adapter.Outbound, 0, len(st.outbounds))
	var stale []adapter.Outbound // has history but past the alive window

	for _, o := range st.outbounds {
		if g.IsAlive(o) {
			alive = append(alive, o)
		} else if h := g.history.LoadURLTestHistory(RealTag(o)); h != nil && !g.hasExcessiveDialFailures(o.Tag()) {
			stale = append(stale, o)
		}
	}

	// If no alive nodes, fall back to stale-but-present nodes.
	if len(alive) == 0 && len(stale) > 0 {
		alive = stale
		g.logger.Debug("no fresh alive nodes, using ", len(stale), " stale-history nodes")
	}

	sort.Slice(alive, func(i, j int) bool {
		hi := g.history.LoadURLTestHistory(RealTag(alive[i]))
		hj := g.history.LoadURLTestHistory(RealTag(alive[j]))
		if hi == nil {
			return false
		}
		if hj == nil {
			return true
		}
		return hi.Delay < hj.Delay
	})
	g.state.Store(&lbState{
		outbounds:     st.outbounds,
		tags:          st.tags,
		alive:         alive,
		outboundByTag: st.outboundByTag,
	})
}

// getAlive returns the current alive outbound list (lock-free).
func (g *LoadBalanceGroup) getAlive() []adapter.Outbound {
	st := g.state.Load()
	if st == nil {
		return nil
	}
	return st.alive
}

// getFailoverCandidates returns up to lbMaxFailoverCandidates alive outbounds excluding the failed one.
func (g *LoadBalanceGroup) getFailoverCandidates(excludeTag string) []adapter.Outbound {
	alive := g.getAlive()
	if len(alive) == 0 {
		return nil
	}
	cap := lbMaxFailoverCandidates
	if len(alive) < cap {
		cap = len(alive)
	}
	result := make([]adapter.Outbound, 0, cap)
	for _, o := range alive {
		if o.Tag() == excludeTag {
			continue
		}
		result = append(result, o)
		if len(result) >= lbMaxFailoverCandidates {
			break
		}
	}
	return result
}

func (g *LoadBalanceGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *LoadBalanceGroup) Touch() {
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

func (g *LoadBalanceGroup) Close() error {
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

func (g *LoadBalanceGroup) loopCheck() {
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

func (g *LoadBalanceGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *LoadBalanceGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, false)
}

func (g *LoadBalanceGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	if g.checking.Swap(true) {
		return nil, nil
	}
	defer g.checking.Store(false)

	snap := g.state.Load()
	if snap == nil {
		return nil, nil
	}
	outbounds := snap.outbounds
	outboundCount := len(outbounds)
	result := make(map[string]uint16, outboundCount)

	// Scale batch timeout with outbound count
	batchTimeout := g.interval
	if scaled := time.Duration(outboundCount/lbMaxBatchConcurrency+1) * C.TCPTimeout * 2; scaled > batchTimeout {
		batchTimeout = scaled
	}
	if batchTimeout > 10*time.Minute {
		batchTimeout = 10 * time.Minute
	}
	if batchTimeout < 2*C.TCPTimeout {
		batchTimeout = 2 * C.TCPTimeout
	}
	batchCtx, batchCancel := context.WithTimeout(g.ctx, batchTimeout)
	defer batchCancel()

	concurrency := outboundCount
	if concurrency > lbMaxBatchConcurrency {
		concurrency = lbMaxBatchConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}
	b, _ := batch.New(batchCtx, batch.WithConcurrencyNum[any](concurrency))
	checked := make(map[string]bool, outboundCount)
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
			testCtx, cancel := context.WithTimeout(batchCtx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(testCtx, g.link, p)
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				// DO NOT delete history — preserve mihomo-parity resilience.
				// The alive-list rebuild uses a wide time window; a single test-URL
				// blockage won't make otherwise-working nodes look dead.
				if cnt := g.incrementFailure(realTag); cnt == 3 {
					g.logger.Info("outbound ", tag, " test failed ", cnt, " times (history retained)")
				}
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
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
	g.rebuildAliveList()
	g.logger.Info("health check completed: ", len(result), "/", outboundCount, " outbounds available")
	if outboundCount > 100 {
		debug.FreeOSMemory()
	}
	return result, nil
}

func (g *LoadBalanceGroup) incrementFailure(tag string) int32 {
	g.failureMu.Lock()
	g.failureCount[tag]++
	count := g.failureCount[tag]
	g.failureMu.Unlock()
	return count
}

func (g *LoadBalanceGroup) resetFailure(tag string) {
	g.failureMu.Lock()
	delete(g.failureCount, tag)
	g.failureMu.Unlock()
}

func (g *LoadBalanceGroup) Unwrap(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	return g.strategyFn(metadata, touch)
}

// --- Utility functions ---

func getKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	var metadataHost string
	if metadata.Destination.IsDomain() {
		metadataHost = metadata.Destination.Fqdn
	} else if metadata.SniffHost != "" {
		metadataHost = metadata.SniffHost
	} else {
		metadataHost = metadata.Domain
	}
	if metadataHost != "" {
		if ip := net.ParseIP(metadataHost); ip != nil {
			return metadataHost
		}
		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadataHost); err == nil {
			return etld
		}
	}
	var destinationAddr netip.Addr
	if len(metadata.DestinationAddresses) > 0 {
		destinationAddr = metadata.DestinationAddresses[0]
	} else {
		destinationAddr = metadata.Destination.Addr
	}
	if !destinationAddr.IsValid() {
		return ""
	}
	return destinationAddr.String()
}

func getKeyWithSrcAndDst(metadata *adapter.InboundContext) string {
	dst := getKey(metadata)
	if metadata == nil {
		return dst
	}
	src := metadata.Source.Addr.String()
	return src + dst
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64
	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}
	return int32(b)
}

// --- Strategies: all operate on alive list, not full outbound list ---

func strategyRoundRobin(g *LoadBalanceGroup) strategyFn {
	var idx atomic.Uint64
	return func(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
		alive := g.getAlive()
		length := len(alive)
		if length == 0 {
			// No alive nodes — fallback to first from snapshot
			snap := g.state.Load()
			if snap != nil && len(snap.outbounds) > 0 {
				return snap.outbounds[0]
			}
			return nil
		}
		if touch {
			current := idx.Add(1)
			return alive[int(current-1)%length]
		}
		current := idx.Load()
		return alive[int(current)%length]
	}
}

func strategyConsistentHashing(g *LoadBalanceGroup) strategyFn {
	hash := maphash.NewHasher[string]()
	return func(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
		alive := g.getAlive()
		if len(alive) == 0 {
			snap := g.state.Load()
			if snap != nil && len(snap.outbounds) > 0 {
				return snap.outbounds[0]
			}
			return nil
		}
		key := hash.Hash(getKey(metadata))
		buckets := int32(len(alive))
		// Adaptive retry: min(alive count, 32)
		maxRetry := len(alive)
		if maxRetry > 32 {
			maxRetry = 32
		}
		for i := 0; i < maxRetry; i++ {
			idx := jumpHash(key+uint64(i), buckets)
			return alive[idx]
		}
		return alive[0]
	}
}

func strategyStickySessions(g *LoadBalanceGroup, lruSize uint32) strategyFn {
	// LRU stores outbound TAG (string), not index — survives provider updates
	lruCache := common.Must1(freelru.NewSharded[uint64, string](lruSize, maphash.NewHasher[uint64]().Hash32))
	lruCache.SetLifetime(g.ttl)
	hash := maphash.NewHasher[string]()

	return func(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
		alive := g.getAlive()
		if len(alive) == 0 {
			snap := g.state.Load()
			if snap != nil && len(snap.outbounds) > 0 {
				return snap.outbounds[0]
			}
			return nil
		}

		key := hash.Hash(getKeyWithSrcAndDst(metadata))

		// Check LRU: if cached tag still alive, use it
		if cachedTag, has := lruCache.Get(key); has {
			st := g.state.Load()
			if st != nil && st.outboundByTag != nil {
				if outbound, ok := st.outboundByTag[cachedTag]; ok && g.IsAlive(outbound) {
					return outbound
				}
			}
		}

		// Deterministic probing on alive list
		buckets := int32(len(alive))
		maxRetry := len(alive)
		if maxRetry > 32 {
			maxRetry = 32
		}
		for i := 0; i < maxRetry; i++ {
			idx := jumpHash(key+uint64(i), buckets)
			proxy := alive[idx]
			lruCache.Add(key, proxy.Tag())
			return proxy
		}

		selected := alive[0]
		lruCache.Add(key, selected.Tag())
		return selected
	}
}
