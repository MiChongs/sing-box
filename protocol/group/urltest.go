package group

import (
	"context"
	"maps"
	"net"
	"regexp"
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

const (
	// urlTestFailureThreshold is the number of consecutive failed health
	// checks after which a member's delay history is dropped. Tolerating a
	// few failures keeps a working selection when only the test URL is
	// briefly unreachable.
	urlTestFailureThreshold = 3
	// urlTestDialFailureThreshold is the number of failed dials through a
	// member that triggers an immediate health check of the group.
	urlTestDialFailureThreshold = 5
	// urlTestFailoverCandidates bounds how many other members a failed dial
	// is retried on.
	urlTestFailoverCandidates = 10
	// After each health check the fastest members are measured again with
	// low concurrency, so the final ranking is not skewed by probes that
	// competed for bandwidth.
	urlTestPrecisionCandidates  = 8
	urlTestPrecisionConcurrency = 2
)

// urlTestManualPin is the member the user selected on a URLTest group. It
// survives periodic and failure-triggered health checks and is released by
// the next user-triggered URL test.
type urlTestManualPin struct {
	tag      string
	outbound adapter.Outbound
}

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.PreMatchOutboundGroup   = (*URLTest)(nil)
	_ adapter.OutboundGroupHint       = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	fallback                     URLTestFallback
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
	providerAccess               sync.Mutex
	providerUpdateCheck          providerUpdateCheckScheduler
	expectedStatus               *urltest.StatusMatcher

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

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
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
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
	expectedStatus, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, err
	}
	outbound.expectedStatus = expectedStatus
	return outbound, nil
}

func (s *URLTest) Hidden() bool {
	return s.hidden
}

func (s *URLTest) Icon() string {
	return s.icon
}

func (s *URLTest) Start() error {
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
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	if len(s.tags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		s.tags = append(s.tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.fallback, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	group.expectedStatus = s.expectedStatus
	group.loadSavedPin = s.loadSavedPin
	s.group = group
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	return nil
}

func (s *URLTest) PostStart() error {
	s.restoreManualPin()
	s.group.PostStart()
	return nil
}

// restoreManualPin re-applies the selection saved by SelectOutbound. Like
// Selector, the saved selection is kept while its member is missing (e.g. a
// provider has not loaded yet) and applied again once the member is back.
func (s *URLTest) restoreManualPin() {
	if tag := s.group.restoreManualPin(); tag != "" {
		s.logger.Info("restored selection ", tag)
	}
}

func (s *URLTest) loadSavedPin() string {
	if s.Tag() == "" {
		return ""
	}
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile == nil {
		return ""
	}
	return cacheFile.LoadSelected(s.Tag())
}

// persistManualPin saves the pin (or its removal, for an empty tag) so it
// survives restarts.
func (s *URLTest) persistManualPin(tag string) {
	if s.Tag() == "" {
		return
	}
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile == nil {
		return
	}
	err := cacheFile.StoreSelected(s.Tag(), tag)
	if err != nil {
		s.logger.Error("store selected: ", err)
	}
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
	selectedOutboundTCP := s.group.selectedOutboundTCP.Load()
	if selectedOutboundTCP != nil {
		return selectedOutboundTCP.Tag()
	}
	selectedOutboundUDP := s.group.selectedOutboundUDP.Load()
	if selectedOutboundUDP != nil {
		return selectedOutboundUDP.Tag()
	}
	return ""
}

// Selected returns the manually selected member, or "" when the group selects
// automatically.
func (s *URLTest) Selected() string {
	if pin := s.group.manualPin.Load(); pin != nil {
		return pin.tag
	}
	return ""
}

// SelectOutbound pins tag as the selected member until the next user-triggered
// URL test; an empty tag returns to automatic selection. It returns false when
// tag is not a member of the group.
func (s *URLTest) SelectOutbound(tag string) bool {
	if tag == "" {
		// Also clear a saved selection that was not restored into memory.
		s.persistManualPin("")
		if s.group.clearManualPin() {
			s.logger.Info("selection released")
			s.group.performUpdateCheck()
		}
		return true
	}
	if !s.group.setManualPin(tag) {
		return false
	}
	s.persistManualPin(tag)
	s.logger.Info("selected ", tag)
	s.group.interruptGroup.Interrupt(s.interruptExternalConnections)
	return true
}

// releaseManualPin is called by user-triggered URL tests, which end a manual
// selection.
func (s *URLTest) releaseManualPin() {
	if s.group.clearManualPin() {
		s.logger.Info("selection released by URL test")
	}
	s.persistManualPin("")
}

func (s *URLTest) All() []string {
	outbounds := s.group.loadOutbounds()
	tags := make([]string, 0, len(outbounds))
	for _, detour := range outbounds {
		tags = append(tags, detour.Tag())
	}
	return tags
}

func (s *URLTest) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	s.group.Touch()
	network := metadata.Network
	if network == N.NetworkICMP {
		network = N.NetworkTCP
	}
	selectedOutbound := s.group.pinnedOutbound(network)
	if selectedOutbound == nil {
		switch network {
		case N.NetworkTCP:
			selectedOutbound = s.group.selectedOutboundTCP.Load()
		case N.NetworkUDP:
			selectedOutbound = s.group.selectedOutboundUDP.Load()
		}
	}
	if selectedOutbound == nil {
		selectedOutbound, _ = s.group.Select(network)
	}
	return selectOutbound(selectedOutbound)
}

// URLTest is the user-triggered test (Clash API group delay); it releases a
// manual selection. Internal checks go through the group directly.
func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	s.releaseManualPin()
	return s.group.URLTest(ctx)
}

func (s *URLTest) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	return s.group.urlTest(ctx, force)
}

// CheckOutbounds is the user-triggered test from the daemon API; it releases
// a manual selection.
func (s *URLTest) CheckOutbounds() {
	s.releaseManualPin()
	s.group.CheckOutbounds(s.ctx, true)
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
		group.CheckOutbounds(ctx, true)
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
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	outbound := s.group.selectedOutbound(network)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, err)
	for _, detour := range s.group.failoverCandidates(network, outbound) {
		if ctx.Err() != nil {
			break
		}
		conn, err = detour.DialContext(ctx, network, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.selectedOutbound(N.NetworkUDP)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	s.group.reportDialFailure(outbound.Tag())
	s.logger.ErrorContext(ctx, err)
	for _, detour := range s.group.failoverCandidates(N.NetworkUDP, outbound) {
		if ctx.Err() != nil {
			break
		}
		conn, err = detour.ListenPacket(ctx, destination)
		if err == nil {
			s.group.reportDialSuccess(detour.Tag())
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		s.group.reportDialFailure(detour.Tag())
	}
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	_, outbounds, outboundsCache, err := collectProviderOutbounds(
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
	if s.isGroupActive() {
		s.group.access.Lock()
		if s.group.ticker != nil {
			s.group.ticker.Reset(s.group.interval)
		}
		s.group.access.Unlock()
		s.providerUpdateCheck.Schedule(func() {
			_, _ = s.group.urlTestWait(s.ctx, false)
		})
	}
	return nil
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	outboundsAccess              sync.RWMutex
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     sync.Mutex
	selectedOutboundTCP          common.TypedValue[adapter.Outbound]
	selectedOutboundUDP          common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      atomic.Bool
	lastActive                   common.TypedValue[time.Time]

	fallback       URLTestFallback
	expectedStatus *urltest.StatusMatcher

	manualPin    atomic.Pointer[urlTestManualPin]
	loadSavedPin func() string

	failureAccess    sync.Mutex
	probeFailures    map[string]int
	dialFailures     map[string]int
	dialFailureAt    time.Time
	lastDialSuccess  map[string]time.Time
	dialRecheckAlive atomic.Bool
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, fallback URLTestFallback, interruptExternalConnections bool) (*URLTestGroup, error) {
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
	}
	group.storeOutbounds(outbounds)
	return group, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
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
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	if pinned := g.pinnedOutbound(network); pinned != nil {
		return pinned, true
	}
	var minDelay uint16
	var minOutbound adapter.Outbound
	var fallbackIgnoreOutboundDelay uint16
	var fallbackIgnoreOutbound adapter.Outbound
	outbounds := g.loadOutbounds()
	var selectedOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		selectedOutbound = g.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		selectedOutbound = g.selectedOutboundUDP.Load()
	}
	if selectedOutbound != nil {
		if history := g.history.LoadURLTestHistory(RealTag(g.outbound, selectedOutbound)); history != nil {
			minOutbound = selectedOutbound
			minDelay = history.Delay
		} else if g.keepWithoutHistory(outbounds, selectedOutbound) {
			return selectedOutbound, true
		}
	}
	failing := g.failingMembers()
	for _, detour := range outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		realTag := RealTag(g.outbound, detour)
		history := g.history.LoadURLTestHistory(realTag)
		if history == nil {
			continue
		}
		// History kept through a few failed checks only protects the
		// current selection; such members are not picked anew.
		if detour != selectedOutbound && failing[realTag] {
			continue
		}
		if g.fallback.enabled && g.fallback.maxDelay > 0 && history.Delay > g.fallback.maxDelay {
			if fallbackIgnoreOutboundDelay == 0 || history.Delay < fallbackIgnoreOutboundDelay {
				fallbackIgnoreOutboundDelay = history.Delay
				fallbackIgnoreOutbound = detour
			}
			continue
		}
		if g.fallback.enabled {
			minDelay = history.Delay
			minOutbound = detour
			if minDelay == 0 {
				continue
			} else {
				break
			}
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil && fallbackIgnoreOutbound != nil {
		return fallbackIgnoreOutbound, true
	}
	if minOutbound == nil {
		for _, detour := range outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

// selectedOutbound returns the member new connections of network use.
func (g *URLTestGroup) selectedOutbound(network string) adapter.Outbound {
	if pinned := g.pinnedOutbound(network); pinned != nil {
		return pinned
	}
	var outbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		outbound = g.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		outbound = g.selectedOutboundUDP.Load()
	}
	if outbound == nil {
		outbound, _ = g.Select(network)
	}
	return outbound
}

func (g *URLTestGroup) pinnedOutbound(network string) adapter.Outbound {
	pin := g.manualPin.Load()
	if pin == nil || !common.Contains(pin.outbound.Network(), network) {
		return nil
	}
	return pin.outbound
}

// setManualPin pins the member tagged tag and returns false when there is no
// such member.
func (g *URLTestGroup) setManualPin(tag string) bool {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	detour := findOutbound(g.loadOutbounds(), tag)
	if detour == nil {
		return false
	}
	g.manualPin.Store(&urlTestManualPin{tag: tag, outbound: detour})
	g.storePinnedSelection(detour)
	return true
}

func (g *URLTestGroup) clearManualPin() bool {
	return g.manualPin.Swap(nil) != nil
}

// restoreManualPin applies the saved selection when its member is present and
// returns the restored tag.
func (g *URLTestGroup) restoreManualPin() string {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	g.reconcileManualPin(g.loadOutbounds())
	pin := g.manualPin.Load()
	if pin == nil {
		return ""
	}
	g.storePinnedSelection(pin.outbound)
	return pin.tag
}

// reconcileManualPin points the pin at the current instance of its member
// (providers replace instances on update), applies a saved selection whose
// member is present and suspends the pin while its member is missing. The
// caller holds updateAccess.
func (g *URLTestGroup) reconcileManualPin(outbounds []adapter.Outbound) {
	var tag string
	if pin := g.manualPin.Load(); pin != nil {
		tag = pin.tag
	} else if g.loadSavedPin != nil {
		tag = g.loadSavedPin()
	}
	if tag == "" {
		return
	}
	detour := findOutbound(outbounds, tag)
	if detour == nil {
		g.manualPin.Store(nil)
		return
	}
	g.manualPin.Store(&urlTestManualPin{tag: tag, outbound: detour})
}

func (g *URLTestGroup) storePinnedSelection(detour adapter.Outbound) {
	if common.Contains(detour.Network(), N.NetworkTCP) {
		g.selectedOutboundTCP.Store(detour)
	}
	if common.Contains(detour.Network(), N.NetworkUDP) {
		g.selectedOutboundUDP.Store(detour)
	}
}

func findOutbound(outbounds []adapter.Outbound, tag string) adapter.Outbound {
	for _, detour := range outbounds {
		if detour.Tag() == tag {
			return detour
		}
	}
	return nil
}

// keepWithoutHistory reports whether the current selection stays selected
// although its history was dropped: it is still a member, real traffic went
// through it recently and its dials are not failing.
func (g *URLTestGroup) keepWithoutHistory(outbounds []adapter.Outbound, selected adapter.Outbound) bool {
	if !containsOutbound(outbounds, selected) {
		return false
	}
	tag := selected.Tag()
	g.failureAccess.Lock()
	defer g.failureAccess.Unlock()
	if g.dialFailures[tag] >= urlTestDialFailureThreshold {
		return false
	}
	lastSuccess, loaded := g.lastDialSuccess[tag]
	return loaded && time.Since(lastSuccess) < g.interval
}

// reportProbeFailure records a failed health check of tag and reports whether
// its history should be dropped.
func (g *URLTestGroup) reportProbeFailure(tag string) bool {
	g.failureAccess.Lock()
	defer g.failureAccess.Unlock()
	if g.probeFailures == nil {
		g.probeFailures = make(map[string]int)
	}
	g.probeFailures[tag]++
	return g.probeFailures[tag] >= urlTestFailureThreshold
}

func (g *URLTestGroup) reportProbeSuccess(tag string) {
	g.failureAccess.Lock()
	delete(g.probeFailures, tag)
	g.failureAccess.Unlock()
}

// failingMembers returns the members whose latest health checks failed.
func (g *URLTestGroup) failingMembers() map[string]bool {
	g.failureAccess.Lock()
	defer g.failureAccess.Unlock()
	failing := make(map[string]bool, len(g.probeFailures))
	for tag := range g.probeFailures {
		failing[tag] = true
	}
	return failing
}

// reportDialFailure records a failed dial through tag. Enough failures within
// an interval trigger an immediate health check instead of waiting for the
// next scheduled one.
func (g *URLTestGroup) reportDialFailure(tag string) {
	g.failureAccess.Lock()
	if g.dialFailures == nil {
		g.dialFailures = make(map[string]int)
	}
	if !g.dialFailureAt.IsZero() && time.Since(g.dialFailureAt) > g.interval {
		clear(g.dialFailures)
	}
	g.dialFailures[tag]++
	g.dialFailureAt = time.Now()
	failures := g.dialFailures[tag]
	g.failureAccess.Unlock()
	if failures >= urlTestDialFailureThreshold && g.dialRecheckAlive.CompareAndSwap(false, true) {
		go func() {
			defer g.dialRecheckAlive.Store(false)
			g.CheckOutbounds(g.ctx, true)
		}()
	}
}

func (g *URLTestGroup) reportDialSuccess(tag string) {
	g.failureAccess.Lock()
	delete(g.dialFailures, tag)
	if g.lastDialSuccess == nil {
		g.lastDialSuccess = make(map[string]time.Time)
	}
	g.lastDialSuccess[tag] = time.Now()
	g.failureAccess.Unlock()
}

// forgetFailures drops failure records of members no longer in the group.
func (g *URLTestGroup) forgetFailures(outbounds []adapter.Outbound) {
	members := make(map[string]bool, len(outbounds))
	for _, detour := range outbounds {
		members[detour.Tag()] = true
	}
	g.failureAccess.Lock()
	defer g.failureAccess.Unlock()
	for _, failures := range []map[string]int{g.probeFailures, g.dialFailures} {
		for tag := range failures {
			if !members[tag] {
				delete(failures, tag)
			}
		}
	}
	for tag := range g.lastDialSuccess {
		if !members[tag] {
			delete(g.lastDialSuccess, tag)
		}
	}
}

// failoverCandidates returns other members supporting network ordered by
// delay, preferring members whose last health check passed.
func (g *URLTestGroup) failoverCandidates(network string, failed adapter.Outbound) []adapter.Outbound {
	type candidate struct {
		outbound adapter.Outbound
		delay    uint16
		failing  bool
	}
	var candidates []candidate
	failing := g.failingMembers()
	for _, detour := range g.loadOutbounds() {
		if detour == failed || !common.Contains(detour.Network(), network) {
			continue
		}
		realTag := RealTag(g.outbound, detour)
		history := g.history.LoadURLTestHistory(realTag)
		if history == nil {
			continue
		}
		candidates = append(candidates, candidate{detour, history.Delay, failing[realTag]})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].failing != candidates[j].failing {
			return !candidates[i].failing
		}
		return candidates[i].delay < candidates[j].delay
	})
	if len(candidates) > urlTestFailoverCandidates {
		candidates = candidates[:urlTestFailoverCandidates]
	}
	outbounds := make([]adapter.Outbound, 0, len(candidates))
	for _, it := range candidates {
		outbounds = append(outbounds, it.outbound)
	}
	return outbounds
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	if !g.checking.TryLock() {
		return make(map[string]uint16), nil
	}
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *URLTestGroup) urlTestWait(ctx context.Context, force bool) (map[string]uint16, error) {
	g.checking.Lock()
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *URLTestGroup) urlTestLocked(ctx context.Context, force bool) (map[string]uint16, error) {
	result := urlTestOutbounds(ctx, g.outbound, g.history, g.logger, g.loadOutbounds(), g.link, g.interval, force, urlTestOptions{
		expectedStatus: g.expectedStatus,
		onFailure:      g.reportProbeFailure,
		onSuccess:      g.reportProbeSuccess,
	})
	g.precisionTest(ctx, result)
	select {
	case <-ctx.Done():
	default:
		g.performUpdateCheck()
	}
	return result, nil
}

// precisionTest measures the fastest members again with low concurrency, so
// their delays are not inflated by probes competing for bandwidth.
func (g *URLTestGroup) precisionTest(ctx context.Context, result map[string]uint16) {
	if len(result) <= urlTestPrecisionCandidates {
		return
	}
	var candidates []adapter.Outbound
	for _, detour := range g.loadOutbounds() {
		if _, isGroup := detour.(adapter.OutboundGroup); isGroup {
			continue
		}
		if _, tested := result[detour.Tag()]; tested {
			candidates = append(candidates, detour)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return result[candidates[i].Tag()] < result[candidates[j].Tag()]
	})
	if len(candidates) > urlTestPrecisionCandidates {
		candidates = candidates[:urlTestPrecisionCandidates]
	}
	var resultAccess sync.Mutex
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](urlTestPrecisionConcurrency))
	for _, detour := range candidates {
		tag := detour.Tag()
		b.Go(tag, func() (any, error) {
			testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
			defer cancel()
			delay, err := urltest.URLTestWithStatus(testCtx, g.link, detour, g.expectedStatus)
			if err != nil {
				return nil, nil
			}
			g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: delay,
			})
			resultAccess.Lock()
			result[tag] = delay
			resultAccess.Unlock()
			return nil, nil
		})
	}
	b.Wait()
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestSessionKey struct {
	tag    string
	link   string
	status string
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
	history  *urltest.HistoryStorage
	logger   log.Logger
	options  urlTestOptions
	session  *urlTestSession
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

// urlTestOptions tunes urlTestOutbounds for a specific caller. The zero value
// matches URLTestOutbounds: default status heuristic, 10 parallel probes and
// history dropped on the first failed probe.
type urlTestOptions struct {
	expectedStatus *urltest.StatusMatcher
	concurrency    int
	// onFailure is called for every failed probe and reports whether the
	// delay history of tag should be dropped.
	onFailure func(tag string) bool
	onSuccess func(tag string)
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, interval, force, urlTestOptions{})
}

// URLTestMembers is the user-triggered test of groups that do not test
// themselves (e.g. Selector): lower concurrency so probes do not skew each
// other, and a failed probe keeps the member's history for periodic checks
// to decide.
func URLTestMembers(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, 0, true, urlTestOptions{
		concurrency: 4,
		onFailure:   func(string) bool { return false },
	})
}

func urlTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, options urlTestOptions) map[string]uint16 {
	ctx, session := urlTestSessionFromContext(ctx)
	concurrency := options.concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](concurrency))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		options:  options,
		session:  session,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundManager, outboundGroup))
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
				sessionKey := urlTestSessionKey{tag: tag, link: link, status: b.options.expectedStatus.String()}
				testResult := b.session.test(b.ctx, sessionKey, func() urlTestResult {
					testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
					defer cancel()
					testChan := make(chan urlTestResult, 1)
					go func() {
						delay, testErr := urltest.URLTestWithStatus(testCtx, link, detour, b.options.expectedStatus)
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
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					if b.options.onFailure == nil || b.options.onFailure(tag) {
						b.history.DeleteURLTestHistory(tag)
					}
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					if b.options.onSuccess != nil {
						b.options.onSuccess(tag)
					}
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

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	var updated bool
	selectedOutboundTCP := g.selectedOutboundTCP.Load()
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (selectedOutboundTCP == nil || (exists && outbound != selectedOutboundTCP)) {
		if selectedOutboundTCP != nil {
			updated = true
		}
		g.selectedOutboundTCP.Store(outbound)
	}
	selectedOutboundUDP := g.selectedOutboundUDP.Load()
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (selectedOutboundUDP == nil || (exists && outbound != selectedOutboundUDP)) {
		if selectedOutboundUDP != nil {
			updated = true
		}
		g.selectedOutboundUDP.Store(outbound)
	}
	if updated {
		g.logger.Info("selected outbound changed, tcp: ", outboundTag(g.selectedOutboundTCP.Load()), ", udp: ", outboundTag(g.selectedOutboundUDP.Load()))
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}

func outboundTag(outbound adapter.Outbound) string {
	if outbound == nil {
		return ""
	}
	return outbound.Tag()
}

func (g *URLTestGroup) loadOutbounds() []adapter.Outbound {
	g.outboundsAccess.RLock()
	defer g.outboundsAccess.RUnlock()
	return g.outbounds
}

func (g *URLTestGroup) storeOutbounds(outbounds []adapter.Outbound) {
	g.outboundsAccess.Lock()
	g.outbounds = outbounds
	g.outboundsAccess.Unlock()
}

func (g *URLTestGroup) replaceOutbounds(outbounds []adapter.Outbound) {
	g.updateAccess.Lock()
	selectedOutboundTCP := g.selectedOutboundTCP.Load()
	selectedOutboundUDP := g.selectedOutboundUDP.Load()
	g.storeOutbounds(outbounds)
	g.reconcileManualPin(outbounds)
	g.forgetFailures(outbounds)
	if pin := g.manualPin.Load(); pin != nil {
		g.storePinnedSelection(pin.outbound)
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
	g.updateAccess.Unlock()
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}

func containsOutbound(outbounds []adapter.Outbound, selected adapter.Outbound) bool {
	if selected == nil {
		return true
	}
	for _, outbound := range outbounds {
		if outbound == selected {
			return true
		}
	}
	return false
}
