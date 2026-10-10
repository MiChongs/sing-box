package group

import (
	"context"
	"io"
	"net"
	"regexp"
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
	// Failover dials after the selected member fails. Each attempt can take a
	// full dial timeout and costs a connection to the member, so only the
	// best ranked members are tried.
	maxFailoverCandidates = 2

	// Dial failures of one member, each confirmed by a failover member
	// reaching the same destination, that trigger a recheck of it (mihomo
	// onDialFailed parity), at most once per dialRecheckCooldown.
	dialFailureThreshold = 3
	dialRecheckCooldown  = 30 * time.Second

	// The current selection survives this many consecutive failed probes
	// before the group switches away, so a briefly blocked test URL does not
	// move traffic while the member itself still works.
	selectionFailureGrace = 2
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

// groupState is an immutable snapshot of the members and their ranking,
// swapped atomically so the dial path never takes a lock.
type groupState struct {
	outbounds []adapter.Outbound
	tags      []string
	byTag     map[string]adapter.Outbound
	rankedTCP []rankedOutbound // alive members sorted by delay
	rankedUDP []rankedOutbound
}

// rankedOutbound is a delay-sorted outbound for O(1) selection.
type rankedOutbound struct {
	outbound adapter.Outbound
	delay    uint16
}

func newGroupState(outbounds []adapter.Outbound) *groupState {
	tags := make([]string, 0, len(outbounds))
	byTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, detour := range outbounds {
		tags = append(tags, detour.Tag())
		byTag[detour.Tag()] = detour
	}
	return &groupState{outbounds: outbounds, tags: tags, byTag: byTag}
}

func (st *groupState) contains(detour adapter.Outbound) bool {
	_, loaded := st.byTag[detour.Tag()]
	return loaded
}

func (st *groupState) ranked(network string) []rankedOutbound {
	if network == N.NetworkUDP {
		return st.rankedUDP
	}
	return st.rankedTCP
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
	interruptExternalConnections bool
	// expectedStatus mihomo 对齐的状态码 matcher。nil = 旧启发式。
	// NewURLTest 时 Parse，失败阻断启动；每次探测透传。
	expectedStatus *urltest.StatusMatcher

	providerAccess sync.Mutex
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
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.fallback, s.interruptExternalConnections, s.expectedStatus)
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
	outbound := s.group.selectedOutbound(network)
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
	group.networkChanged()
}

func (s *URLTest) isGroupActive() bool {
	if !s.group.started.Load() {
		return false
	}
	return s.group.idleFor() <= s.group.idleTimeout
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	outbound := s.Selected(N.NetworkName(network))
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		adapter.RecordGroupDial(ctx, s.Tag(), outbound)
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	if ctx.Err() != nil {
		// The caller gave up; that says nothing about the member.
		return nil, err
	}
	s.logger.ErrorContext(ctx, "outbound ", outbound.Tag(), " failed: ", err)
	for _, detour := range s.group.failoverCandidates(N.NetworkName(network), outbound) {
		failoverConn, failoverErr := detour.DialContext(ctx, network, destination)
		if failoverErr == nil {
			s.group.reportFailover(outbound.Tag(), detour.Tag())
			adapter.RecordGroupDial(ctx, s.Tag(), detour)
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewConn(failoverConn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		if ctx.Err() != nil {
			return nil, failoverErr
		}
	}
	return nil, E.Cause(err, "all outbounds failed for ", network, " to ", destination)
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.Selected(N.NetworkUDP)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.reportDialSuccess(outbound.Tag())
		adapter.RecordGroupDial(ctx, s.Tag(), outbound)
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	s.logger.ErrorContext(ctx, "outbound ", outbound.Tag(), " failed: ", err)
	for _, detour := range s.group.failoverCandidates(N.NetworkUDP, outbound) {
		failoverConn, failoverErr := detour.ListenPacket(ctx, destination)
		if failoverErr == nil {
			s.group.reportFailover(outbound.Tag(), detour.Tag())
			adapter.RecordGroupDial(ctx, s.Tag(), detour)
			s.logger.InfoContext(ctx, "failover to ", detour.Tag())
			return s.group.interruptGroup.NewPacketConn(failoverConn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx)), nil
		}
		if ctx.Err() != nil {
			return nil, failoverErr
		}
	}
	return nil, E.Cause(err, "all outbounds failed for UDP to ", destination)
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
	s.group.pruneMemberState(tags)
	if s.isGroupActive() {
		// Queued behind any running round and coalesced with other pending
		// requests; new members have never been measured and are probed,
		// the others only when due. Provider refreshes are not user speed
		// tests and must keep the manual pin.
		s.group.requestRound(s.ctx, probePlan{scheduled: true}, true)
	}
	return nil
}

type URLTestGroup struct {
	// ctx is cancelled by Close so in-flight probe rounds stop with the group.
	ctx                          context.Context
	cancel                       context.CancelFunc
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
	updateAccess                 sync.Mutex
	selectedOutboundTCP          common.TypedValue[adapter.Outbound]
	selectedOutboundUDP          common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	fallback                     URLTestFallback
	// expectedStatus: 上层 URLTest.NewURLTest 在构造 group 之前解析好
	// 再传进来；每次 URL 探测透传给 urltest.URLTestWithStatus。nil = 旧启发式。
	expectedStatus *urltest.StatusMatcher

	state atomic.Pointer[groupState]

	access      sync.Mutex
	close       chan struct{}
	closed      bool
	started     atomic.Bool
	loopRunning atomic.Bool
	lastActive  atomic.Int64 // urlTestClock reading of the last dial

	// Probe scheduling, see urltest_probe.go.
	roundAccess      sync.Mutex
	runningRound     *probeRound
	queuedRound      *probeRound
	healthAccess     sync.Mutex
	health           map[string]*memberHealth
	networkRecheckAt atomic.Int64

	// Dial-failure tracking: counts user-facing dial failures per tag.
	// Past the threshold, a targeted recheck runs (mihomo onDialFailed parity).
	dialFailureAccess  sync.Mutex
	dialFailureCount   map[string]int32
	dialFailureAt      time.Time // last time we bumped failures; clears periodically
	dialFailureTracked atomic.Int32
	dialRecheckAt      atomic.Int64

	// manualPin: user's temporary manual selection. nil = auto.
	// Set via SelectOutbound, cleared at the next user-triggered URL test.
	manualPin atomic.Pointer[manualPinData]
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, fallback URLTestFallback, interruptExternalConnections bool, expectedStatus *urltest.StatusMatcher) (*URLTestGroup, error) {
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
	ctx, cancel := context.WithCancel(ctx)
	group := &URLTestGroup{
		ctx:                          ctx,
		cancel:                       cancel,
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
		expectedStatus:               expectedStatus,
	}
	group.storeOutbounds(outbounds)
	return group, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return
	}
	g.started.Store(true)
	g.markActive()
	go g.CheckOutbounds(false)
}

// Touch records activity and resumes the health check loop after an idle
// pause. It runs on every dial, so the common case is lock-free.
func (g *URLTestGroup) Touch() {
	if !g.started.Load() {
		return
	}
	if g.loopRunning.Load() {
		g.markActive()
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return
	}
	if g.loopRunning.Load() {
		g.markActive()
		return
	}
	// lastActive is left stale on purpose: loopCheck sees the idle gap and
	// runs a round right away.
	g.loopRunning.Store(true)
	wake := make(chan struct{}, 1)
	if g.pause != nil {
		g.pauseCallback = g.pause.RegisterCallback(func(event int) {
			switch event {
			case pause.EventDeviceWake, pause.EventNetworkWake:
				select {
				case wake <- struct{}{}:
				default:
				}
			}
		})
	}
	go g.loopCheck(g.close, wake)
	g.logger.Info("health check resumed")
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	g.started.Store(false)
	if g.cancel != nil {
		g.cancel()
	}
	g.stopLoopLocked()
	if g.close != nil {
		close(g.close)
	}
	return nil
}

func (g *URLTestGroup) stopLoopLocked() {
	g.loopRunning.Store(false)
	if g.pauseCallback != nil {
		g.pause.UnregisterCallback(g.pauseCallback)
		g.pauseCallback = nil
	}
}

// loopCheck runs a health check on every tick of the shared grid (see
// nextTick) until the group has been idle for idleTimeout. While the device
// or network is paused no tick is armed; waking re-arms it.
func (g *URLTestGroup) loopCheck(closeChan <-chan struct{}, wake <-chan struct{}) {
	if g.idleFor() > g.interval {
		g.markActive()
		g.CheckOutbounds(false)
	}
	timer := time.NewTimer(nextTick(g.interval))
	defer timer.Stop()
	for {
		select {
		case <-closeChan:
			return
		case <-wake:
			timer.Reset(nextTick(g.interval))
			continue
		case <-timer.C:
		}
		if g.pause != nil && g.pause.IsPaused() {
			continue
		}
		if g.idleFor() > g.idleTimeout {
			g.access.Lock()
			if !g.closed {
				g.stopLoopLocked()
			}
			g.access.Unlock()
			g.logger.Info("health check paused due to idle timeout")
			return
		}
		g.CheckOutbounds(false)
		timer.Reset(nextTick(g.interval))
	}
}

// urlTestClockBase anchors lastActive and the tick grid to the monotonic
// clock without the allocation an atomic time.Time store costs on every dial.
var urlTestClockBase = time.Now()

func urlTestClock() int64 {
	return int64(time.Since(urlTestClockBase))
}

// nextTick returns the time until the next multiple of interval on the
// process-wide clock. Groups sharing an interval tick together, so their
// probes wake the radio once per interval instead of once per group.
func nextTick(interval time.Duration) time.Duration {
	return interval - time.Duration(urlTestClock()%int64(interval))
}

func (g *URLTestGroup) markActive() {
	g.lastActive.Store(urlTestClock())
}

func (g *URLTestGroup) idleFor() time.Duration {
	return time.Duration(urlTestClock() - g.lastActive.Load())
}

func (g *URLTestGroup) selectedOutbound(network string) adapter.Outbound {
	if network == N.NetworkUDP {
		return g.selectedOutboundUDP.Load()
	}
	return g.selectedOutboundTCP.Load()
}

// pinnedOutbound returns the manually-pinned outbound when it is still a
// member of the snapshot and supports the requested network; nil otherwise.
// When the pin has been removed from the snapshot (provider update dropped
// it), the pin is auto-cleared so selection falls back to automatic.
func (g *URLTestGroup) pinnedOutbound(network string) adapter.Outbound {
	pin := g.manualPin.Load()
	if pin == nil {
		return nil
	}
	st := g.state.Load()
	if st == nil || !st.contains(pin.outbound) {
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

// findOutboundByTag looks tag up in the current snapshot. Used by
// SelectOutbound so the pin only accepts tags that actually belong to this
// group (mirrors Selector.SelectOutbound's membership guard).
func (g *URLTestGroup) findOutboundByTag(tag string) adapter.Outbound {
	st := g.state.Load()
	if st == nil {
		return nil
	}
	return st.byTag[tag]
}

// Select picks the outbound for network from the delay-sorted ranking.
//
// Disconnect-prevention rules (mihomo-parity):
//  1. If the current selection has a delay within tolerance of the best, keep it.
//  2. If the current selection has no delay (never measured, or its last
//     probes failed) but is still a member, has failed fewer than
//     selectionFailureGrace consecutive probes and has not piled up dial
//     failures, keep it. Avoids thrash when the test URL is briefly blocked
//     while traffic still works.
//  3. Otherwise switch to the best ranked member.
func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	if pin := g.pinnedOutbound(network); pin != nil {
		return pin, true
	}
	if g.fallback.enabled {
		return g.selectFallback(network)
	}
	st := g.state.Load()
	if st == nil {
		return nil, false
	}
	current := g.selectedOutbound(network)
	if current != nil && !st.contains(current) {
		current = nil
	}
	candidates := st.ranked(network)
	if len(candidates) == 0 {
		if current != nil {
			return current, true
		}
		return g.selectFullScan(st, network)
	}
	best := candidates[0]
	if current != nil {
		if currentHistory := g.history.LoadURLTestHistory(RealTag(current, network)); currentHistory != nil {
			if int(currentHistory.Delay) <= int(best.delay)+int(g.tolerance) {
				return current, true
			}
		} else if g.probeFailures(current.Tag()) < selectionFailureGrace && !g.hasExcessiveDialFailures(current.Tag()) {
			return current, true
		}
	}
	return best.outbound, true
}

// selectFallback implements fallback mode: members are tried in configured
// order and the first one with a delay within max_delay wins, regardless of
// the current selection. When every tested member exceeds max_delay, the
// fastest of them is used.
func (g *URLTestGroup) selectFallback(network string) (adapter.Outbound, bool) {
	st := g.state.Load()
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

// selectFullScan is used while the ranking is empty (no rebuild since the
// members were stored): the fastest member with history wins, otherwise the
// first member supporting network is returned as unmeasured.
func (g *URLTestGroup) selectFullScan(st *groupState, network string) (adapter.Outbound, bool) {
	var (
		minDelay     uint16
		minOutbound  adapter.Outbound
		anyAvailable adapter.Outbound
	)
	for _, detour := range st.outbounds {
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
		if minOutbound == nil || history.Delay < minDelay {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound != nil {
		return minOutbound, true
	}
	return anyAvailable, false
}

// hasExcessiveDialFailures reports whether tag has exceeded dial-failure threshold.
func (g *URLTestGroup) hasExcessiveDialFailures(tag string) bool {
	if g.dialFailureTracked.Load() == 0 {
		return false
	}
	g.dialFailureAccess.Lock()
	defer g.dialFailureAccess.Unlock()
	return g.dialFailureCount[tag] >= dialFailureThreshold
}

// reportFailover records that failed could not reach a destination that
// recovered did. Dials failing on every member point at the destination,
// not the member, and are not counted.
func (g *URLTestGroup) reportFailover(failed string, recovered string) {
	g.reportDialSuccess(recovered)
	g.reportDialFailure(failed)
}

// reportDialFailure counts a confirmed dial failure of tag. Past the
// threshold the member is re-probed, at most once per dialRecheckCooldown;
// until a probe succeeds the selection does not hold on to it.
func (g *URLTestGroup) reportDialFailure(tag string) {
	g.dialFailureAccess.Lock()
	if g.dialFailureCount == nil {
		g.dialFailureCount = make(map[string]int32)
	}
	// Decay stale counters if last bump was long ago
	if !g.dialFailureAt.IsZero() && time.Since(g.dialFailureAt) > g.interval {
		clear(g.dialFailureCount)
	}
	g.dialFailureCount[tag]++
	count := g.dialFailureCount[tag]
	g.dialFailureAt = time.Now()
	g.dialFailureTracked.Store(int32(len(g.dialFailureCount)))
	g.dialFailureAccess.Unlock()
	if count < dialFailureThreshold {
		return
	}
	now := urlTestClock()
	last := g.dialRecheckAt.Load()
	if last != 0 && now-last < int64(dialRecheckCooldown) {
		return
	}
	if !g.dialRecheckAt.CompareAndSwap(last, now) {
		return
	}
	g.logger.Debug("outbound ", tag, " failed ", count, " dials, rechecking")
	g.requestRound(g.lifetime(), probePlan{focus: map[string]struct{}{tag: {}}}, true)
}

// reportDialSuccess is called when a dial succeeds — clears the failure counter.
func (g *URLTestGroup) reportDialSuccess(tag string) {
	if g.dialFailureTracked.Load() == 0 {
		return
	}
	g.dialFailureAccess.Lock()
	delete(g.dialFailureCount, tag)
	g.dialFailureTracked.Store(int32(len(g.dialFailureCount)))
	g.dialFailureAccess.Unlock()
}

// failoverCandidates returns the best ranked members other than failed.
func (g *URLTestGroup) failoverCandidates(network string, failed adapter.Outbound) []adapter.Outbound {
	st := g.state.Load()
	if st == nil {
		return nil
	}
	var result []adapter.Outbound
	for _, candidate := range st.ranked(network) {
		if candidate.outbound == failed || candidate.outbound.Tag() == failed.Tag() {
			continue
		}
		result = append(result, candidate.outbound)
		if len(result) == maxFailoverCandidates {
			break
		}
	}
	return result
}

// rebuildRankedCandidates sorts all members with history by delay and
// stores the ranking atomically.
func (g *URLTestGroup) rebuildRankedCandidates() {
	for {
		snap := g.state.Load()
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
		sort.SliceStable(tcpRanked, func(i, j int) bool { return tcpRanked[i].delay < tcpRanked[j].delay })
		sort.SliceStable(udpRanked, func(i, j int) bool { return udpRanked[i].delay < udpRanked[j].delay })
		// A concurrent provider update may have replaced the member list
		// meanwhile; rebuild against it instead of resurrecting old members.
		if g.state.CompareAndSwap(snap, &groupState{
			outbounds: snap.outbounds,
			tags:      snap.tags,
			byTag:     snap.byTag,
			rankedTCP: tcpRanked,
			rankedUDP: udpRanked,
		}) {
			return
		}
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.lifetime(), force)
}

// URLTest serves user speed tests: every member is probed unless it was
// measured moments ago.
func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

// urlTest runs (or joins) a probe round and returns the members' delays once
// it finishes or ctx is done, whichever comes first. The round itself is
// bound to the group, so a caller with a short deadline still gets every
// member refreshed in the background.
func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	var round *probeRound
	if force {
		round = g.requestRound(ctx, probeFull, true)
	} else {
		round = g.requestRound(ctx, probeScheduled, false)
	}
	if round != nil {
		select {
		case <-round.done:
		case <-ctx.Done():
		}
	}
	return g.delaySnapshot(round), nil
}

func (g *URLTestGroup) performUpdateCheck() {
	g.rebuildRankedCandidates()
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

// storeOutbounds swaps in a new member snapshot (ranking is rebuilt by the
// caller or the next health check).
func (g *URLTestGroup) storeOutbounds(outbounds []adapter.Outbound) {
	g.state.Store(newGroupState(outbounds))
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

// pruneMemberState drops probe health and dial failure counters of tags
// that are no longer members.
func (g *URLTestGroup) pruneMemberState(tags []string) {
	activeTagSet := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		activeTagSet[tag] = struct{}{}
	}
	g.healthAccess.Lock()
	for tag := range g.health {
		if _, exists := activeTagSet[tag]; !exists {
			delete(g.health, tag)
		}
	}
	g.healthAccess.Unlock()
	g.dialFailureAccess.Lock()
	for tag := range g.dialFailureCount {
		if _, exists := activeTagSet[tag]; !exists {
			delete(g.dialFailureCount, tag)
		}
	}
	g.dialFailureTracked.Store(int32(len(g.dialFailureCount)))
	g.dialFailureAccess.Unlock()
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
