package group

import (
	"context"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/common/tcpinfo"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	smartservice "github.com/sagernet/sing-box/experimental/smart"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// Smart dialing and maintenance constants (vernesong/mihomo Smart).
const (
	// At most this many members are offered to one connection.
	smartMaxCandidates = 10
	// Dial rounds: the first smartDeterministicPrefix rounds dial one member
	// each, later rounds race smartParallelDials members.
	smartMaxRetries          = 5
	smartDeterministicPrefix = 3
	smartParallelDials       = 5
	// A member's dial timeout is its connect time EMA times this factor.
	smartConnectThreshold = 5.0

	smartDefaultTimeout     = 5 * time.Second
	smartDefaultInterval    = 5 * time.Minute
	smartDefaultIdleTimeout = 30 * time.Minute
	smartDefaultMaxFailed   = 5

	// Failures in a row, each within smartFloodWindow of the previous,
	// that suppress learning until the next success (network outage).
	smartFloodWindow    = 2 * time.Second
	smartFloodThreshold = 50

	// Stalled: the node sent data for this long without receiving any.
	smartStalledGrace = 4 * time.Second
	// A stalled response probe counts as a failure after this long.
	smartStalledProbeGrace = 2 * time.Second
	smartStalledProbeTTL   = 2 * time.Minute

	// Background task intervals.
	smartPersistInterval   = 5 * time.Minute
	smartStableInterval    = 10 * time.Minute
	smartClaimInterval     = 2 * time.Minute
	smartHostCheckInterval = 30 * time.Minute
	smartCleanupInterval   = 2 * time.Hour
	smartHostLimitInterval = 15 * time.Minute

	// DefaultBlockDuration is how long an API block keeps a node out of a
	// group.
	DefaultBlockDuration = 30 * time.Minute
)

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

var (
	_ adapter.OutboundGroup           = (*Smart)(nil)
	_ adapter.OutboundGroupHint       = (*Smart)(nil)
	_ adapter.DialingOutboundGroup    = (*Smart)(nil)
	_ adapter.InterfaceUpdateListener = (*Smart)(nil)
)

// smartGroupState is an immutable member snapshot, swapped atomically.
type smartGroupState struct {
	outbounds []adapter.Outbound
	tags      []string
	nodes     []uint32
	byTag     map[string]int
	// candidates and all offer every member to the engine without
	// allocating when no member is filtered out.
	candidates []smart.Candidate
	all        []int
}

func newSmartGroupState(engine *smart.Engine, priority *smart.Priority, outbounds []adapter.Outbound) *smartGroupState {
	st := &smartGroupState{
		outbounds:  outbounds,
		tags:       make([]string, len(outbounds)),
		nodes:      make([]uint32, len(outbounds)),
		byTag:      make(map[string]int, len(outbounds)),
		candidates: make([]smart.Candidate, len(outbounds)),
		all:        make([]int, len(outbounds)),
	}
	for i, ob := range outbounds {
		st.tags[i] = ob.Tag()
		st.nodes[i] = engine.NodeID(ob.Tag())
		st.byTag[ob.Tag()] = i
		st.candidates[i] = smart.Candidate{Node: st.nodes[i], Priority: priority.Factor(ob.Tag())}
		st.all[i] = i
	}
	return st
}

func (st *smartGroupState) find(tag string) adapter.Outbound {
	if st == nil {
		return nil
	}
	if i, ok := st.byTag[tag]; ok {
		return st.outbounds[i]
	}
	return nil
}

// Smart picks a member per connection with honk's comprehensive score and
// vernesong/mihomo's Smart features; see option.SmartOutboundOptions.
type Smart struct {
	outbound.Adapter
	ctx         context.Context
	taskCtx     context.Context
	taskCancel  context.CancelFunc
	router      adapter.Router
	outboundMgr adapter.OutboundManager
	logger      log.ContextLogger

	testURL        string
	testHost       string
	expectedStatus *urltest.StatusMatcher
	interval       time.Duration
	idleTimeout    time.Duration
	timeout        time.Duration
	tolerance      uint16
	maxFailedTimes int
	disableUDP     bool
	preferASN      bool
	useLightGBM    bool
	collectData    bool
	sampleRate     float64
	priority       *smart.Priority
	hidden         bool
	icon           string

	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	engine *smart.Engine
	group  *smart.Group
	blocks *smart.Blocks
	store  *smart.Store

	providerAccess  sync.Mutex
	provider        adapter.ProviderManager
	providers       map[string]adapter.Provider
	providerTags    []string
	useAllProviders bool
	outboundsCache  map[string][]adapter.Outbound
	filter          *memberFilter
	updateScheduler providerUpdateCheckScheduler

	state   atomic.Pointer[smartGroupState]
	started atomic.Bool
	pin     atomic.Pointer[string]
	// lastSelected is the member that carried the latest connection.
	lastSelected atomic.Pointer[string]
	lastActive   atomic.Int64

	history   adapter.URLTestHistoryStorage
	pause     pause.Manager
	health    smartHealth
	nodeLoad  *nodeLoadCounter
	conns     smartConnRegistry
	keys      smartKeys
	flood     smartFlood
	exitWatch *smart.ExitWatcher
	throttle  smart.ProbeThrottle
	loss      *tcpinfo.LossSampler

	smartService *smartservice.Service
	model        *lightgbm.WeightModel
	collector    *lightgbm.DataCollector

	hostFailLimit atomic.Int32
	tasks         sync.WaitGroup

	balance *smartBalance
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	return newSmart(ctx, router, logger, tag, C.TypeSmart, options)
}

func newSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options option.SmartOutboundOptions) (*Smart, error) {
	filter, err := newMemberFilter(ctx, options.GroupCommonOption)
	if err != nil {
		return nil, err
	}
	for i, member := range options.Outbounds {
		if slices.Contains(options.Outbounds[:i], member) {
			return nil, E.New("duplicate tag: ", member)
		}
	}
	matcher, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, err
	}
	var priority *smart.Priority
	if options.PolicyPriority != "" {
		priority, err = smart.ParsePriority(options.PolicyPriority)
		if err != nil {
			return nil, err
		}
	}
	networks := []string{N.NetworkTCP, N.NetworkUDP}
	if options.DisableUDP {
		networks = []string{N.NetworkTCP}
	}
	engine := smart.Default()
	s := &Smart{
		Adapter:                      outbound.NewAdapter(outboundType, tag, networks, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outboundMgr:                  service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		testURL:                      options.URL,
		expectedStatus:               matcher,
		interval:                     time.Duration(options.Interval),
		idleTimeout:                  time.Duration(options.IdleTimeout),
		timeout:                      time.Duration(options.Timeout),
		tolerance:                    options.Tolerance,
		maxFailedTimes:               options.MaxFailedTimes,
		disableUDP:                   options.DisableUDP,
		preferASN:                    options.PreferASN,
		useLightGBM:                  options.UseLightGBM,
		collectData:                  options.CollectData,
		sampleRate:                   options.SampleRate,
		priority:                     priority,
		hidden:                       options.Hidden,
		icon:                         options.Icon,
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
		engine:                       engine,
		group:                        engine.Group(tag),
		blocks:                       engine.Blocks(),
		provider:                     service.FromContext[adapter.ProviderManager](ctx),
		providers:                    make(map[string]adapter.Provider),
		providerTags:                 options.Providers,
		useAllProviders:              options.UseAllProviders,
		outboundsCache:               make(map[string][]adapter.Outbound),
		filter:                       filter,
		history:                      service.FromContext[adapter.URLTestHistoryStorage](ctx),
		pause:                        service.FromContext[pause.Manager](ctx),
		nodeLoad:                     newNodeLoadCounter(),
		loss:                         tcpinfo.NewLossSampler(),
	}
	if s.testURL == "" {
		s.testURL = urltest.DefaultLink
	}
	s.testHost = smartTestHost(s.testURL)
	if s.interval <= 0 {
		s.interval = smartDefaultInterval
	}
	if s.idleTimeout <= 0 {
		s.idleTimeout = smartDefaultIdleTimeout
	}
	if s.interval > s.idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if s.timeout <= 0 {
		s.timeout = smartDefaultTimeout
	}
	if s.maxFailedTimes <= 0 {
		s.maxFailedTimes = smartDefaultMaxFailed
	}
	if s.sampleRate <= 0 || s.sampleRate > 1 {
		s.sampleRate = 1
	}
	s.hostFailLimit.Store(int32(s.maxFailedTimes))
	s.health.init()
	s.keys.init()
	s.exitWatch = smart.NewExitWatcher(smart.ExitWatcherOptions{
		Name:    tag,
		WantASN: func() bool { return s.preferASN },
		Load:    s.loadExit,
		Save:    s.saveExit,
		DropPin: s.dropPin,
		Debug:   func(message string) { s.logger.Debug(message) },
	})
	return s, nil
}

func (s *Smart) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		return s.startGroup()
	case adapter.StartStateStarted:
		s.postStart()
		scope.Add(s.close)
	}
	return nil
}

func (s *Smart) startGroup() error {
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
		detour, loaded := s.outboundMgr.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	for _, providerTag := range s.providerTags {
		for _, detour := range s.providers[providerTag].Outbounds() {
			if s.filter.Match(detour) {
				outbounds = append(outbounds, detour)
			}
		}
	}
	if len(outbounds) == 0 {
		detour, _ := s.outboundMgr.Outbound("Compatible")
		outbounds = append(outbounds, detour)
	}
	s.setMembers(outbounds)
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	if s.balance != nil {
		s.balance.rebuild()
	}
	return nil
}

func (s *Smart) setMembers(outbounds []adapter.Outbound) {
	st := newSmartGroupState(s.engine, s.priority, outbounds)
	s.state.Store(st)
	s.group.SetMembers(st.nodes)
	if pin := s.pin.Load(); pin != nil && st.find(*pin) == nil {
		s.logger.Info("manual pin [", *pin, "] left the group, released")
		s.pin.Store(nil)
		s.deleteRecord(smartRecordPin, "")
	}
	s.health.prune(st)
	s.nodeLoad.prune(st.tags)
}

func (s *Smart) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	_, outbounds, cache, err := collectProviderOutbounds(tag, s.Dependencies(), s.outboundMgr, s.providers, s.providerTags, s.outboundsCache, s.filter)
	if err != nil {
		s.providerAccess.Unlock()
		return E.Cause(err, s.Tag())
	}
	s.outboundsCache = cache
	s.setMembers(outbounds)
	s.providerAccess.Unlock()
	if s.balance != nil {
		s.balance.onMembersChanged()
	}
	if s.started.Load() && s.isGroupActive() {
		s.updateScheduler.Schedule(func() { s.checkHealth(false) })
	}
	return nil
}

func (s *Smart) postStart() {
	s.taskCtx, s.taskCancel = context.WithCancel(s.ctx)
	if provider := service.FromContext[adapter.CacheFile](s.ctx); provider != nil {
		if dbProvider, ok := provider.(smart.SmartDBProvider); ok {
			store, err := smart.NewStore(dbProvider.SmartDB(), s.engine)
			if err != nil {
				s.logger.Warn("open smart store: ", err)
			} else {
				s.store = store
			}
		}
	}
	s.restore()
	s.pruneStoredGroups()
	s.initLearning()
	if s.balance != nil {
		s.balance.hydrate()
		s.balance.rebuild()
		if s.balance.currentMode() == regionModeDestination || len(s.balance.destMap) > 0 {
			s.balance.countryDatabase()
		}
	}
	s.markActive()
	s.started.Store(true)
	s.startTasks()
	if s.balance != nil {
		s.logger.Info("regions: ", s.balance.summary())
		s.balance.scheduleRefresh()
	}
}

func (s *Smart) initLearning() {
	if !s.useLightGBM && !s.collectData {
		return
	}
	svc, _ := service.FromContext[adapter.SmartService](s.ctx).(*smartservice.Service)
	if svc == nil {
		return
	}
	s.smartService = svc
	if s.useLightGBM {
		model, err := svc.WeightModel()
		if err != nil {
			s.logger.Warn("lightgbm unavailable: ", err)
		}
		s.model = model
	}
	if s.collectData {
		collector, err := svc.DataCollector()
		if err != nil {
			s.logger.Warn("training data collector unavailable: ", err)
		}
		s.collector = collector
	}
}

func (s *Smart) close() error {
	if s.taskCancel != nil {
		s.taskCancel()
	}
	s.tasks.Wait()
	s.persist()
	s.keys.close()
	if s.balance != nil {
		if db := s.balance.country.Swap(nil); db != nil {
			_ = db.Close()
		}
	}
	return nil
}

// Hidden / Icon expose the dashboard hints of GroupCommonOption.
func (s *Smart) Hidden() bool { return s.hidden }
func (s *Smart) Icon() string { return s.icon }

// TestURL returns the health check URL.
func (s *Smart) TestURL() string { return s.testURL }

// PreferASN, UseLightGBM, CollectData, SampleRate and Tolerance expose the
// configuration for the Clash API.
func (s *Smart) PreferASN() bool     { return s.preferASN }
func (s *Smart) UseLightGBM() bool   { return s.useLightGBM }
func (s *Smart) CollectData() bool   { return s.collectData }
func (s *Smart) SampleRate() float64 { return s.sampleRate }
func (s *Smart) Tolerance() uint16   { return s.tolerance }
func (s *Smart) ExpectedStatus() string {
	if s.expectedStatus == nil {
		return "*"
	}
	return s.expectedStatus.String()
}

// LGBMModelAge returns how long ago the LightGBM model was loaded, 0 when
// the group does not use one.
func (s *Smart) LGBMModelAge() time.Duration {
	if !s.model.IsLoaded() {
		return 0
	}
	return time.Since(s.model.LastUpdate())
}

// PolicyPriority returns the parsed policy_priority rules.
func (s *Smart) PolicyPriority() []smart.PriorityRule { return s.priority.Rules() }

func (s *Smart) getPriorityFactor(tag string) float64 { return s.priority.Factor(tag) }

// IsLoadBalance reports whether the group is a smart-loadbalance group.
func (s *Smart) IsLoadBalance() bool { return s.balance != nil }

// DialThroughGroup keeps the group in the dial path: it observes every dial.
func (s *Smart) DialThroughGroup() {}

func (s *Smart) AttachConnection(closer io.Closer) func() {
	s.markActive()
	return s.interruptGroup.Add(closer, true)
}

// MemberTags returns the member node tags.
func (s *Smart) MemberTags() []string {
	st := s.state.Load()
	if st == nil {
		return nil
	}
	return slices.Clone(st.tags)
}

func (s *Smart) All() []string {
	if s.balance != nil {
		if all := s.balance.allMembers(); all != nil {
			return all
		}
	}
	return s.MemberTags()
}

// PinnedTag returns the manual selection, "" when automatic.
func (s *Smart) PinnedTag() string {
	if pin := s.pin.Load(); pin != nil {
		return *pin
	}
	return ""
}

// FixedSelection is the pin, or the region lock of a smart-loadbalance group.
func (s *Smart) FixedSelection() string {
	if pin := s.PinnedTag(); pin != "" {
		return pin
	}
	if s.balance != nil {
		return s.balance.lockDisplay()
	}
	return ""
}

// Now returns the member shown as selected: the pin, then the member that
// carried the latest connection, then the best ranked member.
func (s *Smart) Now() string {
	if pin := s.PinnedTag(); pin != "" {
		return pin
	}
	if s.balance != nil {
		if now := s.balance.now(); now != "" {
			return now
		}
	}
	st := s.state.Load()
	if last := s.lastSelected.Load(); last != nil && st.find(*last) != nil {
		return *last
	}
	if ob := s.peekBest(N.NetworkTCP); ob != nil {
		return ob.Tag()
	}
	if st != nil && len(st.tags) > 0 {
		return st.tags[0]
	}
	return ""
}

func (s *Smart) Selected(network string) adapter.Outbound {
	st := s.state.Load()
	if s.balance != nil && s.PinnedTag() == "" {
		if tag := s.balance.now(); tag != "" {
			if ob, loaded := s.outboundMgr.Outbound(tag); loaded {
				return ob
			}
		}
	}
	if pin := s.PinnedTag(); pin != "" {
		if ob := st.find(pin); ob != nil {
			return ob
		}
	}
	if network != N.NetworkUDP {
		network = N.NetworkTCP
	}
	if last := s.lastSelected.Load(); last != nil {
		if ob := st.find(*last); ob != nil && common.Contains(ob.Network(), network) {
			return ob
		}
	}
	if ob := s.peekBest(network); ob != nil {
		return ob
	}
	if st != nil && len(st.outbounds) > 0 {
		return st.outbounds[0]
	}
	return nil
}

// SelectOutbound pins tag as the manual selection (mihomo Set), or clears
// the pin when tag is "". A smart-loadbalance group also accepts a region
// code, name or region outbound tag, which locks the region.
func (s *Smart) SelectOutbound(tag string) bool {
	if tag == "" {
		s.setPin("")
		if s.balance != nil && s.RegionLock() != "" {
			_, _ = s.SetRegionLock("")
		}
		return true
	}
	if s.state.Load().find(tag) == nil {
		if s.balance != nil {
			if code, ok := s.balance.selectionRegion(tag); ok {
				s.setPin("")
				_, err := s.SetRegionLock(code)
				return err == nil
			}
		}
		return false
	}
	s.setPin(tag)
	return true
}

func (s *Smart) setPin(tag string) {
	previous := s.PinnedTag()
	if tag == "" {
		s.pin.Store(nil)
		s.deleteRecord(smartRecordPin, "")
	} else {
		s.pin.Store(&tag)
		s.putRecord(smartRecordPin, "", []byte(tag))
	}
	if previous == tag {
		return
	}
	if tag == "" {
		s.logger.Info("manual pin released")
	} else {
		s.logger.Info("manual pin set to ", tag)
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
}

func (s *Smart) markActive() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *Smart) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - s.lastActive.Load())
}

func (s *Smart) isGroupActive() bool {
	return s.idleFor() <= s.idleTimeout
}

// isGroupIdle reports whether the group carried no connection recently.
func (s *Smart) isGroupIdle() bool {
	return s.idleFor() > 2*time.Minute
}

// InterfaceUpdated resets health and fresh path evidence after a network
// change, then rechecks the members.
func (s *Smart) InterfaceUpdated(ctx context.Context) {
	if !s.started.Load() {
		return
	}
	if s.pause != nil && (s.pause.IsDevicePaused() || s.pause.IsNetworkPaused()) {
		return
	}
	s.health.reset()
	s.flood.reset()
	s.logger.Debug("network changed, rechecking members")
	if s.isGroupActive() {
		s.updateScheduler.Schedule(func() { s.checkHealth(true) })
	}
}

// inNetworkStorm reports whether failures are flooding in (an outage), so
// optional probes should hold off.
func (s *Smart) inNetworkStorm() bool {
	return s.flood.suppressed.Load()
}

func smartSkipType(t string) bool {
	switch t {
	case C.TypeBlock, C.TypeDNS:
		return true
	}
	return false
}

func (s *Smart) supportsUDP(ob adapter.Outbound) bool {
	return supportsNetwork(s.history, ob, N.NetworkUDP)
}
