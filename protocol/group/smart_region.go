package group

import (
	"context"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/smart"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// smart-region: one region of a smart-loadbalance group as an outbound of
// its own. It can be a route outbound, a detour of a chained (landing)
// node, or a selector member; every connection still goes through the
// group's pipeline, restricted to the region, so learning, breakers and
// balancing stay shared with the group.

var (
	_ adapter.OutboundGroup        = (*SmartRegion)(nil)
	_ adapter.DialingOutboundGroup = (*SmartRegion)(nil)
	_ adapter.OutboundGroupHint    = (*SmartRegion)(nil)
)

func RegisterSmartRegion(registry *outbound.Registry) {
	outbound.Register[option.SmartRegionOutboundOptions](registry, C.TypeSmartRegion, NewSmartRegion)
}

type SmartRegion struct {
	outbound.Adapter
	logger      log.ContextLogger
	outboundMgr adapter.OutboundManager
	connection  adapter.ConnectionManager

	groupTag  string
	region    string
	fallback  bool
	hidden    bool
	icon      string
	generated bool

	parent  atomic.Pointer[Smart]
	pinned  atomic.Pointer[string]
	lastTag atomic.Pointer[string]
}

// NewSmartRegion builds a smart-region outbound from configuration.
func NewSmartRegion(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartRegionOutboundOptions) (adapter.Outbound, error) {
	if options.Group == "" {
		return nil, E.New("smart-region: missing group")
	}
	region := normaliseRegionCode(options.Region)
	if region == "" {
		return nil, E.New("smart-region: missing region")
	}
	return newSmartRegion(ctx, logger, tag, options.Group, region, options.Fallback, options.Hidden, options.Icon, []string{N.NetworkTCP, N.NetworkUDP}), nil
}

func newSmartRegion(ctx context.Context, logger log.ContextLogger, tag, group, region string, fallback, hidden bool, icon string, networks []string) *SmartRegion {
	r := &SmartRegion{
		Adapter:     outbound.NewAdapter(C.TypeSmartRegion, tag, networks, []string{group}),
		logger:      logger,
		outboundMgr: service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		groupTag:    group,
		region:      region,
		fallback:    fallback,
		hidden:      hidden,
		icon:        icon,
	}
	r.pinned.Store(new(string))
	r.lastTag.Store(new(string))
	return r
}

func (r *SmartRegion) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart || r.parent.Load() != nil {
		return nil
	}
	detour, loaded := r.outboundMgr.Outbound(r.groupTag)
	if !loaded {
		return E.New("smart-region[", r.Tag(), "]: group not found: ", r.groupTag)
	}
	parent, isSmart := detour.(*Smart)
	if !isSmart || parent.balance == nil {
		return E.New("smart-region[", r.Tag(), "]: ", r.groupTag, " is not a smart-loadbalance group")
	}
	r.parent.Store(parent)
	parent.balance.registerSubgroup(r)
	return nil
}

func (r *SmartRegion) group() (*Smart, error) {
	parent := r.parent.Load()
	if parent == nil {
		return nil, E.New("smart-region[", r.Tag(), "]: not started")
	}
	return parent, nil
}

// Group / Region / Fallback / Generated describe the view for the API.
func (r *SmartRegion) Group() string     { return r.groupTag }
func (r *SmartRegion) Region() string    { return r.region }
func (r *SmartRegion) Fallback() bool    { return r.fallback }
func (r *SmartRegion) Generated() bool   { return r.generated }
func (r *SmartRegion) Hidden() bool      { return r.hidden }
func (r *SmartRegion) Icon() string      { return r.icon }
func (r *SmartRegion) DialThroughGroup() {}

// Parent returns the smart-loadbalance group, nil before Start.
func (r *SmartRegion) Parent() *Smart { return r.parent.Load() }

func (r *SmartRegion) request() *balanceRequest {
	return &balanceRequest{
		group:    r.groupTag,
		region:   r.region,
		fallback: r.fallback,
		pin:      *r.pinned.Load(),
		onSuccess: func(tag string) {
			r.lastTag.Store(&tag)
		},
	}
}

func (r *SmartRegion) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	parent, err := r.group()
	if err != nil {
		return nil, err
	}
	return parent.DialContext(contextWithBalanceRequest(ctx, r.request()), network, destination)
}

func (r *SmartRegion) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	parent, err := r.group()
	if err != nil {
		return nil, err
	}
	return parent.ListenPacket(contextWithBalanceRequest(ctx, r.request()), destination)
}

func (r *SmartRegion) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	parent := r.parent.Load()
	if parent == nil {
		r.connection.NewConnection(ctx, r, conn, metadata, onClose)
		return
	}
	ctx = context.WithValue(ctx, smartMetaCtxKey{}, parent.buildMeta(metadata, false))
	if parent.interruptExternalConnections {
		ctx = interrupt.ContextWithIsExternalConnection(ctx)
	}
	r.connection.NewConnection(ctx, r, conn, metadata, onClose)
}

func (r *SmartRegion) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	parent := r.parent.Load()
	if parent == nil {
		r.connection.NewPacketConnection(ctx, r, conn, metadata, onClose)
		return
	}
	ctx = context.WithValue(ctx, smartMetaCtxKey{}, parent.buildMeta(metadata, true))
	if parent.interruptExternalConnections {
		ctx = interrupt.ContextWithIsExternalConnection(ctx)
	}
	r.connection.NewPacketConnection(ctx, r, conn, metadata, onClose)
}

// All lists the members of the region.
func (r *SmartRegion) All() []string {
	parent := r.parent.Load()
	if parent == nil {
		return nil
	}
	members := parent.balance.snapshot().members(r.region)
	tags := make([]string, len(members))
	for i, ob := range members {
		tags[i] = ob.Tag()
	}
	return tags
}

// Now returns the pinned member, else the member that carried the last
// connection of this view, else the region's best healthy member.
func (r *SmartRegion) Now() string {
	if pin := *r.pinned.Load(); pin != "" {
		return pin
	}
	if last := *r.lastTag.Load(); last != "" {
		return last
	}
	parent := r.parent.Load()
	if parent == nil {
		return ""
	}
	if tag, ok := parent.balance.regionLast.Load(r.region); ok {
		return tag
	}
	return parent.balance.bestMember(r.region)
}

func (r *SmartRegion) Selected(string) adapter.Outbound {
	tag := r.Now()
	if tag == "" {
		return nil
	}
	detour, _ := r.outboundMgr.Outbound(tag)
	return detour
}

func (r *SmartRegion) AttachConnection(closer io.Closer) func() {
	parent := r.parent.Load()
	if parent == nil || parent.interruptGroup == nil {
		return func() {}
	}
	return parent.interruptGroup.Add(closer, true)
}

// SelectOutbound pins a member of the region for this view; "" clears.
func (r *SmartRegion) SelectOutbound(tag string) bool {
	if tag == "" {
		r.pinned.Store(new(string))
		return true
	}
	for _, member := range r.All() {
		if member == tag {
			r.pinned.Store(&tag)
			r.lastTag.Store(&tag)
			return true
		}
	}
	return false
}

func (r *SmartRegion) PinnedTag() string { return *r.pinned.Load() }

// WeightRanking returns the group's ranking restricted to the region.
func (r *SmartRegion) WeightRanking(forceRefresh bool) ([]smart.NodeRank, error) {
	parent, err := r.group()
	if err != nil {
		return nil, err
	}
	ranking, err := parent.WeightRanking(forceRefresh)
	if err != nil {
		return nil, err
	}
	members := make(map[string]struct{})
	for _, tag := range r.All() {
		members[tag] = struct{}{}
	}
	filtered := make([]smart.NodeRank, 0, len(members))
	for _, rank := range ranking {
		if _, ok := members[rank.Name]; ok {
			filtered = append(filtered, rank)
		}
	}
	return filtered, nil
}

// ── Generated region outbounds ─────────────────────────────────────────────

type subgroupConfig struct {
	enabled     bool
	regions     []string
	auto        bool
	tagTemplate string
	hidden      bool
	icon        string
	fallback    bool
	members     string
}

func newSubgroupConfig(options option.SmartRegionOutboundsOptions) (subgroupConfig, error) {
	config := subgroupConfig{
		enabled:     options.Enabled,
		auto:        options.Auto,
		tagTemplate: options.Tag,
		hidden:      options.Hidden,
		icon:        options.Icon,
		fallback:    options.Fallback,
	}
	seen := make(map[string]bool)
	for _, raw := range options.Regions {
		if code := normaliseRegionCode(raw); code != "" && !seen[code] {
			seen[code] = true
			config.regions = append(config.regions, code)
		}
	}
	if len(config.regions) == 0 {
		config.auto = true
	}
	if config.tagTemplate == "" {
		config.tagTemplate = defaultSubgroupTag
	}
	if !strings.Contains(config.tagTemplate, "{region}") && !strings.Contains(config.tagTemplate, "{name}") && !strings.Contains(config.tagTemplate, "{name_en}") && !strings.Contains(config.tagTemplate, "{flag}") {
		return config, E.New("region.outbounds.tag must contain {region}, {name}, {name_en} or {flag}")
	}
	switch strings.ToLower(strings.TrimSpace(options.Members)) {
	case "", subgroupMembersRegions:
		config.members = subgroupMembersRegions
	case subgroupMembersNodes:
		config.members = subgroupMembersNodes
	default:
		return config, E.New("unknown region.outbounds.members: ", options.Members)
	}
	return config, nil
}

type subgroupState struct {
	access   sync.Mutex
	byRegion map[string]*SmartRegion
	runtime  map[string]bool // regions whose outbound was created at runtime
}

func (b *smartBalance) subgroupTag(code string) string {
	name, nameEn, _ := b.regionName(code)
	tag := b.sub.tagTemplate
	tag = strings.ReplaceAll(tag, "{group}", b.s.Tag())
	tag = strings.ReplaceAll(tag, "{region}", code)
	tag = strings.ReplaceAll(tag, "{name}", name)
	tag = strings.ReplaceAll(tag, "{name_en}", nameEn)
	tag = strings.ReplaceAll(tag, "{flag}", regionFlag(code))
	return strings.TrimSpace(tag)
}

func (b *smartBalance) newGeneratedSubgroup(ctx context.Context, logger log.ContextLogger, code string) *SmartRegion {
	_, _, icon := b.regionName(code)
	if b.sub.icon != "" {
		icon = b.sub.icon
	}
	child := newSmartRegion(ctx, logger, b.subgroupTag(code), b.s.Tag(), code, b.sub.fallback, b.sub.hidden, icon, b.s.Network())
	child.generated = true
	child.parent.Store(b.s)
	return child
}

// createDeclaredSubgroups registers the region outbounds listed in
// region.outbounds.regions while the group itself is being built, so the
// rest of the configuration can reference them.
func (b *smartBalance) createDeclaredSubgroups(ctx context.Context, _ adapter.Router, logger log.ContextLogger) error {
	if !b.sub.enabled || len(b.sub.regions) == 0 {
		return nil
	}
	adder, ok := b.s.outboundMgr.(adapter.OutboundAdder)
	if !ok {
		return E.New("outbound manager cannot register region outbounds")
	}
	for _, code := range b.sub.regions {
		child := b.newGeneratedSubgroup(ctx, logger, code)
		if err := adder.AddOutbound(child); err != nil {
			return E.Cause(err, "register region outbound ", child.Tag())
		}
		b.registerSubgroup(child)
	}
	return nil
}

// registerSubgroup records a region outbound of this group, generated or
// configured. The first one registered for a region represents it.
func (b *smartBalance) registerSubgroup(child *SmartRegion) {
	b.subgroups.access.Lock()
	defer b.subgroups.access.Unlock()
	if b.subgroups.byRegion == nil {
		b.subgroups.byRegion = make(map[string]*SmartRegion)
	}
	if _, exists := b.subgroups.byRegion[child.region]; !exists {
		b.subgroups.byRegion[child.region] = child
	}
}

func (b *smartBalance) subgroupFor(code string) *SmartRegion {
	b.subgroups.access.Lock()
	defer b.subgroups.access.Unlock()
	return b.subgroups.byRegion[code]
}

func (b *smartBalance) subgroupList() map[string]*SmartRegion {
	b.subgroups.access.Lock()
	defer b.subgroups.access.Unlock()
	out := make(map[string]*SmartRegion, len(b.subgroups.byRegion))
	for code, child := range b.subgroups.byRegion {
		out[code] = child
	}
	return out
}

// syncSubgroups creates region outbounds for regions that appeared and
// removes the runtime-created ones of regions that are gone. Only active
// with region.outbounds.auto (implied when no regions are listed).
func (b *smartBalance) syncSubgroups() {
	if !b.sub.enabled || !b.sub.auto || !b.s.started.Load() {
		return
	}
	adder, canAdd := b.s.outboundMgr.(adapter.OutboundAdder)
	remover, canRemove := b.s.outboundMgr.(adapter.RuntimeComponentRemover)
	if !canAdd {
		return
	}
	snap := b.snapshot()
	b.subgroups.access.Lock()
	if b.subgroups.byRegion == nil {
		b.subgroups.byRegion = make(map[string]*SmartRegion)
	}
	if b.subgroups.runtime == nil {
		b.subgroups.runtime = make(map[string]bool)
	}
	var create []string
	for _, code := range snap.codes {
		if code == regionUnknown {
			continue
		}
		if _, exists := b.subgroups.byRegion[code]; !exists {
			create = append(create, code)
		}
	}
	var remove []*SmartRegion
	for code, child := range b.subgroups.byRegion {
		if _, present := snap.regions[code]; !present && b.subgroups.runtime[code] {
			remove = append(remove, child)
			delete(b.subgroups.byRegion, code)
			delete(b.subgroups.runtime, code)
		}
	}
	b.subgroups.access.Unlock()

	sort.Strings(create)
	for _, code := range create {
		child := b.newGeneratedSubgroup(b.s.ctx, b.s.logger, code)
		if existing, loaded := b.s.outboundMgr.Outbound(child.Tag()); loaded {
			if region, isRegion := existing.(*SmartRegion); !isRegion || region.groupTag != b.s.Tag() {
				b.s.logger.Warn("smart-loadbalance[", b.s.Tag(), "] region outbound tag ", child.Tag(), " is taken by another outbound; skipped")
				continue
			}
		}
		if err := adder.AddOutbound(child); err != nil {
			b.s.logger.Warn("smart-loadbalance[", b.s.Tag(), "] create region outbound ", child.Tag(), ": ", err)
			continue
		}
		b.subgroups.access.Lock()
		b.subgroups.byRegion[code] = child
		b.subgroups.runtime[code] = true
		b.subgroups.access.Unlock()
		b.s.logger.Info("smart-loadbalance[", b.s.Tag(), "] region outbound ", child.Tag(), " created")
	}
	if canRemove {
		for _, child := range remove {
			if current, loaded := b.s.outboundMgr.Outbound(child.Tag()); loaded && current == adapter.Outbound(child) {
				if err := remover.Remove(child.Tag()); err != nil {
					b.s.logger.Warn("smart-loadbalance[", b.s.Tag(), "] remove region outbound ", child.Tag(), ": ", err)
					continue
				}
				b.s.logger.Info("smart-loadbalance[", b.s.Tag(), "] region outbound ", child.Tag(), " removed (region gone)")
			}
		}
	}
}

// bestMember returns the region's healthy member with the best overall
// quality, for display when the region has not carried traffic yet.
func (b *smartBalance) bestMember(code string) string {
	snap := b.snapshot()
	sc := b.newScorer(nil, false)
	blocked := b.blockedNodes()
	var (
		best        string
		bestQuality = -1.0
	)
	for _, ob := range snap.members(code) {
		if !b.nodeHealthy(ob, false, blocked) {
			continue
		}
		if q, _ := sc.quality(ob.Tag()); q > bestQuality {
			best, bestQuality = ob.Tag(), q
		}
	}
	if best == "" {
		if members := snap.members(code); len(members) > 0 {
			best = members[0].Tag()
		}
	}
	return best
}
