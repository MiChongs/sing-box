package group

import (
	"context"
	"crypto/sha256"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func RegisterNested(registry *outbound.Registry) {
	outbound.Register[option.NestedOutboundOptions](registry, C.TypeNested, NewNested)
}

var (
	_ adapter.Outbound              = (*Nested)(nil)
	_ adapter.OutboundGroup         = (*Nested)(nil)
	_ adapter.Referrer              = (*Nested)(nil)
	_ adapter.PreMatchOutboundGroup = (*Nested)(nil)
	_ adapter.Lifecycle             = (*Nested)(nil)
)

type Nested struct {
	*Selector
	router          adapter.Router
	registry        adapter.OutboundRegistry
	detour          string
	directTags      []string
	shadowOutbounds map[string]adapter.Outbound
	shadowList      []adapter.Outbound
	shadowLock      sync.Mutex
}

func NewNested(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NestedOutboundOptions) (adapter.Outbound, error) {
	if options.Detour == "" {
		return nil, E.New("missing detour in nested outbound: ", tag)
	}
	if options.Detour == tag {
		return nil, E.New("circular detour in nested outbound: ", tag)
	}
	registry := service.FromContext[adapter.OutboundRegistry](ctx)
	if registry == nil {
		return nil, E.New("missing outbound registry in context")
	}
	selector, err := NewSelector(ctx, router, logger, tag, options.SelectorOutboundOptions)
	if err != nil {
		return nil, err
	}
	return &Nested{
		Selector:   selector.(*Selector),
		router:     router,
		registry:   registry,
		detour:     options.Detour,
		directTags: options.Outbounds,
	}, nil
}

func (n *Nested) Type() string {
	return C.TypeNested
}

func (n *Nested) Dependencies() []string {
	dependencies := slices.Clone(n.directTags)
	if n.detour != "" && !slices.Contains(dependencies, n.detour) {
		dependencies = append(dependencies, n.detour)
	}
	return dependencies
}

func (n *Nested) References() []string {
	references := n.Selector.References()
	if n.detour != "" && !slices.Contains(references, n.detour) {
		references = append(references, n.detour)
	}
	return references
}

func (n *Nested) shadowTag(rawTag string) string {
	if rawTag == "Compatible" {
		return rawTag
	}
	return rawTag + "@" + n.Tag()
}

func (n *Nested) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	n.providerAccess.Lock()
	defer n.providerAccess.Unlock()

	if n.detour != "" {
		_, loaded := n.outbound.Outbound(n.detour)
		if !loaded {
			return E.New("detour outbound not found: ", n.detour)
		}
	}

	if n.useAllProviders {
		var providerTags []string
		for _, p := range n.provider.Providers() {
			providerTags = append(providerTags, p.Tag())
			n.providers[p.Tag()] = p
		}
		n.providerTags = providerTags
	} else {
		for i, tag := range n.providerTags {
			p, loaded := n.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			n.providers[tag] = p
		}
	}

	directTags := slices.Clone(n.directTags)
	if len(directTags)+len(n.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	rawOutboundByTag := make(map[string]adapter.Outbound, len(directTags))
	for i, tag := range directTags {
		detour, loaded := n.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		rawOutboundByTag[tag] = detour
	}

	tags := directTags
	if len(tags) == 0 {
		detour, loaded := n.outbound.Outbound("Compatible")
		if !loaded {
			return E.New("fallback outbound not found: Compatible")
		}
		tags = append(tags, detour.Tag())
		rawOutboundByTag[detour.Tag()] = detour
	}

	shadowTags, shadowMap, newShadows, err := n.applyShadowOutbounds(tags, rawOutboundByTag)
	if err != nil {
		return err
	}

	selected, err := n.outboundSelect(shadowMap, shadowTags)
	if err != nil {
		n.closeShadows(newShadows)
		return err
	}

	n.shadowLock.Lock()
	n.shadowOutbounds = shadowMap
	n.shadowList = newShadows
	n.shadowLock.Unlock()

	n.stateAccess.Lock()
	n.tags, n.outbounds = shadowTags, shadowMap
	n.selected.Store(selected)
	n.stateAccess.Unlock()

	scope.Add(n.Close)
	for _, providerTag := range n.providerTags {
		p := n.providers[providerTag]
		element := p.RegisterCallback(n.onProviderUpdated)
		scope.Add(func() error { p.UnregisterCallback(element); return nil })
	}
	return nil
}

func (n *Nested) Close() error {
	n.interruptGroup.Interrupt(true)
	n.shadowLock.Lock()
	shadows := n.shadowList
	n.shadowList = nil
	n.shadowOutbounds = nil
	n.shadowLock.Unlock()

	var err error
	for _, shadow := range shadows {
		err = E.Append(err, n.outbound.UnregisterOutbound(shadow.Tag()), func(err error) error {
			return E.Cause(err, "unregister shadow outbound [", shadow.Tag(), "]")
		})
		common.Close(shadow)
	}
	return err
}

func (n *Nested) onProviderUpdated(tag string) error {
	n.providerAccess.Lock()
	tags, rawOutbounds, outboundsCache, err := collectProviderOutbounds(
		tag,
		n.directTags,
		n.outbound,
		n.providers,
		n.providerTags,
		n.outboundsCache,
		n.filter,
	)
	if err != nil {
		n.providerAccess.Unlock()
		return E.Cause(err, n.Tag())
	}

	rawOutboundByTag := make(map[string]adapter.Outbound, len(rawOutbounds))
	for _, detour := range rawOutbounds {
		rawOutboundByTag[detour.Tag()] = detour
	}

	shadowTags, shadowMap, newShadows, err := n.applyShadowOutbounds(tags, rawOutboundByTag)
	if err != nil {
		n.providerAccess.Unlock()
		return E.Cause(err, n.Tag())
	}

	n.stateAccess.Lock()
	detour, err := n.outboundSelect(shadowMap, shadowTags)
	if err != nil {
		n.stateAccess.Unlock()
		n.providerAccess.Unlock()
		n.closeShadows(newShadows)
		return err
	}

	n.shadowLock.Lock()
	oldShadows := n.shadowList
	n.shadowOutbounds = shadowMap
	n.shadowList = newShadows
	n.shadowLock.Unlock()

	n.tags, n.outbounds, n.outboundsCache = shadowTags, shadowMap, outboundsCache
	previous := n.selected.Swap(detour)
	n.stateAccess.Unlock()
	n.providerAccess.Unlock()

	n.closeReplacedShadows(oldShadows, newShadows)

	if previous != detour {
		n.interruptGroup.Interrupt(n.interruptExternalConnections)
		if n.history != nil {
			n.history.NotifyUpdated()
		}
	}
	return nil
}

func hashOutboundOptions(opt option.Outbound) [32]byte {
	content, _ := json.Marshal(opt.Options)
	h := sha256.New()
	h.Write([]byte(opt.Type))
	h.Write(content)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func (n *Nested) applyShadowOutbounds(tags []string, rawOutbounds map[string]adapter.Outbound) ([]string, map[string]adapter.Outbound, []adapter.Outbound, error) {
	shadowTags := make([]string, 0, len(tags))
	shadowMap := make(map[string]adapter.Outbound, len(tags)*2)
	newShadows := make([]adapter.Outbound, 0, len(tags))
	createdInThisRun := make([]adapter.Outbound, 0)

	n.shadowLock.Lock()
	existingShadows := n.shadowOutbounds
	n.shadowLock.Unlock()

	for _, tag := range tags {
		shadowTag := n.shadowTag(tag)

		if tag == "Compatible" {
			if rawOutbound, exists := rawOutbounds[tag]; exists {
				shadowTags = append(shadowTags, tag)
				shadowMap[tag] = rawOutbound
				continue
			}
		}

		rawOpt, foundOpt := n.findOutboundOption(tag)
		if !foundOpt {
			if rawOutbound, exists := rawOutbounds[tag]; exists {
				n.logger.Warn("nested [", n.Tag(), "]: outbound option not found for [", tag, "], using original outbound")
				shadowTags = append(shadowTags, tag)
				shadowMap[tag] = rawOutbound
				continue
			}
			n.closeShadows(createdInThisRun)
			return nil, nil, nil, E.New("outbound not found: ", tag)
		}

		if rawOpt.Type == C.TypeDirect || rawOpt.Type == C.TypeBlock {
			if rawOutbound, exists := rawOutbounds[tag]; exists {
				shadowTags = append(shadowTags, tag)
				shadowMap[tag] = rawOutbound
				continue
			}
		}

		currentHash := hashOutboundOptions(rawOpt)

		// 校验是否存在配置完全一致的影子实例，一致则复用
		if existing, ok := existingShadows[shadowTag]; ok {
			if sInst, isShadow := existing.(*shadowOutbound); isShadow && sInst.rawHash == currentHash {
				shadowTags = append(shadowTags, shadowTag)
				shadowMap[shadowTag] = existing
				shadowMap[tag] = existing
				newShadows = append(newShadows, existing)
				continue
			}
			// 配置变更：先从全局管理器解绑旧 Tag，以便注册新实例
			_ = n.outbound.UnregisterOutbound(shadowTag)
		}

		clonedOptions, err := cloneOptionsWithDetour(n.registry, rawOpt.Type, rawOpt.Options, n.detour)
		if err != nil {
			n.closeShadows(createdInThisRun)
			return nil, nil, nil, E.Cause(err, "clone options for [", tag, "]")
		}

		rawShadowOutbound, err := n.registry.CreateOutbound(n.ctx, n.router, n.logger, shadowTag, rawOpt.Type, clonedOptions)
		if err != nil {
			n.closeShadows(createdInThisRun)
			return nil, nil, nil, E.Cause(err, "create shadow outbound for [", tag, "]")
		}

		shadowOutboundInstance := &shadowOutbound{
			Outbound: rawShadowOutbound,
			parent:   n,
			rawHash:  currentHash,
		}

		err = n.outbound.RegisterOutbound(shadowOutboundInstance)
		if err != nil {
			common.Close(shadowOutboundInstance)
			n.closeShadows(createdInThisRun)
			return nil, nil, nil, E.Cause(err, "register shadow outbound [", shadowTag, "]")
		}

		shadowTags = append(shadowTags, shadowTag)
		shadowMap[shadowTag] = shadowOutboundInstance
		shadowMap[tag] = shadowOutboundInstance
		newShadows = append(newShadows, shadowOutboundInstance)
		createdInThisRun = append(createdInThisRun, shadowOutboundInstance)
	}

	return shadowTags, shadowMap, newShadows, nil
}

func (n *Nested) findOutboundOption(tag string) (option.Outbound, bool) {
	if opt, loaded := n.outbound.OutboundOption(tag); loaded {
		return opt, true
	}
	for _, p := range n.providers {
		if po, ok := p.(interface {
			OutboundOption(string) (option.Outbound, bool)
		}); ok {
			if opt, loaded := po.OutboundOption(tag); loaded {
				return opt, true
			}
		}
	}
	return option.Outbound{}, false
}

func cloneOptionsWithDetour(registry adapter.OutboundRegistry, outboundType string, options any, detour string) (any, error) {
	content, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	var rawMap map[string]any
	err = json.Unmarshal(content, &rawMap)
	if err != nil {
		return nil, err
	}
	rawMap["detour"] = detour
	modifiedContent, err := json.Marshal(rawMap)
	if err != nil {
		return nil, err
	}
	cloned, loaded := registry.CreateOptions(outboundType)
	if !loaded {
		return nil, E.New("unknown outbound type: ", outboundType)
	}
	err = json.Unmarshal(modifiedContent, cloned)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func (n *Nested) closeShadows(shadows []adapter.Outbound) {
	for _, shadow := range shadows {
		n.outbound.UnregisterOutbound(shadow.Tag())
		common.Close(shadow)
	}
}

func (n *Nested) closeReplacedShadows(oldShadows, newShadows []adapter.Outbound) {
	newTags := common.Map(newShadows, func(it adapter.Outbound) string { return it.Tag() })
	for _, oldShadow := range oldShadows {
		if !slices.Contains(newShadows, oldShadow) {
			// 仅在当前 Tag 已彻底被删除时才从管理器注销，防止误注销刚注册的新同名实例
			if !slices.Contains(newTags, oldShadow.Tag()) {
				n.outbound.UnregisterOutbound(oldShadow.Tag())
			}
			// 无论是被同名新实例替换还是彻底删除，均关闭旧实例释放底层连接与资源
			common.Close(oldShadow)
		}
	}
}

func (n *Nested) checkDetourAvailable() error {
	if n.detour == "" {
		return E.New("nested [", n.Tag(), "]: detour is not configured")
	}
	detourOutbound, loaded := n.outbound.Outbound(n.detour)
	if !loaded {
		return E.New("nested [", n.Tag(), "]: detour [", n.detour, "] not found")
	}
	realTag := RealTag(detourOutbound, n.detour)
	if realTag == "" || realTag == "Compatible" {
		return E.New("nested [", n.Tag(), "]: detour [", n.detour, "] degraded to Compatible, blocking to prevent direct leak")
	}
	return nil
}

func (n *Nested) checkAvailable() error {
	selected := n.selected.Load()
	if selected == nil || selected.Tag() == "Compatible" {
		return E.New("nested [", n.Tag(), "]: current outbound is not ready or degraded to Compatible, blocking to prevent direct leak")
	}
	return n.checkDetourAvailable()
}

func (n *Nested) SelectOutbound(tag string) bool {
	if !slices.Contains(n.tags, tag) {
		shadow := n.shadowTag(tag)
		if slices.Contains(n.tags, shadow) {
			tag = shadow
		}
	}
	return n.Selector.SelectOutbound(tag)
}

func (n *Nested) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := n.checkAvailable(); err != nil {
		return nil, err
	}
	return n.Selector.DialContext(ctx, network, destination)
}

func (n *Nested) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := n.checkAvailable(); err != nil {
		return nil, err
	}
	return n.Selector.ListenPacket(ctx, destination)
}

type shadowOutbound struct {
	adapter.Outbound
	parent  *Nested
	rawHash [32]byte
}

var _ adapter.Lifecycle = (*shadowOutbound)(nil)

func (s *shadowOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if lifecycle, ok := s.Outbound.(adapter.Lifecycle); ok {
		return lifecycle.Start(stage, scope)
	}
	return nil
}

func (s *shadowOutbound) Close() error {
	return common.Close(s.Outbound)
}

func (s *shadowOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := s.parent.checkDetourAvailable(); err != nil {
		return nil, err
	}
	return s.Outbound.DialContext(ctx, network, destination)
}

func (s *shadowOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := s.parent.checkDetourAvailable(); err != nil {
		return nil, err
	}
	return s.Outbound.ListenPacket(ctx, destination)
}

func (s *shadowOutbound) MultiplexEnabled() bool {
	if m, ok := s.Outbound.(adapter.OutboundWithMultiplex); ok {
		return m.MultiplexEnabled()
	}
	return false
}

func (s *shadowOutbound) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	if p, ok := s.Outbound.(adapter.OutboundWithPreferredRoutes); ok {
		return p.PreferredDomain(metadata, domain)
	}
	return false
}

func (s *shadowOutbound) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if p, ok := s.Outbound.(adapter.OutboundWithPreferredRoutes); ok {
		return p.PreferredAddress(metadata, address)
	}
	return false
}
