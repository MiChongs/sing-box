package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.OutboundManager         = (*Manager)(nil)
	_ adapter.RuntimeComponentRemover = (*Manager)(nil)
	_ adapter.OutboundAdder           = (*Manager)(nil)
)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
	// scope is set once the manager starts; outbounds created after that
	// (outbound providers) are started through it as runtime outbounds.
	scope   *adapter.Scope
	runtime map[adapter.Outbound]struct{}
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		runtime:       make(map[adapter.Outbound]struct{}),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	// Runtime outbounds were already started through every stage on creation.
	outbounds := common.Filter(m.outbounds, func(it adapter.Outbound) bool {
		_, isRuntime := m.runtime[it]
		return !isRuntime
	})
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	}
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			err := scope.Start(name, lifecycle, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	return m.add(tag, outbound, false)
}

// AddOutbound registers an outbound its owner constructed itself (the region
// views of a smart-loadbalance group). Going through Create from inside a
// constructor would re-enter the registry, which holds its lock while a
// constructor runs. Before the manager starts, a duplicate tag is an error;
// afterwards the outbound is started as a runtime outbound and replaces any
// outbound with the same tag. A generated outbound only becomes the default
// outbound when route.final names it: owners register it before themselves,
// so it must not take the "first outbound" default from its owner.
func (m *Manager) AddOutbound(outbound adapter.Outbound) error {
	if outbound == nil || outbound.Tag() == "" {
		return os.ErrInvalid
	}
	return m.add(outbound.Tag(), outbound, true)
}

func (m *Manager) add(tag string, outbound adapter.Outbound, generated bool) error {
	var err error
	m.access.Lock()
	scope := m.scope
	_, loaded := m.outboundByTag[tag]
	m.access.Unlock()
	if scope == nil {
		if loaded {
			return E.New("duplicate outbound tag: ", tag)
		}
	} else if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
		// Start before swapping, so a replaced outbound keeps serving until
		// its successor is ready.
		err = adapter.StartRuntimeComponent(scope, "outbound/"+outbound.Type()+"["+tag+"]", lifecycle)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	replaced := m.outboundByTag[tag]
	if replaced != nil {
		m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
			return it != replaced
		})
		delete(m.runtime, replaced)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if scope != nil {
		m.runtime[outbound] = struct{}{}
	}
	if tag == m.defaultTag || (!generated && m.defaultTag == "" && m.defaultOutbound == nil) || (replaced != nil && m.defaultOutbound == replaced) {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if replaced != nil {
		return adapter.CloseRuntimeComponent(scope, replaced)
	}
	return nil
}

// Remove drops an outbound while the box is running (outbound providers).
func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	outbound, loaded := m.outboundByTag[tag]
	if !loaded {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.outboundByTag, tag)
	delete(m.runtime, outbound)
	m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
		return it != outbound
	})
	if m.defaultOutbound == outbound {
		m.defaultOutbound = nil
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		}
	}
	scope := m.scope
	m.access.Unlock()
	return adapter.CloseRuntimeComponent(scope, outbound)
}
