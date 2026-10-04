package endpoint

import (
	"context"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.EndpointManager         = (*Manager)(nil)
	_ adapter.RuntimeComponentRemover = (*Manager)(nil)
)

type Manager struct {
	registry      adapter.EndpointRegistry
	access        sync.Mutex
	scope         *adapter.Scope
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
	// runtime holds endpoints created after the manager started (outbound
	// providers); they are started through every stage on creation.
	runtime map[adapter.Endpoint]struct{}
}

func NewManager(registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
		runtime:       make(map[adapter.Endpoint]struct{}),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	defer m.access.Unlock()
	if stage == adapter.StartStateInitialize {
		m.scope = scope
	}
	if stage == adapter.StartStateStart {
		return nil
	}
	for _, endpoint := range m.endpoints {
		if _, isRuntime := m.runtime[endpoint]; isRuntime {
			continue
		}
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		err := scope.Start(name, endpoint, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) StartEndpoint(endpoint adapter.Endpoint) error {
	return m.scope.Start("endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint, adapter.StartStateStart)
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return m.endpoints
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	scope := m.scope
	_, loaded := m.endpointByTag[tag]
	m.access.Unlock()
	if scope == nil {
		if loaded {
			return E.New("duplicate endpoint tag: ", tag)
		}
	} else {
		// Start before swapping, so a replaced endpoint keeps serving until
		// its successor is ready.
		err = adapter.StartRuntimeComponent(scope, "endpoint/"+endpoint.Type()+"["+tag+"]", endpoint)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	replaced := m.endpointByTag[tag]
	if replaced != nil {
		m.endpoints = common.Filter(m.endpoints, func(it adapter.Endpoint) bool {
			return it != replaced
		})
		delete(m.runtime, replaced)
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	if scope != nil {
		m.runtime[endpoint] = struct{}{}
	}
	m.access.Unlock()
	if replaced != nil {
		return adapter.CloseRuntimeComponent(scope, replaced)
	}
	return nil
}

// Remove drops an endpoint while the box is running (outbound providers).
func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	endpoint, loaded := m.endpointByTag[tag]
	if !loaded {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.endpointByTag, tag)
	delete(m.runtime, endpoint)
	m.endpoints = common.Filter(m.endpoints, func(it adapter.Endpoint) bool {
		return it != endpoint
	})
	scope := m.scope
	m.access.Unlock()
	return adapter.CloseRuntimeComponent(scope, endpoint)
}
