package dns

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.DNSTransportManager     = (*TransportManager)(nil)
	_ adapter.DNSTransportAdder       = (*TransportManager)(nil)
	_ adapter.RuntimeComponentRemover = (*TransportManager)(nil)
)

type TransportManager struct {
	registry                 adapter.DNSTransportRegistry
	outbound                 adapter.OutboundManager
	defaultTag               string
	access                   sync.RWMutex
	transports               []adapter.DNSTransport
	transportByTag           map[string]adapter.DNSTransport
	defaultTransport         adapter.DNSTransport
	defaultTransportFallback func() (adapter.DNSTransport, error)
	fakeIPTransport          adapter.FakeIPTransport
	// scope is set once the manager starts; transports added after that
	// (outbound provider DNS) are started through it as runtime transports.
	scope   *adapter.Scope
	runtime map[adapter.DNSTransport]struct{}
	// added holds the transports registered through AddTransport, the only
	// ones Remove may drop.
	added map[adapter.DNSTransport]struct{}
}

func NewTransportManager(registry adapter.DNSTransportRegistry, outbound adapter.OutboundManager, defaultTag string) *TransportManager {
	return &TransportManager{
		registry:       registry,
		outbound:       outbound,
		defaultTag:     defaultTag,
		transportByTag: make(map[string]adapter.DNSTransport),
		runtime:        make(map[adapter.DNSTransport]struct{}),
		added:          make(map[adapter.DNSTransport]struct{}),
	}
}

func (m *TransportManager) Initialize(defaultTransportFallback func() (adapter.DNSTransport, error)) {
	m.defaultTransportFallback = defaultTransportFallback
}

func (m *TransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultTransport == nil {
			m.access.Unlock()
			return E.New("default DNS server not found: ", m.defaultTag)
		}
		if m.defaultTransport == nil {
			defaultTransport, err := m.defaultTransportFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "default DNS server fallback")
			}
			m.transports = append(m.transports, defaultTransport)
			m.transportByTag[defaultTransport.Tag()] = defaultTransport
			m.defaultTransport = defaultTransport
		}
	}
	// Runtime transports were already started through every stage when added.
	transports := common.Filter(m.transports, func(it adapter.DNSTransport) bool {
		_, isRuntime := m.runtime[it]
		return !isRuntime
	})
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startTransports(scope, transports)
	}
	for _, transport := range transports {
		name := "dns/" + transport.Type() + "[" + transport.Tag() + "]"
		err := scope.Start(name, transport, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *TransportManager) startTransports(scope *adapter.Scope, transports []adapter.DNSTransport) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, transportToStart := range transports {
			transportTag := transportToStart.Tag()
			if started[transportTag] {
				continue
			}
			dependencies := transportToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[transportTag] = true
			canContinue = true
			name := "dns/" + transportToStart.Type() + "[" + transportTag + "]"
			err := scope.Start(name, transportToStart, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(transports) {
			break
		}
		if canContinue {
			continue
		}
		currentTransport := common.Find(transports, func(it adapter.DNSTransport) bool {
			return !started[it.Tag()]
		})
		var lintTransport func(oTree []string, oCurrent adapter.DNSTransport) error
		lintTransport = func(oTree []string, oCurrent adapter.DNSTransport) error {
			problemTransportTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemTransportTag) {
				return E.New("circular server dependency: ", strings.Join(oTree, " -> "), " -> ", problemTransportTag)
			}
			m.access.Lock()
			problemTransport := m.transportByTag[problemTransportTag]
			m.access.Unlock()
			if problemTransport == nil {
				return E.New("dependency[", problemTransportTag, "] not found for server[", oCurrent.Tag(), "]")
			}
			return lintTransport(append(oTree, problemTransportTag), problemTransport)
		}
		return lintTransport([]string{currentTransport.Tag()}, currentTransport)
	}
	return nil
}

func (m *TransportManager) Transports() []adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.transports
}

func (m *TransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	m.access.RLock()
	outbound, found := m.transportByTag[tag]
	m.access.RUnlock()
	return outbound, found
}

func (m *TransportManager) Default() adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultTransport
}

func (m *TransportManager) FakeIP() adapter.FakeIPTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.fakeIPTransport
}

func (m *TransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	transport, err := m.registry.CreateDNSTransport(ctx, logger, tag, transportType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.transportByTag[tag]
	if loaded {
		return E.New("duplicate DNS server tag: ", tag)
	}
	m.transports = append(m.transports, transport)
	m.transportByTag[tag] = transport
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultTransport == nil) {
		if transport.Type() == C.DNSTypeFakeIP {
			return E.New("default server cannot be fakeip")
		}
		m.defaultTransport = transport
	}
	if transport.Type() == C.DNSTypeFakeIP {
		if m.fakeIPTransport != nil {
			return E.New("multiple fakeip server are not supported")
		}
		m.fakeIPTransport = transport.(adapter.FakeIPTransport)
	}
	return nil
}

// AddTransport registers a transport constructed by its owner (outbound
// providers). It never becomes the default server. Once the manager has
// started, the transport is started through every stage before it is
// published.
func (m *TransportManager) AddTransport(transport adapter.DNSTransport) error {
	tag := transport.Tag()
	if tag == "" {
		return os.ErrInvalid
	}
	m.access.Lock()
	_, loaded := m.transportByTag[tag]
	scope := m.scope
	m.access.Unlock()
	if loaded {
		return E.New("duplicate DNS server tag: ", tag)
	}
	if scope != nil {
		err := adapter.StartRuntimeComponent(scope, "dns/"+transport.Type()+"["+tag+"]", transport)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	if _, loaded = m.transportByTag[tag]; loaded {
		m.access.Unlock()
		if scope != nil {
			_ = adapter.CloseRuntimeComponent(scope, transport)
		}
		return E.New("duplicate DNS server tag: ", tag)
	}
	m.transports = append(m.transports, transport)
	m.transportByTag[tag] = transport
	m.added[transport] = struct{}{}
	if scope != nil {
		m.runtime[transport] = struct{}{}
	}
	m.access.Unlock()
	return nil
}

// Remove drops a transport added at runtime. Configured servers may be
// referenced by rules and other servers, so they cannot be removed.
func (m *TransportManager) Remove(tag string) error {
	m.access.Lock()
	transport, loaded := m.transportByTag[tag]
	if !loaded {
		m.access.Unlock()
		return os.ErrInvalid
	}
	if _, isAdded := m.added[transport]; !isAdded {
		m.access.Unlock()
		return E.New("cannot remove configured DNS server: ", tag)
	}
	delete(m.added, transport)
	delete(m.transportByTag, tag)
	m.transports = common.Filter(m.transports, func(it adapter.DNSTransport) bool {
		return it != transport
	})
	delete(m.runtime, transport)
	scope := m.scope
	m.access.Unlock()
	// Runtime transports and those added before the manager started were both
	// started in the manager scope.
	return adapter.CloseRuntimeComponent(scope, transport)
}
