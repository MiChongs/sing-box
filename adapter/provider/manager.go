package provider

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.ProviderManager = (*Manager)(nil)

type Manager struct {
	ctx           context.Context
	logger        log.ContextLogger
	registry      adapter.ProviderRegistry
	access        sync.Mutex
	providers     []adapter.Provider
	providerByTag map[string]adapter.Provider
}

func NewManager(ctx context.Context, logger logger.ContextLogger, registry adapter.ProviderRegistry) *Manager {
	return &Manager{
		ctx:           ctx,
		logger:        logger,
		registry:      registry,
		providerByTag: make(map[string]adapter.Provider),
	}
}

func (m *Manager) Initialize() {
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	m.access.Lock()
	providers := m.providers
	m.access.Unlock()
	if len(providers) == 0 {
		return nil
	}
	startContext := adapter.NewHTTPStartContext()
	defer startContext.Close()
	for _, provider := range providers {
		name := "provider/" + provider.Type() + "[" + provider.Tag() + "]"
		// Register the cleanup first so a provider that fails to start is
		// still closed with the box.
		if closer, isCloser := provider.(io.Closer); isCloser {
			scope.Add(func() error {
				done := adapter.LogElapsed(m.logger, "close ", name)
				monitor := taskmonitor.New(m.logger, C.StopTimeout)
				monitor.Start("close ", name)
				err := closer.Close()
				monitor.Finish()
				done()
				if err != nil {
					return E.Cause(err, "close ", name)
				}
				return nil
			})
		}
		if contextStarter, ok := provider.(interface {
			StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error
		}); ok {
			err := contextStarter.StartContext(m.ctx, startContext)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	return nil
}

func (m *Manager) Providers() []adapter.Provider {
	m.access.Lock()
	defer m.access.Unlock()
	return m.providers
}

func (m *Manager) Get(tag string) (adapter.Provider, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	provider, err := m.registry.CreateProvider(ctx, router, logFactory, tag, providerType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if _, loaded := m.providerByTag[tag]; loaded {
		return E.New("duplicate provider tag: ", tag)
	}
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	return nil
}
