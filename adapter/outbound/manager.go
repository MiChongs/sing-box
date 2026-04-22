package outbound

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	logger                  log.ContextLogger
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	started                 bool
	stage                   adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	dependByTag             map[string][]string
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(logger logger.ContextLogger, registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		dependByTag:   make(map[string][]string),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	if stage == adapter.StartStateStart {
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
		outbounds := m.outbounds
		m.access.Unlock()
		return m.startOutbounds(append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	} else {
		outbounds := m.outbounds
		m.access.Unlock()
		for _, outbound := range outbounds {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			m.logger.Trace(stage, " ", name)
			startTime := time.Now()
			err := adapter.LegacyStart(outbound, stage)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
			adapter.LogElapsed(m.logger, startTime, stage, " ", name)
		}
	}
	return nil
}

func (m *Manager) startOutbounds(outbounds []adapter.Outbound) error {
	monitor := taskmonitor.New(m.logger, C.StartTimeout)
	started := make(map[string]bool)
	for {
		// Collect all outbounds whose dependencies are satisfied
		var ready []adapter.Outbound
	collectReady:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			for _, dependency := range outboundToStart.Dependencies() {
				if !started[dependency] {
					continue collectReady
				}
			}
			ready = append(ready, outboundToStart)
		}
		if len(ready) == 0 {
			if len(started) == len(outbounds) {
				break
			}
			// Circular dependency detection
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
				m.access.Lock()
				problemOutbound := m.outboundByTag[problemOutboundTag]
				m.access.Unlock()
				if problemOutbound == nil {
					return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
				}
				return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
			}
			return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
		}
		// Start all ready outbounds in parallel
		if len(ready) == 1 {
			// Single outbound — no goroutine overhead
			ob := ready[0]
			started[ob.Tag()] = true
			if err := m.startSingleOutbound(monitor, ob); err != nil {
				return err
			}
		} else {
			var wg sync.WaitGroup
			var startErr error
			var errOnce sync.Once
			for _, ob := range ready {
				started[ob.Tag()] = true
				wg.Add(1)
				go func(outbound adapter.Outbound) {
					defer wg.Done()
					// 每个 goroutine 使用自己的 Monitor 实例，避免
					// 共享 monitor 下并发 Start/Finish 产生的字段竞态。
					// 即便 Monitor 内部已加锁，"G1 的 Start → G2 的
					// Finish" 这种跨 goroutine 配对仍会让某个任务的
					// 超时告警丢失 (G2 的 Finish 停了 G1 的 timer)，
					// 按每个任务一个 Monitor 语义才正确。
					taskMonitor := taskmonitor.New(m.logger, C.StartTimeout)
					if err := m.startSingleOutbound(taskMonitor, outbound); err != nil {
						errOnce.Do(func() { startErr = err })
					}
				}(ob)
			}
			wg.Wait()
			if startErr != nil {
				return startErr
			}
		}
		ready = ready[:0]
		if len(started) == len(outbounds) {
			break
		}
	}
	return nil
}

func (m *Manager) startSingleOutbound(monitor *taskmonitor.Monitor, outbound adapter.Outbound) error {
	name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
	if starter, isStarter := outbound.(adapter.Lifecycle); isStarter {
		m.logger.Trace("start ", name)
		startTime := time.Now()
		monitor.Start("start ", name)
		err := starter.Start(adapter.StartStateStart)
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "start ", name)
		}
		adapter.LogElapsed(m.logger, startTime, "start ", name)
	} else if starter, isStarter := outbound.(interface {
		Start() error
	}); isStarter {
		m.logger.Trace("start ", name)
		startTime := time.Now()
		monitor.Start("start ", name)
		err := starter.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "start ", name)
		}
		adapter.LogElapsed(m.logger, startTime, "start ", name)
	}
	return nil
}

func (m *Manager) Close() error {
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	outbounds := m.outbounds
	m.outbounds = nil
	m.access.Unlock()
	var err error
	for _, outbound := range outbounds {
		if closer, isCloser := outbound.(io.Closer); isCloser {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			m.logger.Trace("close ", name)
			startTime := time.Now()
			monitor.Start("close ", name)
			err = E.Append(err, closer.Close(), func(err error) error {
				return E.Cause(err, "close ", name)
			})
			monitor.Finish()
			adapter.LogElapsed(m.logger, startTime, "close ", name)
		}
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

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	delete(m.outboundByTag, tag)
	index := common.Index(m.outbounds, func(it adapter.Outbound) bool {
		return it == outbound
	})
	if index == -1 {
		panic("invalid inbound index")
	}
	m.outbounds = append(m.outbounds[:index], m.outbounds[index+1:]...)
	started := m.started
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
			m.logger.Info("updated default outbound to ", m.defaultOutbound.Tag())
		} else {
			m.defaultOutbound = nil
		}
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 {
		return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		if len(m.dependByTag[dependency]) == 1 {
			delete(m.dependByTag, dependency)
		} else {
			m.dependByTag[dependency] = common.Filter(m.dependByTag[dependency], func(it string) bool {
				return it != tag
			})
		}
	}
	if started {
		return common.Close(outbound)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	if m.started {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			m.logger.Trace(stage, " ", name)
			startTime := time.Now()
			err = adapter.LegacyStart(outbound, stage)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
			adapter.LogElapsed(m.logger, startTime, stage, " ", name)
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	if existsOutbound, loaded := m.outboundByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsOutbound)
			if err != nil {
				return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.outbounds, func(it adapter.Outbound) bool {
			return it == existsOutbound
		})
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.outbounds = append(m.outbounds[:existsIndex], m.outbounds[existsIndex+1:]...)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		m.dependByTag[dependency] = append(m.dependByTag[dependency], tag)
	}
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
		if m.started {
			m.logger.Info("updated default outbound to ", outbound.Tag())
		}
	}
	return nil
}
