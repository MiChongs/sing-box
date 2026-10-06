package nowhere

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// portalUpstreamManager keeps native Portal forwarding usable across network
// interface changes. New flows acquire the current generation while existing
// flows retain the generation they started on. A retired bundle closes only
// after its last flow returns from PortalUpstream.
type portalUpstreamManager struct {
	mu      sync.Mutex
	factory func() (*bundle.CarrierBundle, error)
	logger  log.ContextLogger
	current *portalUpstreamGeneration
	closed  bool
}

type portalUpstreamGeneration struct {
	upstream *nwserver.PortalUpstream
	bundle   *bundle.CarrierBundle
	refs     int
	retired  bool
}

func newPortalUpstreamManager(factory func() (*bundle.CarrierBundle, error), logger log.ContextLogger) (*portalUpstreamManager, error) {
	manager := &portalUpstreamManager{factory: factory, logger: logger}
	generation, err := manager.buildGeneration()
	if err != nil {
		return nil, err
	}
	manager.current = generation
	return manager, nil
}

func (m *portalUpstreamManager) buildGeneration() (*portalUpstreamGeneration, error) {
	b, err := m.factory()
	if err != nil {
		return nil, err
	}
	upstream, err := nwserver.NewPortalUpstream(b)
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	return &portalUpstreamGeneration{upstream: upstream, bundle: b}, nil
}

// Replace installs a fresh next-hop carrier generation. Constructing a bundle
// is lazy with respect to network I/O, so an unreachable Portal does not make
// an interface update discard the working generation.
func (m *portalUpstreamManager) Replace() error {
	if m == nil {
		return net.ErrClosed
	}
	generation, err := m.buildGeneration()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = generation.bundle.Close()
		return net.ErrClosed
	}
	previous := m.current
	m.current = generation
	var closeBundle *bundle.CarrierBundle
	if previous != nil {
		previous.retired = true
		closeBundle = takeRetiredBundle(previous)
	}
	m.mu.Unlock()
	return closeCarrierBundle(closeBundle)
}

func (m *portalUpstreamManager) acquire() (*portalUpstreamGeneration, error) {
	if m == nil {
		return nil, net.ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.current == nil {
		return nil, net.ErrClosed
	}
	m.current.refs++
	return m.current, nil
}

func (m *portalUpstreamManager) release(generation *portalUpstreamGeneration) {
	if generation == nil {
		return
	}
	m.mu.Lock()
	if generation.refs > 0 {
		generation.refs--
	}
	closeBundle := takeRetiredBundle(generation)
	m.mu.Unlock()
	if err := closeCarrierBundle(closeBundle); err != nil && m.logger != nil {
		m.logger.Warn("nowhere: close retired next-hop bundle: ", err)
	}
}

func takeRetiredBundle(generation *portalUpstreamGeneration) *bundle.CarrierBundle {
	if generation == nil || !generation.retired || generation.refs != 0 || generation.bundle == nil {
		return nil
	}
	b := generation.bundle
	generation.bundle = nil
	return b
}

func closeCarrierBundle(b *bundle.CarrierBundle) error {
	if b == nil {
		return nil
	}
	return b.Close()
}

func (m *portalUpstreamManager) HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	generation, err := m.acquire()
	if err != nil {
		if readiness != nil {
			return errors.Join(err, readiness.Reject(err))
		}
		return err
	}
	defer m.release(generation)
	return generation.upstream.HandleStream(ctx, conn, source, target, readiness)
}

func (m *portalUpstreamManager) HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	generation, err := m.acquire()
	if err != nil {
		if readiness != nil {
			return errors.Join(err, readiness.Reject(err))
		}
		return err
	}
	defer m.release(generation)
	return generation.upstream.HandlePacket(ctx, pc, source, target, readiness)
}

// Close retires the current generation. The inbound invokes this only after
// its Handler has drained, so the current bundle normally closes immediately.
func (m *portalUpstreamManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	current := m.current
	m.current = nil
	if current != nil {
		current.retired = true
	}
	closeBundle := takeRetiredBundle(current)
	m.mu.Unlock()
	return closeCarrierBundle(closeBundle)
}

func (m *portalUpstreamManager) currentBundleForTest() *bundle.CarrierBundle {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	return m.current.bundle
}

var _ nwserver.Upstream = (*portalUpstreamManager)(nil)
