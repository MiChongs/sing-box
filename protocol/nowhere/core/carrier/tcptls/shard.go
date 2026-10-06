package tcptls

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	carriermux "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/mux"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// MaxMuxCarriers is the Nowhere 2 client pool cap for established or connecting
// Mux TLS carriers in one session. Both logical directions share the pool.
const (
	MaxMuxCarriers = 8
	muxDialTimeout = 15 * time.Second
)

var errNoMuxCarrier = errors.New("nowhere: no eligible TLS Mux carrier available")

// MuxDirection is retained for API compatibility. Nowhere 2 uses one shared
// full-duplex Mux pool, so uplink and downlink reservations compete together.
type MuxDirection uint8

const (
	// MuxUp is accepted by Open and mapped onto the shared pool.
	MuxUp MuxDirection = iota
	// MuxDown is accepted by Open and mapped onto the shared pool.
	MuxDown
)

// MuxManager owns lazily opened Mux TLS carriers for one bundle session.
type MuxManager struct {
	cfg    *Config
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	shards []*muxShard
}

type muxShard struct {
	mgr     *MuxManager
	pending atomic.Int64

	mu        sync.Mutex
	handle    *carriermux.Handle
	err       error
	ready     chan struct{}
	readyOnce sync.Once
	once      sync.Once
}

// NewMuxManager binds a TLS config to a shared Mux carrier pool.
func NewMuxManager(cfg *Config) (*MuxManager, error) {
	if cfg == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &MuxManager{cfg: cfg, ctx: ctx, cancel: cancel}, nil
}

// Open assigns flowID to a shared-pool carrier, dialing another if capacity remains.
func (m *MuxManager) Open(ctx context.Context, flowID uint32, _ MuxDirection) (net.Conn, error) {
	if m == nil {
		return nil, errors.New("nowhere: mux manager unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	shard, err := m.reserveLocked(flowID)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer shard.pending.Add(-1)

	handle, err := shard.wait(ctx)
	if err != nil {
		if fallback := m.fallback(flowID); fallback != nil && fallback != shard {
			fallback.pending.Add(1)
			defer fallback.pending.Add(-1)
			handle, err = fallback.wait(ctx)
			if err != nil {
				return nil, err
			}
			return handle.OpenStream(flowID)
		}
		return nil, err
	}
	return handle.OpenStream(flowID)
}

func (m *MuxManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	shards := append([]*muxShard(nil), m.shards...)
	m.shards = nil
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, shard := range shards {
		shard.close()
	}
	return nil
}

func (m *MuxManager) reserveLocked(flowID uint32) (*muxShard, error) {
	live := m.shards[:0]
	var best *muxShard
	bestActive := 0
	bestPressure := 0
	have := false
	for _, shard := range m.shards {
		if shard.closed() {
			continue
		}
		live = append(live, shard)
		if handle := shard.liveHandle(); handle != nil && !handle.CanOpenFlow(flowID) {
			// The carrier still retains protocol state for this flow ID
			// (or has exhausted its state budget); reopening the ID on it
			// before that state retires would corrupt the stream map.
			continue
		}
		active, pressure := shard.occupancy()
		if !have || muxBetter(active, pressure, bestActive, bestPressure) {
			best = shard
			bestActive = active
			bestPressure = pressure
			have = true
		}
	}
	m.shards = live
	if have && (bestActive == 0 || len(m.shards) >= MaxMuxCarriers) {
		best.pending.Add(1)
		return best, nil
	}
	if len(m.shards) >= MaxMuxCarriers {
		// Every established carrier conflicts with the requested flow ID.
		// Retire an idle one and dial a replacement so wraparound cannot
		// reopen that ID while protocol state survives.
		index := -1
		for i, shard := range m.shards {
			if shard.pending.Load() != 0 {
				continue
			}
			if handle := shard.liveHandle(); handle != nil && handle.ActiveStreams() == 0 {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, errNoMuxCarrier
		}
		retired := m.shards[index]
		m.shards = append(m.shards[:index], m.shards[index+1:]...)
		retired.close()
	}
	shard := &muxShard{mgr: m, ready: make(chan struct{})}
	shard.pending.Add(1)
	m.shards = append(m.shards, shard)
	go shard.dial()
	go m.monitor(shard)
	return shard, nil
}

func muxBetter(active, pressure, bestActive, bestPressure int) bool {
	idle, bestIdle := active == 0, bestActive == 0
	if idle != bestIdle {
		return idle
	}
	if pressure != bestPressure {
		return pressure < bestPressure
	}
	return active < bestActive
}

func (m *MuxManager) fallback(flowID uint32) *muxShard {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *muxShard
	bestActive := 0
	bestPressure := 0
	have := false
	for _, shard := range m.shards {
		handle := shard.liveHandle()
		if handle == nil || !handle.CanOpenFlow(flowID) {
			continue
		}
		active, pressure := shard.occupancy()
		if !have || pressure < bestPressure || (pressure == bestPressure && active < bestActive) {
			best = shard
			bestActive = active
			bestPressure = pressure
			have = true
		}
	}
	return best
}

func (m *MuxManager) monitor(shard *muxShard) {
	ctx := context.Background()
	handle, err := shard.wait(ctx)
	if err != nil {
		m.remove(shard)
		return
	}
	for {
		if handle.IsClosed() {
			m.remove(shard)
			return
		}
		if !handle.IdleFor(ctx, carriermux.IdleTimeout) {
			if handle.IsClosed() {
				m.remove(shard)
			}
			continue
		}
		if shard.pending.Load() == 0 && handle.ActiveStreams() == 0 && !handle.IsClosed() {
			m.remove(shard)
			handle.Close()
			return
		}
	}
}

func (m *MuxManager) remove(shard *muxShard) {
	m.mu.Lock()
	out := m.shards[:0]
	for _, item := range m.shards {
		if item != shard {
			out = append(out, item)
		}
	}
	m.shards = out
	m.mu.Unlock()
}

func (s *muxShard) occupancy() (active, pressure int) {
	active = int(s.pending.Load())
	if handle := s.liveHandle(); handle != nil {
		active += handle.ActiveStreams()
		pressure = handle.Pressure()
	}
	return active, pressure
}

func (s *muxShard) liveHandle() *carriermux.Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || s.handle.IsClosed() {
		return nil
	}
	return s.handle
}

func (s *muxShard) closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return true
	}
	return s.handle != nil && s.handle.IsClosed()
}

func (s *muxShard) wait(ctx context.Context) (*carriermux.Handle, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ready:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.handle == nil {
		return nil, errClosedConn()
	}
	return s.handle, nil
}

func (s *muxShard) dial() {
	s.once.Do(func() {
		parent := context.Background()
		if s.mgr != nil && s.mgr.ctx != nil {
			parent = s.mgr.ctx
		}
		ctx, cancel := context.WithTimeout(parent, muxDialTimeout)
		defer cancel()
		conn, err := dialMuxCarrier(ctx, s.mgr.cfg)
		if err != nil {
			s.fail(err)
			return
		}
		handle, incoming, err := carriermux.Start(conn, carriermux.DefaultConfig())
		if err != nil {
			_ = conn.Close()
			s.fail(err)
			return
		}
		incoming.Discard()
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			handle.Close()
			return
		}
		s.handle = handle
		s.mu.Unlock()
		s.finishReady()
	})
}

func (s *muxShard) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.finishReady()
}

func (s *muxShard) finishReady() {
	s.readyOnce.Do(func() { close(s.ready) })
}

func (s *muxShard) close() {
	s.mu.Lock()
	handle := s.handle
	if s.err == nil && handle == nil {
		s.err = net.ErrClosed
	}
	s.mu.Unlock()
	s.finishReady()
	if handle != nil {
		handle.Close()
	}
}

func errClosedConn() error { return net.ErrClosed }

func dialMuxCarrier(ctx context.Context, cfg *Config) (net.Conn, error) {
	if cfg == nil || cfg.dialer == nil || cfg.tlsDialer == nil {
		return nil, errors.New("nowhere: incomplete TCP carrier config")
	}
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	if err != nil {
		return nil, err
	}
	raw, err = wrapMorphClient(cfg, raw)
	if err != nil {
		return nil, err
	}
	handshaked, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	tlsConn := handshaked.Conn
	if tlsConn == nil {
		_ = raw.Close()
		return nil, errors.New("nowhere: TLS dialer returned nil connection")
	}
	if err := handshaked.TLSHandshakeInfo.Validate(cfg.alpn); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	auth, err := tcpAuthFrame(cfg, handshaked.Exporter)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	opening := make([]byte, 0, len(auth)+1)
	opening = append(opening, auth...)
	opening = append(opening, wire.MuxMarker)
	if _, err := writeFullTimed(tlsConn, opening); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
