package tcptls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	carriermux "github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier/mux"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

type testTCPDialer struct{}

func (testTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}

type testTLSDialer struct{}

func (testTLSDialer) DialTLSConn(context.Context, net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{}, errors.New("unused")
}

func boundTestConfig(t *testing.T, dialer TCPDialer) *Config {
	t.Helper()
	cfg, err := NewConfig(TCPOptions{
		Address: "127.0.0.1:1", Dialer: dialer, TLSDialer: testTLSDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = cfg.BindSession(credentials, wire.SessionID{1}, wire.DefaultALPN)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTCPPoolRejectsOutOfRangeTargets(t *testing.T) {
	cfg := boundTestConfig(t, testTCPDialer{})
	for _, target := range []int{-1, MaxPoolSize + 1} {
		if _, err := NewTCPPool(cfg, target); err == nil {
			t.Fatalf("target %d accepted", target)
		}
	}
	pool, err := NewTCPPool(cfg, MaxPoolSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Resize(MaxPoolSize + 1); err == nil {
		t.Fatal("oversize resize accepted")
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pool.Resize(0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("resize closed pool = %v", err)
	}
}

type closeErrorConn struct {
	err error
}

func (*closeErrorConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*closeErrorConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *closeErrorConn) Close() error                   { return c.err }
func (*closeErrorConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*closeErrorConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*closeErrorConn) SetDeadline(time.Time) error      { return nil }
func (*closeErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (*closeErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPPoolCloseAggregatesAndMemoizesErrors(t *testing.T) {
	cfg := boundTestConfig(t, testTCPDialer{})
	pool, err := NewTCPPool(cfg, 2)
	if err != nil {
		t.Fatal(err)
	}
	first := errors.New("first close")
	second := errors.New("second close")
	pool.idle = []*warmConn{
		{conn: &closeErrorConn{err: first}, carrier: newCarrierInfo(nil)},
		{conn: &closeErrorConn{err: second}, carrier: newCarrierInfo(nil)},
	}
	err = pool.Close()
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("close error = %v", err)
	}
	err = pool.Close()
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("memoized close error = %v", err)
	}
}

type blockingTCPDialer struct {
	once    sync.Once
	started chan struct{}
}

func (d *blockingTCPDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestTCPPoolCloseCancelsAndWaitsForWarmPrepare(t *testing.T) {
	dialer := &blockingTCPDialer{started: make(chan struct{})}
	cfg := boundTestConfig(t, dialer)
	pool, err := NewTCPPool(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	pool.Prewarm()
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("warm prepare did not start")
	}
	done := make(chan error, 1)
	go func() { done <- pool.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and join warm prepare")
	}
}

// muxShardFixture is a manager holding one carrier whose peer is a raw pipe.
type muxShardFixture struct {
	manager *MuxManager
	shard   *muxShard
	handle  *carriermux.Handle
	peer    net.Conn
	monitor bool
}

func (f *muxShardFixture) close() {
	f.manager.Close()
	_ = f.peer.Close()
}

// startMuxShardFixture installs a live carrier in a bare manager so the pool
// paths can be exercised without dialing TLS.
func startMuxShardFixture(t *testing.T) *muxShardFixture {
	t.Helper()
	manager, err := NewMuxManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	handle, _, err := carriermux.Start(left, carriermux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	shard := &muxShard{mgr: manager, ready: make(chan struct{}), handle: handle}
	shard.finishReady()
	manager.mu.Lock()
	manager.shards = append(manager.shards, shard)
	manager.mu.Unlock()
	// The raw peer must drain everything the carrier writes.
	go func() {
		_, _ = io.Copy(io.Discard, right)
	}()
	fixture := &muxShardFixture{manager: manager, shard: shard, handle: handle, peer: right}
	t.Cleanup(fixture.close)
	return fixture
}

func (f *muxShardFixture) startMonitor(t *testing.T) {
	t.Helper()
	f.monitor = true
	f.manager.monitor.Add(1)
	go func() {
		defer f.manager.monitor.Done()
		f.manager.monitorLoop(f.shard)
	}()
}

func TestLastAcquisitionCloseRetiresIdleCarrier(t *testing.T) {
	fixture := startMuxShardFixture(t)
	fixture.startMonitor(t)

	conn, err := fixture.manager.Open(context.Background(), 7, MuxUp)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.handle.IsClosed() {
		t.Fatal("carrier closed while an acquisition was live")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	// The carrier is retired as soon as the last handle is gone; it does not
	// wait for the idle monitor.
	waitForClose(t, fixture.handle)
	fixture.manager.mu.Lock()
	shards := len(fixture.manager.shards)
	fixture.manager.mu.Unlock()
	if shards != 0 {
		t.Fatalf("pooled carriers = %d, want 0", shards)
	}
	if reason := fixture.handle.CloseReason(); reason != carriermux.CloseReasonIdleTimeout {
		t.Fatalf("close reason = %v, want idle timeout", reason)
	}
}

func TestIdleCarrierCloseKeepsConcurrentAcquisitionsAlive(t *testing.T) {
	fixture := startMuxShardFixture(t)
	fixture.startMonitor(t)

	first, err := fixture.manager.Open(context.Background(), 7, MuxUp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.manager.Open(context.Background(), 9, MuxUp)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.shard.acquisitions.Load() != 2 {
		t.Fatalf("acquisitions = %d, want 2", fixture.shard.acquisitions.Load())
	}
	// Dropping one handle leaves the carrier up for the other flow.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.handle.IsClosed() {
		t.Fatal("carrier closed while another acquisition was live")
	}
	if _, err := second.Write([]byte("still alive")); err != nil {
		t.Fatalf("surviving stream write = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	waitForClose(t, fixture.handle)
	fixture.manager.mu.Lock()
	shards := len(fixture.manager.shards)
	fixture.manager.mu.Unlock()
	if shards != 0 {
		t.Fatalf("pooled carriers = %d, want 0", shards)
	}
}

func TestMuxManagerCloseJoinsMonitorsAndClosesCarriers(t *testing.T) {
	fixture := startMuxShardFixture(t)
	fixture.startMonitor(t)

	done := make(chan error, 1)
	go func() { done <- fixture.manager.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join the carrier monitor")
	}
	waitForClose(t, fixture.handle)
	if reason := fixture.handle.CloseReason(); reason != carriermux.CloseReasonApplication {
		t.Fatalf("close reason = %v, want application closed", reason)
	}
	// The pool is gated: further acquires fail instead of dialing.
	if _, err := fixture.manager.Open(context.Background(), 11, MuxUp); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v, want net.ErrClosed", err)
	}
	if err := fixture.manager.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestMuxOpenAfterCloseFailsWaitingAcquire(t *testing.T) {
	manager, err := NewMuxManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	// A shard that is still dialing: acquires park on its ready channel.
	shard := &muxShard{mgr: manager, ready: make(chan struct{})}
	manager.mu.Lock()
	manager.shards = append(manager.shards, shard)
	manager.mu.Unlock()

	opening := make(chan error, 1)
	go func() {
		_, err := manager.Open(context.Background(), 5, MuxUp)
		opening <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for shard.pending.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if shard.pending.Load() == 0 {
		t.Fatal("acquire never reserved the carrier")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-opening:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Open during Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not observe the pool gate")
	}
}

func waitForClose(t *testing.T, handle *carriermux.Handle) {
	t.Helper()
	select {
	case <-handle.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("carrier did not close")
	}
}
