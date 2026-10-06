package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestOpenUDPAsyncCloseCancelsPendingSetup(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	backend := &blockingQUICBackend{block: make(chan struct{})}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: backend, Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()

	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := bundle.OpenUDPAsync(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- pc.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close blocked on pending OpenUDP")
	}
	close(backend.block)
}

func TestAsyncUDPConnQueuesFirstPacket(t *testing.T) {
	inner := &recordingPacketConn{}
	c := &asyncUDPConn{
		cancel: func() {},
		queue:  make(chan queuedUDPPacket, DefaultUDPSetupQueuePackets),
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	if n, err := c.WriteTo([]byte("first"), &net.UDPAddr{}); err != nil || n != 5 {
		t.Fatalf("queued write = (%d, %v)", n, err)
	}
	c.mu.Lock()
	c.inner = inner
	c.mu.Unlock()
	close(c.ready)
	c.drainSetupQueue(inner)
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.writes) != 1 || string(inner.writes[0]) != "first" {
		t.Fatalf("drained writes = %v", inner.writes)
	}
	_ = c.Close()
}

func TestAsyncUDPConnDrainWriteFailureClosesInner(t *testing.T) {
	writeErr := errors.New("write failed")
	inner := &recordingPacketConn{writeErr: writeErr}
	c := &asyncUDPConn{
		cancel: func() {},
		queue:  make(chan queuedUDPPacket, DefaultUDPSetupQueuePackets),
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	if _, err := c.WriteTo([]byte("first"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.inner = inner
	c.mu.Unlock()
	close(c.ready)

	c.drainSetupQueue(inner)

	c.mu.Lock()
	setupErr := c.setupErr
	innerConn := c.inner
	c.mu.Unlock()
	if !errors.Is(setupErr, writeErr) {
		t.Fatalf("setupErr = %v, want %v", setupErr, writeErr)
	}
	if innerConn != nil {
		t.Fatal("inner should be cleared after drain write failure")
	}
	if got := inner.closeCount.Load(); got != 1 {
		t.Fatalf("inner Close calls = %d, want 1", got)
	}
	if _, err := c.WriteTo([]byte("late"), &net.UDPAddr{}); !errors.Is(err, writeErr) {
		t.Fatalf("WriteTo after drain failure = %v, want %v", err, writeErr)
	}
	_ = c.Close()
}

type blockingQUICBackend struct {
	block chan struct{}
}

func (b *blockingQUICBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	select {
	case <-b.block:
		return nil, errors.New("released")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*blockingQUICBackend) InvalidateSession(carrier.QuicSession) {}
func (*blockingQUICBackend) Close() error                          { return nil }

type recordingPacketConn struct {
	mu         sync.Mutex
	writes     [][]byte
	writeErr   error
	closeCount atomic.Int32
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingPacketConn) Close() error {
	c.closeCount.Add(1)
	return nil
}
func (*recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
