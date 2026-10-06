package tcptls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
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
