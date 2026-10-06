package server

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestDialUpstreamUsesConfiguredTCPReadGrace(t *testing.T) {
	for _, test := range []struct {
		name  string
		grace time.Duration
	}{
		{name: "short", grace: 20 * time.Millisecond},
		{name: "longer", grace: 80 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials, err := wire.NewCredentials("secret")
			if err != nil {
				t.Fatalf("NewCredentials: %v", err)
			}
			config, err := NewConfig(ConfigOptions{
				Credentials: credentials,
				Networks:    []Network{NetworkTCP},
				Timeouts:    Timeouts{TCPReadGrace: test.grace},
			})
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			remote := newGraceBlockingConn()
			t.Cleanup(func() { _ = remote.Close() })
			handler, err := NewHandler(HandlerOptions{
				Config:   config,
				Upstream: NewDialUpstream(graceDialer{conn: remote}),
			})
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}

			done := make(chan error, 1)
			target, err := wire.NewDomainTarget("example.com", 443)
			if err != nil {
				t.Fatalf("NewDomainTarget: %v", err)
			}
			go func() {
				done <- handler.upstream.HandleStream(
					context.Background(), graceEOFConn{}, nil, target, graceReadiness{},
				)
			}()
			awaitGraceSignal(t, remote.closeWriteCalled, "half-close")
			started := time.Now()
			if test.grace >= 50*time.Millisecond {
				select {
				case err := <-done:
					t.Fatalf("HandleStream returned before configured grace: %v", err)
				case <-time.After(test.grace / 2):
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("HandleStream: %v", err)
				}
				if elapsed := time.Since(started); elapsed+5*time.Millisecond < test.grace {
					t.Fatalf("relay ended after %v, before configured grace %v", elapsed, test.grace)
				}
			case <-time.After(test.grace + 200*time.Millisecond):
				t.Fatalf("relay exceeded configured TCPReadGrace %v", test.grace)
			}
		})
	}
}

func awaitGraceSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type graceDialer struct {
	conn net.Conn
}

func (d graceDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

type graceReadiness struct{}

func (graceReadiness) Ready() error       { return nil }
func (graceReadiness) Reject(error) error { return nil }

type graceEOFConn struct{}

func (graceEOFConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (graceEOFConn) Write(p []byte) (int, error)      { return len(p), nil }
func (graceEOFConn) Close() error                     { return nil }
func (graceEOFConn) LocalAddr() net.Addr              { return graceAddr("local") }
func (graceEOFConn) RemoteAddr() net.Addr             { return graceAddr("remote") }
func (graceEOFConn) SetDeadline(time.Time) error      { return nil }
func (graceEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (graceEOFConn) SetWriteDeadline(time.Time) error { return nil }

type graceBlockingConn struct {
	closed           chan struct{}
	closeWriteCalled chan struct{}
	closeOnce        sync.Once
	closeWriteOnce   sync.Once
}

func newGraceBlockingConn() *graceBlockingConn {
	return &graceBlockingConn{closed: make(chan struct{}), closeWriteCalled: make(chan struct{})}
}

func (c *graceBlockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (*graceBlockingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *graceBlockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *graceBlockingConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() { close(c.closeWriteCalled) })
	return nil
}
func (*graceBlockingConn) LocalAddr() net.Addr              { return graceAddr("remote-local") }
func (*graceBlockingConn) RemoteAddr() net.Addr             { return graceAddr("remote-peer") }
func (*graceBlockingConn) SetDeadline(time.Time) error      { return nil }
func (*graceBlockingConn) SetReadDeadline(time.Time) error  { return nil }
func (*graceBlockingConn) SetWriteDeadline(time.Time) error { return nil }

type graceAddr string

func (a graceAddr) Network() string { return string(a) }
func (a graceAddr) String() string  { return string(a) }
