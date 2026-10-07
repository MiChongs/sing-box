package tcpinfo

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestLossRate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		info   Info
		sent   uint64
		retx   uint64
		lossed float64
	}{
		{"unknown", Info{}, 0, 0, 0},
		{"segments win over bytes", Info{SegsOut: 200, RetransSegs: 10, BytesSent: 1e6, BytesRetrans: 1}, 200, 10, 0.05},
		{"bytes only", Info{BytesSent: 4000, BytesRetrans: 100}, 4000, 100, 0.025},
		{"clamped", Info{SegsOut: 10, RetransSegs: 30}, 10, 30, 1},
	} {
		if got := tc.info.Sent(); got != tc.sent {
			t.Errorf("%s: Sent = %d, want %d", tc.name, got, tc.sent)
		}
		if got := tc.info.Retransmitted(); got != tc.retx {
			t.Errorf("%s: Retransmitted = %d, want %d", tc.name, got, tc.retx)
		}
		if got := tc.info.LossRate(); got != tc.lossed {
			t.Errorf("%s: LossRate = %v, want %v", tc.name, got, tc.lossed)
		}
	}
}

type upstreamConn struct {
	net.Conn
	inner net.Conn
}

func (c *upstreamConn) Upstream() any { return c.inner }

// fieldConn hides the socket behind an exported field only.
type fieldConn struct {
	io.Reader
	Transport net.Conn
}

func (c *fieldConn) Write(b []byte) (int, error)        { return c.Transport.Write(b) }
func (c *fieldConn) Close() error                       { return c.Transport.Close() }
func (c *fieldConn) LocalAddr() net.Addr                { return c.Transport.LocalAddr() }
func (c *fieldConn) RemoteAddr() net.Addr               { return c.Transport.RemoteAddr() }
func (c *fieldConn) SetDeadline(t time.Time) error      { return c.Transport.SetDeadline(t) }
func (c *fieldConn) SetReadDeadline(t time.Time) error  { return c.Transport.SetReadDeadline(t) }
func (c *fieldConn) SetWriteDeadline(t time.Time) error { return c.Transport.SetWriteDeadline(t) }

// TestReadUnwrapsToSocket: the counters are read through proxy wrappers
// from the TCP socket underneath, on every platform that reports them.
func TestReadUnwrapsToSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, conn)
			conn.Close()
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}

	supported := map[string]bool{"linux": true, "android": true, "darwin": true, "ios": true, "windows": true}[runtime.GOOS]
	for name, wrapped := range map[string]net.Conn{
		"socket":   conn,
		"upstream": &upstreamConn{inner: conn},
		"field":    &fieldConn{Reader: conn, Transport: conn},
	} {
		info, ok := Read(wrapped)
		if !supported {
			continue
		}
		if !ok || info.Sent() == 0 {
			t.Errorf("%s: Read = %+v, %v; want sent counters", name, info, ok)
		}
	}

	if _, ok := Read(&upstreamConn{inner: nil}); ok {
		t.Error("wrapper without a socket reported counters")
	}
	if _, ok := Read(nil); ok {
		t.Error("nil conn reported counters")
	}
}
