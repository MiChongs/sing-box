//go:build with_quic

package quic

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestQUICPacketConnForwardsBufferControl(t *testing.T) {
	readErr := errors.New("test read buffer error")
	writeErr := errors.New("test write buffer error")
	conn := &bufferControlledConn{
		fakeConnectedPacketConn: newFakeConnectedPacketConn([]byte("response")),
		readErr:                 readErr,
		writeErr:                writeErr,
	}

	packetConn := newQUICPacketConn(conn)
	readControl, ok := packetConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		t.Fatal("packet conn does not expose SetReadBuffer")
	}
	writeControl, ok := packetConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		t.Fatal("packet conn does not expose SetWriteBuffer")
	}

	if err := readControl.SetReadBuffer(4096); !errors.Is(err, readErr) {
		t.Fatalf("SetReadBuffer error = %v, want %v", err, readErr)
	}
	if err := writeControl.SetWriteBuffer(8192); !errors.Is(err, writeErr) {
		t.Fatalf("SetWriteBuffer error = %v, want %v", err, writeErr)
	}
	if conn.readBuffer != 4096 {
		t.Fatalf("SetReadBuffer value = %d, want 4096", conn.readBuffer)
	}
	if conn.writeBuffer != 8192 {
		t.Fatalf("SetWriteBuffer value = %d, want 8192", conn.writeBuffer)
	}
}

func TestQUICPacketConnDoesNotInventBufferControl(t *testing.T) {
	packetConn := newQUICPacketConn(newFakeConnectedPacketConn(nil))
	if _, ok := packetConn.(interface{ SetReadBuffer(int) error }); ok {
		t.Fatal("packet conn unexpectedly exposes SetReadBuffer")
	}
	if _, ok := packetConn.(interface{ SetWriteBuffer(int) error }); ok {
		t.Fatal("packet conn unexpectedly exposes SetWriteBuffer")
	}
}

func TestQUICPacketConnPreservesUnbindPacketSemantics(t *testing.T) {
	conn := newFakeConnectedPacketConn([]byte("response"))
	packetConn := newQUICPacketConn(conn)

	payload := make([]byte, 32)
	n, source, err := packetConn.ReadFrom(payload)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(payload[:n]); got != "response" {
		t.Fatalf("ReadFrom payload = %q, want %q", got, "response")
	}
	if source.String() != conn.remote.String() {
		t.Fatalf("ReadFrom source = %v, want %v", source, conn.remote)
	}

	ignoredDestination := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	n, err = packetConn.WriteTo([]byte("request"), ignoredDestination)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len("request") || string(conn.written) != "request" {
		t.Fatalf("WriteTo = (%d, %q), want (%d, %q)", n, conn.written, len("request"), "request")
	}
	if packetConn.LocalAddr().String() != conn.local.String() {
		t.Fatalf("LocalAddr = %v, want %v", packetConn.LocalAddr(), conn.local)
	}

	deadline := time.Unix(100, 200)
	readDeadline := time.Unix(300, 400)
	writeDeadline := time.Unix(500, 600)
	if err := packetConn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := packetConn.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := packetConn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if conn.deadline != deadline {
		t.Fatalf("SetDeadline value = %v, want %v", conn.deadline, deadline)
	}
	if conn.readDeadline != readDeadline {
		t.Fatalf("SetReadDeadline value = %v, want %v", conn.readDeadline, readDeadline)
	}
	if conn.writeDeadline != writeDeadline {
		t.Fatalf("SetWriteDeadline value = %v, want %v", conn.writeDeadline, writeDeadline)
	}

	if err := packetConn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if conn.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", conn.closeCalls)
	}
}

type fakeConnectedPacketConn struct {
	readPayload   []byte
	written       []byte
	local         net.Addr
	remote        net.Addr
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	closeCalls    int
}

func newFakeConnectedPacketConn(readPayload []byte) *fakeConnectedPacketConn {
	return &fakeConnectedPacketConn{
		readPayload: readPayload,
		local:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000},
		remote:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000},
	}
}

func (c *fakeConnectedPacketConn) Read(payload []byte) (int, error) {
	if c.readPayload == nil {
		return 0, io.EOF
	}
	n := copy(payload, c.readPayload)
	c.readPayload = nil
	return n, nil
}

func (c *fakeConnectedPacketConn) Write(payload []byte) (int, error) {
	c.written = append(c.written[:0], payload...)
	return len(payload), nil
}

func (c *fakeConnectedPacketConn) Close() error {
	c.closeCalls++
	return nil
}

func (c *fakeConnectedPacketConn) LocalAddr() net.Addr {
	return c.local
}

func (c *fakeConnectedPacketConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *fakeConnectedPacketConn) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}

func (c *fakeConnectedPacketConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return nil
}

func (c *fakeConnectedPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return nil
}

type bufferControlledConn struct {
	*fakeConnectedPacketConn
	readBuffer  int
	writeBuffer int
	readErr     error
	writeErr    error
}

func (c *bufferControlledConn) SetReadBuffer(size int) error {
	c.readBuffer = size
	return c.readErr
}

func (c *bufferControlledConn) SetWriteBuffer(size int) error {
	c.writeBuffer = size
	return c.writeErr
}

var _ net.Conn = (*fakeConnectedPacketConn)(nil)
