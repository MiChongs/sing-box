package server

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestServerSplicedConnHalfClosePreservesOppositeDirection(t *testing.T) {
	reader := newServerHalfCloseConn([]byte("downlink-remains-readable"))
	writer := newServerHalfCloseConn(nil)
	conn := &splicedConn{
		reader: reader,
		writer: writer,
		closer: []io.Closer{reader, writer},
	}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite: %v", err)
	}
	if writer.closeWriteCount() != 1 {
		t.Fatalf("writer CloseWrite count = %d, want 1", writer.closeWriteCount())
	}
	payload, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if string(payload) != "downlink-remains-readable" {
		t.Fatalf("payload = %q", payload)
	}

	reader2 := newServerHalfCloseConn(nil)
	writer2 := newServerHalfCloseConn(nil)
	conn2 := &splicedConn{
		reader: reader2,
		writer: writer2,
		closer: []io.Closer{reader2, writer2},
	}
	if err := conn2.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if _, err := conn2.Write([]byte("uplink-remains-writable")); err != nil {
		t.Fatalf("write after CloseRead: %v", err)
	}
	if got := writer2.written(); got != "uplink-remains-writable" {
		t.Fatalf("written = %q", got)
	}
}

type serverHalfCloseConn struct {
	mu         sync.Mutex
	reader     *bytes.Reader
	writer     bytes.Buffer
	closeRead  int
	closeWrite int
}

func newServerHalfCloseConn(data []byte) *serverHalfCloseConn {
	return &serverHalfCloseConn{reader: bytes.NewReader(data)}
}

func (c *serverHalfCloseConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.Read(p)
}

func (c *serverHalfCloseConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.Write(p)
}

func (c *serverHalfCloseConn) CloseRead() error {
	c.mu.Lock()
	c.closeRead++
	c.mu.Unlock()
	return nil
}

func (c *serverHalfCloseConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWrite++
	c.mu.Unlock()
	return nil
}
func (*serverHalfCloseConn) Close() error                { return nil }
func (*serverHalfCloseConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (*serverHalfCloseConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (*serverHalfCloseConn) SetDeadline(time.Time) error { return nil }
func (*serverHalfCloseConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*serverHalfCloseConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *serverHalfCloseConn) closeWriteCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWrite
}

func (c *serverHalfCloseConn) written() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.String()
}
