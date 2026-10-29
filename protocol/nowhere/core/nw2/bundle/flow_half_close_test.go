package bundle

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSplicedConnCloseWriteKeepsReadSideAlive(t *testing.T) {
	reader := newHalfCloseTestConn([]byte("reply-after-eof"))
	writer := newHalfCloseTestConn(nil)
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
	if got := writer.closeWriteCount(); got != 1 {
		t.Fatalf("writer CloseWrite count = %d, want 1", got)
	}
	if got := reader.closeWriteCount(); got != 0 {
		t.Fatalf("reader CloseWrite count = %d, want 0", got)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if string(reply) != "reply-after-eof" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestSplicedConnCloseReadKeepsWriteSideAlive(t *testing.T) {
	reader := newHalfCloseTestConn(nil)
	writer := newHalfCloseTestConn(nil)
	conn := &splicedConn{
		reader: reader,
		writer: writer,
		closer: []io.Closer{reader, writer},
	}

	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if _, err := conn.Write([]byte("request-after-read-close")); err != nil {
		t.Fatalf("write after CloseRead: %v", err)
	}
	if got := writer.written(); got != "request-after-read-close" {
		t.Fatalf("written = %q", got)
	}
	if got := writer.closeReadCount(); got != 0 {
		t.Fatalf("writer CloseRead count = %d, want 0", got)
	}
}

type halfCloseTestConn struct {
	mu         sync.Mutex
	reader     *bytes.Reader
	writer     bytes.Buffer
	closeRead  int
	closeWrite int
	closed     int
}

func newHalfCloseTestConn(data []byte) *halfCloseTestConn {
	return &halfCloseTestConn{reader: bytes.NewReader(data)}
}

func (c *halfCloseTestConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.Read(p)
}

func (c *halfCloseTestConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.Write(p)
}

func (c *halfCloseTestConn) CloseRead() error {
	c.mu.Lock()
	c.closeRead++
	c.mu.Unlock()
	return nil
}

func (c *halfCloseTestConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWrite++
	c.mu.Unlock()
	return nil
}

func (c *halfCloseTestConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *halfCloseTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *halfCloseTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *halfCloseTestConn) SetDeadline(time.Time) error      { return nil }
func (c *halfCloseTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *halfCloseTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *halfCloseTestConn) closeReadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeRead
}

func (c *halfCloseTestConn) closeWriteCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWrite
}

func (c *halfCloseTestConn) written() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.String()
}

var (
	_ interface{ CloseRead() error }  = (*halfCloseTestConn)(nil)
	_ interface{ CloseWrite() error } = (*halfCloseTestConn)(nil)
)
