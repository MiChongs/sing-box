//go:build with_quic

package quic

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
)

type stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type streamConn struct {
	stream  stream
	local   net.Addr
	remote  net.Addr
	onClose func()
	writeMu sync.Mutex

	readCloseOnce  sync.Once
	readCloseErr   error
	writeCloseOnce sync.Once
	writeCloseErr  error
	closeOnce      sync.Once
	closeErr       error
	releaseOnce    sync.Once
}

func wrapStream(session *Session, stream stream) net.Conn {
	var lAddr, rAddr net.Addr
	if session.conn != nil {
		lAddr = session.conn.LocalAddr()
		rAddr = session.conn.RemoteAddr()
	}
	return &streamConn{
		stream:  stream,
		local:   lAddr,
		remote:  rAddr,
		onClose: session.releaseStream,
	}
}

func (c *streamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.UDPAddr{}
}

func (c *streamConn) Read(payload []byte) (int, error) {
	return c.stream.Read(payload)
}

func (c *streamConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.stream.Write(payload)
}

func (c *streamConn) CloseRead() error {
	c.readCloseOnce.Do(func() {
		c.stream.CancelRead(0)
	})
	return c.readCloseErr
}

func (c *streamConn) CloseWrite() error {
	c.writeCloseOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.writeCloseErr = c.stream.Close()
	})
	return c.writeCloseErr
}

func (c *streamConn) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		if err := c.stream.SetWriteDeadline(time.Now()); err != nil {
			c.stream.CancelWrite(0)
		}
		c.writeMu.Lock()
		readErr := c.CloseRead()
		c.writeCloseOnce.Do(func() {
			c.writeCloseErr = c.stream.Close()
		})
		c.writeMu.Unlock()
		c.closeErr = errors.Join(readErr, c.writeCloseErr)
		c.releaseOnce.Do(func() {
			if c.onClose != nil {
				c.onClose()
			}
		})
	})
	if !first {
		return nil
	}
	return c.closeErr
}

func (c *streamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func resetStream(stream stream) {
	_ = stream.SetWriteDeadline(time.Now())
	stream.CancelWrite(0)
	stream.CancelRead(0)
}

func abortStream(stream stream) error {
	resetStream(stream)
	return stream.Close()
}

var _ net.Conn = (*streamConn)(nil)
