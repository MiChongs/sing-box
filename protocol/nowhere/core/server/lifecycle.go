package server

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
)

// CloseHandler is invoked exactly once for each physical carrier.
// It runs synchronously after the carrier is closed. Implementations must return promptly.
type CloseHandler func(error)

type lifecycle struct {
	once     sync.Once
	closer   io.Closer
	callback CloseHandler
	observer diagnostic.Observer
	ctx      context.Context
}

func newLifecycle(ctx context.Context, closer io.Closer, callback CloseHandler, observer diagnostic.Observer) *lifecycle {
	if ctx == nil {
		ctx = context.Background()
	}
	return &lifecycle{ctx: ctx, closer: closer, callback: callback, observer: observer}
}

func (l *lifecycle) Close(err error) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.closer != nil {
			_ = l.closer.Close()
		}
		if l.callback != nil {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						diagnostic.Emit(l.ctx, l.observer, diagnostic.Event{
							Level:     diagnostic.LevelError,
							Code:      "callback_panic",
							Component: "server",
						})
					}
				}()
				l.callback(err)
			}()
		}
	})
}

type ownedConn struct {
	net.Conn
	life *lifecycle
}

func (c *ownedConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return c.Close()
}

func (c *ownedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Close()
}

func (c *ownedConn) Close() error {
	if c == nil {
		return nil
	}
	c.life.Close(nil)
	return nil
}

func (c *ownedConn) closeWithError(err error) { c.life.Close(err) }

type ownedPacketConn struct {
	net.PacketConn
	life *lifecycle
}

func (c *ownedPacketConn) Close() error {
	if c == nil {
		return nil
	}
	c.life.Close(nil)
	return nil
}

func (c *ownedPacketConn) closeWithError(err error) { c.life.Close(err) }
