package server

import (
	"context"
	"net"
	"sync"
	"time"
)

type claimContextKey struct{}

func withClaimContext(ctx context.Context, claimCtx context.Context) context.Context {
	if claimCtx == nil {
		return ctx
	}
	return context.WithValue(ctx, claimContextKey{}, claimCtx)
}

func claimContextFrom(ctx context.Context) context.Context {
	claimCtx, _ := ctx.Value(claimContextKey{}).(context.Context)
	return claimCtx
}

type routeLifetime struct {
	once    sync.Once
	cancel  context.CancelCauseFunc
	finish  func()
	release func()
}

func (l *routeLifetime) end(cause error) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}
		if l.cancel != nil {
			l.cancel(cause)
		}
		if l.release != nil {
			l.release()
		}
		if l.finish != nil {
			l.finish()
		}
	})
}

type trackedFlowConn struct {
	net.Conn
	life      *routeLifetime
	closeOnce sync.Once
	closeErr  error
}

func (c *trackedFlowConn) CloseRead() error {
	return closeReadSide(c.Conn)
}

func (c *trackedFlowConn) CloseWrite() error {
	return closeWriteSide(c.Conn)
}

func (c *trackedFlowConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.life.end(c.closeErr)
	})
	return c.closeErr
}

func (c *trackedFlowConn) closeWithError(cause error) {
	c.closeOnce.Do(func() {
		closeConnWithError(c.Conn, cause)
		c.life.end(cause)
	})
}

type trackedFlowPacketConn struct {
	net.PacketConn
	life      *routeLifetime
	closeOnce sync.Once
	closeErr  error
}

func (c *trackedFlowPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.PacketConn.Close()
		c.life.end(c.closeErr)
	})
	return c.closeErr
}

func (c *trackedFlowPacketConn) closeWithError(cause error) {
	c.closeOnce.Do(func() {
		closePacketConnWithError(c.PacketConn, cause)
		c.life.end(cause)
	})
}

func (c *trackedFlowPacketConn) SetDeadline(value time.Time) error {
	return c.PacketConn.SetDeadline(value)
}
