package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// Upstream receives decoded Nowhere streams / packet flows after auth + framing.
// On success the Upstream owns conn/pc lifecycle (including any CloseHandler in ctx).
type Upstream interface {
	HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness FlowReadiness) error
	HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness FlowReadiness) error
}

type ctxKeyClose struct{}

// ContextWithCloseHandler attaches an optional CloseHandler for Upstream implementations.
func ContextWithCloseHandler(ctx context.Context, onClose CloseHandler) context.Context {
	if onClose == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyClose{}, onClose)
}

// CloseHandlerFromContext returns the CloseHandler attached by ContextWithCloseHandler.
func CloseHandlerFromContext(ctx context.Context) CloseHandler {
	h, _ := ctx.Value(ctxKeyClose{}).(CloseHandler)
	return h
}

// Dialer abstracts net.Dialer for DialUpstream.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialUpstream is a simple Portal-like upstream that dials the target and copies.
type DialUpstream struct {
	Dialer       Dialer
	tcpReadGrace time.Duration
}

// NewDialUpstream returns a DialUpstream using d, or net.Dialer if d is nil.
func NewDialUpstream(d Dialer) *DialUpstream {
	if d == nil {
		d = &net.Dialer{}
	}
	return &DialUpstream{Dialer: d, tcpReadGrace: DefaultTCPReadGrace}
}

func (u *DialUpstream) withTCPReadGrace(grace time.Duration) *DialUpstream {
	clone := *u
	clone.tcpReadGrace = grace
	return &clone
}

// HandleStream dials the TCP target, sends the setup result, and relays bytes
// until both directions close or the context is canceled.
func (u *DialUpstream) HandleStream(ctx context.Context, conn net.Conn, _ net.Addr, target wire.Target, readiness FlowReadiness) error {
	remote, err := u.Dialer.DialContext(ctx, "tcp", targetAddress(target))
	if err != nil {
		if readiness != nil {
			return errors.Join(err, readiness.Reject(err))
		}
		return err
	}
	defer remote.Close()
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			return err
		}
	}
	err = relay(conn, remote, u.tcpReadGrace)
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(err)
	}
	return nil
}

// HandlePacket dials the UDP target, sends the setup result, and relays
// datagrams until the packet flow or context closes.
func (u *DialUpstream) HandlePacket(ctx context.Context, pc net.PacketConn, _ net.Addr, target wire.Target, readiness FlowReadiness) error {
	remote, err := u.Dialer.DialContext(ctx, "udp", targetAddress(target))
	if err != nil {
		if readiness != nil {
			return errors.Join(err, readiness.Reject(err))
		}
		return err
	}
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			_ = remote.Close()
			return err
		}
	}

	destination := remote.RemoteAddr()
	if destination == nil {
		destination = targetNetAddr(target)
	}
	done := make(chan error, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				done <- err
				return
			}
			if _, err := pc.WriteTo(buf[:n], destination); err != nil {
				done <- err
				return
			}
		}
	}()

	var retErr error
	completed := 0
	select {
	case <-ctx.Done():
		retErr = context.Cause(ctx)
		if retErr == nil {
			retErr = ctx.Err()
		}
	case retErr = <-done:
		completed = 1
	}
	closePacketConnWithError(pc, retErr)
	_ = remote.Close()
	for completed < 2 {
		<-done
		completed++
	}
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(retErr)
	}
	return nil
}

func targetAddress(target wire.Target) string {
	host := target.Host
	if target.Type != wire.TargetTypeDomain {
		host = target.Addr.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(target.Port)))
}

func targetNetAddr(target wire.Target) net.Addr {
	if target.Type != wire.TargetTypeDomain && target.Addr.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.Addr, target.Port))
	}
	return &net.UDPAddr{}
}

func relay(a, b net.Conn, readGrace time.Duration) error {
	if readGrace <= 0 {
		readGrace = DefaultTCPReadGrace
	}
	type result struct {
		direction int
		err       error
	}
	done := make(chan result, 2)
	go func() {
		_, err := io.Copy(a, b)
		done <- result{direction: 0, err: err}
	}()
	go func() {
		_, err := io.Copy(b, a)
		done <- result{direction: 1, err: err}
	}()
	first := <-done
	if first.direction == 0 {
		if closer, ok := a.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	} else if closer, ok := b.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	timer := time.NewTimer(readGrace)
	var second result
	select {
	case second = <-done:
		timer.Stop()
	case <-timer.C:
		second.err = context.DeadlineExceeded
	}
	resultErr := first.err
	if resultErr == nil || errors.Is(resultErr, io.EOF) {
		resultErr = second.err
	}
	if errors.Is(resultErr, io.EOF) {
		resultErr = nil
	}
	closeConnWithError(a, resultErr)
	_ = b.Close()
	if second.err == context.DeadlineExceeded {
		<-done
	}
	return resultErr
}
