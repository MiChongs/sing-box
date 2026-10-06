package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// PortalUpstream forwards authenticated flows through another native Nowhere
// Portal using a CarrierBundle. It does not own the bundle: callers must stop
// the Handler or Server before closing the bundle.
type PortalUpstream struct {
	client       portalFlowClient
	tcpReadGrace time.Duration
}

type portalFlowClient interface {
	OpenTCPWithHops(context.Context, wire.Target, uint8) (net.Conn, error)
	OpenUDPWithHops(context.Context, wire.Target, uint8) (net.PacketConn, error)
}

// NewPortalUpstream returns a native Portal-to-Portal forwarding Upstream.
// The supplied bundle remains caller-owned and must outlive the Upstream.
func NewPortalUpstream(client *bundle.CarrierBundle) (*PortalUpstream, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil Portal bundle", ErrUpstreamNotConfigured)
	}
	return &PortalUpstream{client: client, tcpReadGrace: DefaultTCPReadGrace}, nil
}

func (u *PortalUpstream) withTCPReadGrace(grace time.Duration) *PortalUpstream {
	clone := *u
	clone.tcpReadGrace = grace
	return &clone
}

// HandleStream opens the next native Portal flow, commits incoming readiness,
// and relays bytes until both directions close or the context is canceled.
func (u *PortalUpstream) HandleStream(ctx context.Context, conn net.Conn, _ net.Addr, target wire.Target, readiness FlowReadiness) error {
	hops, err := forwardedPortalHops(ctx)
	if err != nil {
		return rejectForwardedFlow(readiness, err)
	}
	remote, err := u.client.OpenTCPWithHops(ctx, target, hops)
	if err != nil {
		return rejectForwardedFlow(readiness, err)
	}
	defer remote.Close()
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			return err
		}
	}
	stopCancel := afterContextFunc(ctx, func() {
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		closeConnWithError(conn, cause)
		_ = remote.Close()
	})
	defer stopCancel()
	err = relay(conn, remote, u.tcpReadGrace)
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(err)
	}
	return nil
}

// HandlePacket opens the next native Portal UDP flow, commits incoming
// readiness, and relays datagrams until either side closes or ctx is canceled.
func (u *PortalUpstream) HandlePacket(ctx context.Context, pc net.PacketConn, _ net.Addr, target wire.Target, readiness FlowReadiness) error {
	hops, err := forwardedPortalHops(ctx)
	if err != nil {
		return rejectForwardedFlow(readiness, err)
	}
	remote, err := u.client.OpenUDPWithHops(ctx, target, hops)
	if err != nil {
		return rejectForwardedFlow(readiness, err)
	}
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			_ = remote.Close()
			return err
		}
	}
	relayErr := relayPacketConns(ctx, pc, remote, targetNetAddr(target))
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(relayErr)
	}
	return nil
}

func forwardedPortalHops(ctx context.Context) (uint8, error) {
	info, _ := FlowInfoFromContext(ctx)
	switch info.Hops {
	case 0:
		return wire.MaxPortalHops, nil
	case 1:
		return 0, ErrPortalHopLimit
	default:
		if info.Hops > wire.MaxPortalHops {
			return 0, fmt.Errorf("%w: portal hop budget %d", wire.ErrInvalidFlowHeader, info.Hops)
		}
		return info.Hops - 1, nil
	}
}

func rejectForwardedFlow(readiness FlowReadiness, cause error) error {
	if readiness == nil {
		return cause
	}
	return errors.Join(cause, readiness.Reject(cause))
}

func relayPacketConns(ctx context.Context, incoming, upstream net.PacketConn, destination net.Addr) error {
	done := make(chan error, 2)
	copyPackets := func(dst, src net.PacketConn) {
		buf := make([]byte, 65535)
		for {
			n, _, err := src.ReadFrom(buf)
			if err == nil {
				_, err = dst.WriteTo(buf[:n], destination)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}
	go copyPackets(upstream, incoming)
	go copyPackets(incoming, upstream)

	var relayErr error
	completed := 0
	select {
	case <-ctx.Done():
		relayErr = context.Cause(ctx)
		if relayErr == nil {
			relayErr = ctx.Err()
		}
	case relayErr = <-done:
		completed = 1
	}
	closePacketConnWithError(incoming, relayErr)
	_ = upstream.Close()
	for completed < 2 {
		<-done
		completed++
	}
	return relayErr
}

var _ Upstream = (*PortalUpstream)(nil)
