package bundle

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func (b *CarrierBundle) mixEnabled() bool {
	return b.cfg.upMode.IsMix() || b.cfg.downMode.IsMix()
}

func (b *CarrierBundle) openMixTCP(ctx context.Context, target wire.Target, payload []byte, hops uint8) (net.Conn, error) {
	lanes, flowID, route, err := b.prepareMix(ctx, wire.FlowKindTCP, hops, target, payload)
	if err != nil {
		return nil, err
	}
	conn, err := b.commitMixTCP(ctx, lanes, route, flowID, target, payload, hops)
	if err != nil {
		_ = lanes.Close()
		return nil, err
	}
	return conn, nil
}

func (b *CarrierBundle) openMixUDP(ctx context.Context, target wire.Target, hops uint8) (net.PacketConn, error) {
	started := time.Now()
	lanes, flowID, route, err := b.prepareMix(ctx, wire.FlowKindUDP, hops, target, nil)
	if err != nil {
		if route.split() {
			b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, route.uplink, route.downlink, 0, 0, started, err)
		}
		return nil, err
	}
	pc, err := b.commitMixUDP(ctx, lanes, route, flowID, target, hops)
	if err != nil {
		_ = lanes.Close()
		if route.split() {
			b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, route.uplink, route.downlink, 0, 0, started, err)
		}
		return nil, err
	}
	if route.split() {
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, route.uplink, route.downlink, 0, 0, started, nil)
	}
	return pc, nil
}

func (b *CarrierBundle) prepareMix(
	ctx context.Context,
	kind wire.FlowKind,
	hops uint8,
	target wire.Target,
	payload []byte,
) (*preparedLanes, wire.FlowID, resolvedRoute, error) {
	flowID, err := b.allocFlowID()
	if err != nil {
		return nil, 0, resolvedRoute{}, err
	}
	plan := planRoute(b.cfg.upMode, b.cfg.downMode, b.cfg.routeSeed, flowID)
	return prepareWithFallback(
		ctx,
		b.cfg.mixFallbackTimeout,
		flowID,
		plan,
		b.allocFlowID,
		func(ctx context.Context, id wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			return b.prepareLanes(ctx, route, id, kind, hops, target, payload)
		},
	)
}

func (b *CarrierBundle) commitMixTCP(
	ctx context.Context,
	lanes *preparedLanes,
	route resolvedRoute,
	flowID wire.FlowID,
	target wire.Target,
	payload []byte,
	hops uint8,
) (net.Conn, error) {
	if !route.split() {
		header := wire.FlowHeader{
			Role:     wire.FlowRoleDuplex,
			FlowID:   flowID,
			Kind:     wire.FlowKindTCP,
			Uplink:   route.uplink,
			Downlink: route.downlink,
			Hops:     hops,
		}
		conn, err := lanes.up.commit(ctx, header, target, payload)
		if err != nil {
			return nil, fmtError("commit mix duplex", err)
		}
		if err := readSetupResult(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}

	openHeader, attachHeader := newSplitFlowHeaders(flowID, wire.FlowKindTCP, route.uplink, route.downlink, hops)
	openConn, err := lanes.up.commit(ctx, openHeader, target, payload)
	if err != nil {
		return nil, fmtError("commit mix open half", err)
	}
	attachConn, err := lanes.down.commit(ctx, attachHeader, wire.Target{}, nil)
	if err != nil {
		_ = openConn.Close()
		return nil, fmtError("commit mix attach half", err)
	}
	if err := readSetupResult(attachConn); err != nil {
		_ = closeAll(openConn, attachConn)
		return nil, fmtError("read mix downlink flow result", err)
	}
	return &splicedConn{
		reader: attachConn,
		writer: openConn,
		closer: []io.Closer{openConn, attachConn},
		remote: openConn.RemoteAddr(),
		local:  openConn.LocalAddr(),
	}, nil
}

func (b *CarrierBundle) commitMixUDP(
	ctx context.Context,
	lanes *preparedLanes,
	route resolvedRoute,
	flowID wire.FlowID,
	target wire.Target,
	hops uint8,
) (net.PacketConn, error) {
	if !route.split() {
		header := wire.FlowHeader{
			Role:     wire.FlowRoleDuplex,
			FlowID:   flowID,
			Kind:     wire.FlowKindUDP,
			Uplink:   route.uplink,
			Downlink: route.downlink,
			Hops:     hops,
		}
		if route.uplink == wire.CarrierTLSTCP {
			conn, err := lanes.up.commit(ctx, header, target, nil)
			if err != nil {
				return nil, fmtError("commit mix tcp uot duplex", err)
			}
			if err := readSetupResult(conn); err != nil {
				_ = conn.Close()
				return nil, fmtError("read mix tcp uot setup result", err)
			}
			return newUOTPacketConn(conn, targetToAddr(target)), nil
		}
		conn, err := lanes.up.commit(ctx, header, target, nil)
		if err != nil {
			return nil, fmtError("commit mix quic udp duplex", err)
		}
		if err := readSetupResult(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		quicHandle, err := lanes.activateUDPDownlink()
		if err != nil {
			_ = conn.Close()
			return nil, fmtError("activate mix quic udp duplex", err)
		}
		lanes.up.quic = nil
		return newQUICPacketConn(quicHandle, conn, target), nil
	}

	openHeader, attachHeader := newSplitFlowHeaders(flowID, wire.FlowKindUDP, route.uplink, route.downlink, hops)
	if route.uplink == wire.CarrierTLSTCP {
		tcpConn, err := lanes.up.commit(ctx, openHeader, target, nil)
		if err != nil {
			return nil, fmtError("commit mix tcp open half", err)
		}
		quicConn, err := lanes.down.commit(ctx, attachHeader, wire.Target{}, nil)
		if err != nil {
			_ = tcpConn.Close()
			return nil, fmtError("commit mix quic attach half", err)
		}
		if err := readSetupResult(quicConn); err != nil {
			_ = closeAll(tcpConn, quicConn)
			return nil, fmtError("read mix quic attach setup result", err)
		}
		quicHandle, err := lanes.activateUDPDownlink()
		if err != nil {
			_ = closeAll(tcpConn, quicConn)
			return nil, fmtError("activate mix quic udp flow", err)
		}
		lanes.down.quic = nil
		return &asymmetricPacketConn{
			dest:     target,
			uplink:   &uotLaneUplink{raw: tcpConn},
			downlink: &quicLaneDownlink{prep: quicHandle},
			dnCloser: quicConn,
		}, nil
	}

	quicConn, err := lanes.up.commit(ctx, openHeader, target, nil)
	if err != nil {
		return nil, fmtError("commit mix quic open half", err)
	}
	tcpConn, err := lanes.down.commit(ctx, attachHeader, wire.Target{}, nil)
	if err != nil {
		_ = quicConn.Close()
		return nil, fmtError("commit mix tcp attach half", err)
	}
	if err := readSetupResult(tcpConn); err != nil {
		_ = closeAll(quicConn, tcpConn)
		return nil, fmtError("read mix tcp downlink setup result", err)
	}
	quicHandle := newQUICSendHandle(lanes.up.quic, flowID)
	lanes.up.quic = nil
	return &asymmetricPacketConn{
		dest:     target,
		uplink:   &quicLaneUplink{prep: quicHandle},
		downlink: &uotLaneDownlink{raw: tcpConn},
		upCloser: quicConn,
	}, nil
}
