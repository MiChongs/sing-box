package bundle

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

// openUDPRoute opens a UDP logical flow on the resolved up/down route.
func (b *CarrierBundle) openUDPRoute(ctx context.Context, target wire.Target, hops uint8) (net.PacketConn, error) {
	started := time.Now()
	route := planRoute(b.cfg.upMode, b.cfg.downMode)
	flowID, err := b.allocFlowID()
	if err != nil {
		return nil, err
	}
	lanes, err := b.prepareLanes(ctx, route, flowID, wire.FlowKindUDP, hops, target, nil)
	if err != nil {
		if route.split() {
			b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, route.uplink, route.downlink, 0, 0, started, err)
		}
		return nil, err
	}
	pc, err := b.commitUDPRoute(ctx, lanes, route, flowID, target, hops)
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

func (b *CarrierBundle) commitUDPRoute(
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
				return nil, fmtError("commit tcp uot duplex", err)
			}
			if err := readSetupResult(conn); err != nil {
				_ = conn.Close()
				return nil, fmtError("read tcp uot setup result", err)
			}
			return newUOTPacketConn(conn, targetToAddr(target)), nil
		}
		conn, err := lanes.up.commit(ctx, header, target, nil)
		if err != nil {
			return nil, fmtError("commit quic udp duplex", err)
		}
		if err := readSetupResult(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		quicHandle, err := lanes.activateUDPDownlink()
		if err != nil {
			_ = conn.Close()
			return nil, fmtError("activate quic udp duplex", err)
		}
		lanes.up.quic = nil
		return newQUICPacketConn(quicHandle, conn, target), nil
	}

	openHeader, attachHeader := newSplitFlowHeaders(flowID, wire.FlowKindUDP, route.uplink, route.downlink, hops)
	if route.uplink == wire.CarrierTLSTCP {
		tcpConn, err := lanes.up.commit(ctx, openHeader, target, nil)
		if err != nil {
			return nil, fmtError("commit tcp open half", err)
		}
		quicConn, err := lanes.down.commit(ctx, attachHeader, wire.Target{}, nil)
		if err != nil {
			_ = tcpConn.Close()
			return nil, fmtError("commit quic attach half", err)
		}
		if err := readSetupResult(quicConn); err != nil {
			_ = closeAll(tcpConn, quicConn)
			return nil, fmtError("read quic attach setup result", err)
		}
		quicHandle, err := lanes.activateUDPDownlink()
		if err != nil {
			_ = closeAll(tcpConn, quicConn)
			return nil, fmtError("activate quic udp flow", err)
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
		return nil, fmtError("commit quic open half", err)
	}
	tcpConn, err := lanes.down.commit(ctx, attachHeader, wire.Target{}, nil)
	if err != nil {
		_ = quicConn.Close()
		return nil, fmtError("commit tcp attach half", err)
	}
	if err := readSetupResult(tcpConn); err != nil {
		_ = closeAll(quicConn, tcpConn)
		return nil, fmtError("read tcp downlink setup result", err)
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
