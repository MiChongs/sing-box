package bundle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// physicalLane is a pre-commit carrier: AUTH may have been written, FlowHeader
// has not. Close abandons an unused lane; commit transfers the live conn.
type physicalLane struct {
	carrier wire.Carrier
	tcp     *tcptls.PreparedFlowHalf
	mux     net.Conn
	quic    *quicPreparedStream
}

func (l *physicalLane) Close() error {
	if l == nil {
		return nil
	}
	var err error
	switch {
	case l.tcp != nil:
		err = l.tcp.Close()
		l.tcp = nil
	case l.mux != nil:
		err = l.mux.Close()
		l.mux = nil
	case l.quic != nil:
		err = l.quic.Close()
		l.quic = nil
	}
	return err
}

type preparedLanes struct {
	up            *physicalLane
	down          *physicalLane
	downDatagrams *preparedQUICDatagrams
	split         bool
}

func (p *preparedLanes) Close() error {
	if p == nil {
		return nil
	}
	return closeAll(p.downDatagrams, p.up, p.down)
}

func (b *CarrierBundle) prepareLanes(
	ctx context.Context,
	route resolvedRoute,
	flowID wire.FlowID,
	kind wire.FlowKind,
	hops uint8,
	target wire.Target,
	payload []byte,
) (*preparedLanes, error) {
	if !route.split() {
		header := wire.FlowHeader{
			Role:     wire.FlowRoleDuplex,
			FlowID:   flowID,
			Kind:     kind,
			Uplink:   route.uplink,
			Downlink: route.downlink,
			Hops:     hops,
		}
		lane, err := b.prepareLane(ctx, header, target, len(payload) > 0, tcptls.MuxUp)
		if err != nil {
			return nil, err
		}
		lanes := &preparedLanes{up: lane}
		if err := lanes.prepareUDPDownlink(kind, route, flowID); err != nil {
			_ = lanes.Close()
			return nil, err
		}
		return lanes, nil
	}

	openHeader, attachHeader := newSplitFlowHeaders(flowID, kind, route.uplink, route.downlink, hops)
	type result struct {
		lane *physicalLane
		err  error
	}
	upCh := make(chan result, 1)
	downCh := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		deferAuth := openHeader.Uplink == wire.CarrierTLSTCP && len(payload) > 0
		lane, err := b.prepareLane(ctx, openHeader, target, deferAuth, tcptls.MuxUp)
		upCh <- result{lane: lane, err: err}
	}()
	go func() {
		defer wg.Done()
		lane, err := b.prepareLane(ctx, attachHeader, wire.Target{}, false, tcptls.MuxDown)
		downCh <- result{lane: lane, err: err}
	}()
	up := <-upCh
	down := <-downCh
	wg.Wait()
	switch {
	case up.err == nil && down.err == nil:
		lanes := &preparedLanes{up: up.lane, down: down.lane, split: true}
		if err := lanes.prepareUDPDownlink(kind, route, flowID); err != nil {
			_ = lanes.Close()
			return nil, err
		}
		return lanes, nil
	case up.err != nil && down.err == nil:
		_ = down.lane.Close()
		return nil, up.err
	case up.err == nil && down.err != nil:
		_ = up.lane.Close()
		return nil, down.err
	default:
		_ = up.lane.Close()
		_ = down.lane.Close()
		return nil, fmt.Errorf(
			"nowhere: both %s route lanes failed before commit: uplink: %v; downlink: %v",
			route.label(), up.err, down.err,
		)
	}
}

func (p *preparedLanes) prepareUDPDownlink(kind wire.FlowKind, route resolvedRoute, flowID wire.FlowID) error {
	if kind != wire.FlowKindUDP || route.downlink != wire.CarrierQUIC {
		return nil
	}
	lane := p.up
	if p.split {
		lane = p.down
	}
	if lane == nil || lane.quic == nil {
		return errors.New("nowhere: missing prepared QUIC UDP downlink")
	}
	prepared, err := prepareQUICDatagrams(lane.quic, flowID)
	if err != nil {
		return err
	}
	p.downDatagrams = prepared
	return nil
}

func (p *preparedLanes) activateUDPDownlink() (*qSessionHandle, error) {
	if p == nil || p.downDatagrams == nil {
		return nil, errors.New("nowhere: missing prepared QUIC UDP registration")
	}
	prepared := p.downDatagrams
	p.downDatagrams = nil
	return prepared.Activate()
}

func (b *CarrierBundle) prepareLane(
	ctx context.Context,
	header wire.FlowHeader,
	target wire.Target,
	deferAuth bool,
	dir tcptls.MuxDirection,
) (*physicalLane, error) {
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
	}
	switch carrier {
	case wire.CarrierTLSTCP:
		if b.cfg.mux == MuxEnabled {
			mgr, err := b.tlsMux()
			if err != nil {
				return nil, err
			}
			if mgr == nil {
				return nil, errors.New("nowhere: mux manager unavailable")
			}
			stream, err := mgr.Open(ctx, header.FlowID, dir)
			if err != nil {
				return nil, err
			}
			return &physicalLane{carrier: carrier, mux: stream}, nil
		}
		half, err := b.prepareTCPHalf(ctx, target, header, deferAuth)
		if err != nil {
			return nil, err
		}
		return &physicalLane{carrier: carrier, tcp: half}, nil
	case wire.CarrierQUIC:
		prep, err := b.prepareQUICStream(ctx, header.FlowID)
		if err != nil {
			return nil, err
		}
		return &physicalLane{carrier: carrier, quic: prep}, nil
	default:
		return nil, errors.New("nowhere: invalid carrier")
	}
}

func (l *physicalLane) commit(ctx context.Context, header wire.FlowHeader, target wire.Target, payload []byte) (net.Conn, error) {
	if l == nil {
		return nil, errors.New("nowhere: nil physical lane")
	}
	switch {
	case l.tcp != nil:
		conn, err := l.tcp.CommitWithPayload(payload)
		l.tcp = nil
		return conn, err
	case l.mux != nil:
		setup, err := encodeFlowSetupBytes(header, target)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		if err := wire.WriteFull(l.mux, appendOpeningPayload(setup, payload)); err != nil {
			_ = l.Close()
			return nil, err
		}
		conn := l.mux
		l.mux = nil
		return conn, nil
	case l.quic != nil:
		setup, err := encodeFlowSetupBytes(header, target)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		finishWrite := header.Kind == wire.FlowKindUDP || header.Role == wire.FlowRoleAttach
		conn, err := l.quic.commit(ctx, appendOpeningPayload(setup, payload), finishWrite)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		if header.Kind == wire.FlowKindTCP {
			l.quic = nil
		}
		return conn, nil
	default:
		return nil, errors.New("nowhere: empty physical lane")
	}
}
