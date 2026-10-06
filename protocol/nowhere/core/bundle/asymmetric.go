package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func (b *CarrierBundle) openAsymmetricTCP(ctx context.Context, target wire.Target, payloadPrefix []byte, hops uint8) (net.Conn, error) {
	up, down := b.cfg.up, b.cfg.down
	flowID, err := b.allocFlowID()
	if err != nil {
		return nil, err
	}
	started := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	openHeader, attachHeader := newSplitFlowHeaders(flowID, wire.FlowKindTCP, up, down, hops)

	var (
		tcpHeader  wire.FlowHeader
		quicHeader wire.FlowHeader
		tcpIsOpen  bool
	)
	switch {
	case up == wire.CarrierTLSTCP && down == wire.CarrierQUIC:
		tcpHeader, quicHeader, tcpIsOpen = openHeader, attachHeader, true
	case up == wire.CarrierQUIC && down == wire.CarrierTLSTCP:
		tcpHeader, quicHeader, tcpIsOpen = attachHeader, openHeader, false
	default:
		return nil, errors.New("nowhere: asymmetric tcp requires mixed carriers")
	}

	var tcpPayload []byte
	if tcpHeader.Role == wire.FlowRoleOpen {
		tcpPayload = payloadPrefix
	}
	tcpConn, err := b.openTCPCarrier(
		ctx, target, tcpHeader, tcpPayload,
		tcpHeader.CarriesTarget() && len(payloadPrefix) > 0,
	)
	if err != nil {
		b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare tcp half", err)
	}
	tcpCarrierID := uint64(0)
	defer func() {
		if tcpConn != nil {
			_ = tcpConn.Close()
		}
	}()

	quicPrep, err := b.prepareQUICStream(ctx, quicHeader.FlowID)
	if err != nil {
		cancel()
		b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("prepare quic half", err)
	}
	defer func() {
		if quicPrep != nil {
			_ = quicPrep.Close()
		}
	}()

	quicTarget := wire.Target{}
	if quicHeader.Role == wire.FlowRoleOpen {
		quicTarget = target
	}
	setupBytes, err := encodeFlowSetupBytes(quicHeader, quicTarget)
	if err != nil {
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("encode quic half", err)
	}
	if quicHeader.Role == wire.FlowRoleOpen {
		setupBytes = appendOpeningPayload(setupBytes, payloadPrefix)
	}
	quicConn, err := commitQUICHalf(ctx, quicPrep, setupBytes, quicHeader.Role == wire.FlowRoleAttach)
	if err != nil {
		cancel()
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("commit quic half", err)
	}
	quicPrep = nil

	var openConn, attachConn net.Conn
	if tcpIsOpen {
		openConn, attachConn = tcpConn, quicConn
	} else {
		openConn, attachConn = quicConn, tcpConn
	}
	if err := readSetupResult(attachConn); err != nil {
		cancel()
		_ = closeAll(openConn, attachConn)
		b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("read downlink flow result", err)
	}
	upCarrierID, downCarrierID := asymmetricCarrierIDs(up, down, tcpIsOpen, tcpCarrierID)
	b.emitAsymmetric(ctx, "asymmetric_flow_open", flowID, target, up, down, upCarrierID, downCarrierID, started, nil)
	tcpConn = nil
	return &splicedConn{
		reader: attachConn,
		writer: openConn,
		closer: []io.Closer{openConn, attachConn},
		remote: openConn.RemoteAddr(),
		local:  openConn.LocalAddr(),
	}, nil
}

func (b *CarrierBundle) emitAsymmetric(
	ctx context.Context,
	code string,
	flowID wire.FlowID,
	target wire.Target,
	up, down wire.Carrier,
	upCarrierID, downCarrierID uint64,
	started time.Time,
	err error,
) {
	observer := b.cfg.tcp.Observer()
	if observer == nil {
		return
	}
	result := diagnostic.ResultOK
	errorClass := ""
	level := diagnostic.LevelDebug
	if err != nil {
		result, errorClass = diagnostic.ClassifyClose(err)
		if result == diagnostic.ResultOK {
			result = diagnostic.ResultFailed
		}
		level = diagnostic.LevelWarn
	}
	diagnostic.Emit(ctx, observer, diagnostic.Event{
		Level:             level,
		Code:              code,
		Component:         "bundle",
		Target:            targetString(target),
		FlowID:            flowID,
		UplinkTransport:   carrierTransportName(up),
		DownlinkTransport: carrierTransportName(down),
		UplinkCarrierID:   upCarrierID,
		DownlinkCarrierID: downCarrierID,
		Result:            result,
		ErrorClass:        errorClass,
		Duration:          time.Since(started),
		Err:               err,
	})
}
