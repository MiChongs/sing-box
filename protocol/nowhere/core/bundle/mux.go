package bundle

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// MuxMode selects client TLS lane framing. Portal auto-detects both forms.
type MuxMode uint8

const (
	// MuxDisabled originates dedicated TLS lanes (AuthFrame then FlowHeader).
	MuxDisabled MuxMode = 0
	// MuxEnabled originates marked Mux TLS shards (AuthFrame, 0xff, Mux frames).
	MuxEnabled MuxMode = 1
)

func (m MuxMode) validate() error {
	switch m {
	case MuxDisabled, MuxEnabled:
		return nil
	default:
		return errors.New("nowhere: mux mode must be 0 or 1")
	}
}

func (b *CarrierBundle) tlsMux() (*tcptls.MuxManager, error) {
	if !b.cfg.usesTCP {
		return nil, nil
	}
	b.muxOnce.Do(func() {
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()
		if b.closed {
			b.muxErr = net.ErrClosed
			return
		}
		if _, err := b.SessionID(); err != nil {
			b.muxErr = err
			return
		}
		b.mux, b.muxErr = tcptls.NewMuxManager(b.cfg.tcp)
	})
	return b.mux, b.muxErr
}

func (b *CarrierBundle) openTCPCarrier(ctx context.Context, target wire.Target, header wire.FlowHeader, payload []byte, deferAuth bool) (net.Conn, error) {
	if b.cfg.mux == MuxEnabled {
		return b.openMuxTCPLane(ctx, target, header, payload)
	}
	half, err := b.prepareTCPHalf(ctx, target, header, deferAuth)
	if err != nil {
		return nil, err
	}
	conn, err := half.CommitWithPayload(payload)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (b *CarrierBundle) openMuxTCPLane(ctx context.Context, target wire.Target, header wire.FlowHeader, payload []byte) (net.Conn, error) {
	mgr, err := b.tlsMux()
	if err != nil {
		return nil, err
	}
	if mgr == nil {
		return nil, errors.New("nowhere: mux manager unavailable")
	}
	dir := tcptls.MuxUp
	if header.Role == wire.FlowRoleAttach {
		dir = tcptls.MuxDown
	}
	stream, err := mgr.Open(ctx, header.FlowID, dir)
	if err != nil {
		return nil, err
	}
	setup, err := encodeFlowSetupBytes(header, target)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	opening := append(setup, payload...)
	if err := wire.WriteFull(stream, opening); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}
