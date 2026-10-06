package bundle

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const initialTCPPayloadCoalesceLimit = 64 * 1024

// OpenTCP opens a TCP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return b.openTCP(ctx, target, nil, 0)
}

// OpenTCPWithHops opens a TCP logical flow with an explicit remaining native
// Portal forwarding budget. Vector-originated callers should use OpenTCP,
// which always writes HOPS zero.
func (b *CarrierBundle) OpenTCPWithHops(ctx context.Context, target wire.Target, hops uint8) (net.Conn, error) {
	return b.openTCP(ctx, target, nil, hops)
}

// OpenTCPWithPayload opens a TCP logical flow and synchronously writes payload.
// Up to 64 KiB is coalesced into the opening envelope; any remainder is written
// only after the peer returns READY. The caller retains ownership of payload.
func (b *CarrierBundle) OpenTCPWithPayload(ctx context.Context, target wire.Target, payload []byte) (net.Conn, error) {
	return b.openTCP(ctx, target, payload, 0)
}

func (b *CarrierBundle) openTCP(ctx context.Context, target wire.Target, payload []byte, hops uint8) (net.Conn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if hops > wire.MaxPortalHops {
		return nil, errors.New("nowhere: portal hop budget exceeds 7")
	}
	prefixLen := len(payload)
	if prefixLen > initialTCPPayloadCoalesceLimit {
		prefixLen = initialTCPPayloadCoalesceLimit
	}
	prefix, tail := payload[:prefixLen], payload[prefixLen:]

	var (
		conn net.Conn
		err  error
	)
	if b.mixEnabled() {
		conn, err = b.openMixTCP(ctx, target, prefix, hops)
	} else if b.cfg.up != b.cfg.down {
		conn, err = b.openAsymmetricTCP(ctx, target, prefix, hops)
	} else {
		switch b.cfg.up {
		case wire.CarrierTLSTCP:
			conn, err = b.openSymmetricTCPTCP(ctx, target, prefix, hops)
		case wire.CarrierQUIC:
			conn, err = b.openSymmetricUDPQUIC(ctx, target, prefix, hops)
		default:
			return nil, errors.New("nowhere: invalid carrier")
		}
	}
	if err != nil {
		return nil, err
	}
	if len(tail) > 0 {
		if err := wire.WriteFull(conn, tail); err != nil {
			_ = conn.Close()
			return nil, fmtError("write initial tcp payload tail", err)
		}
	}
	return conn, nil
}

// OpenUDP opens a UDP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenUDP(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	return b.openUDP(ctx, target, 0)
}

// OpenUDPWithHops opens a UDP logical flow with an explicit remaining native
// Portal forwarding budget. Vector-originated callers should use OpenUDP,
// which always writes HOPS zero.
func (b *CarrierBundle) OpenUDPWithHops(ctx context.Context, target wire.Target, hops uint8) (net.PacketConn, error) {
	return b.openUDP(ctx, target, hops)
}

func (b *CarrierBundle) openUDP(ctx context.Context, target wire.Target, hops uint8) (net.PacketConn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if hops > wire.MaxPortalHops {
		return nil, errors.New("nowhere: portal hop budget exceeds 7")
	}
	return b.openMixUDP(ctx, target, hops)
}

func (b *CarrierBundle) openSymmetricTCPTCP(ctx context.Context, target wire.Target, payloadPrefix []byte, hops uint8) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, target, hops)
	if err != nil {
		return nil, err
	}
	conn, err := b.openTCPCarrier(ctx, target, setup.header, payloadPrefix, len(payloadPrefix) > 0)
	if err != nil {
		return nil, fmtError("prepare tcp duplex", err)
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (b *CarrierBundle) openSymmetricUDPQUIC(ctx context.Context, target wire.Target, payloadPrefix []byte, hops uint8) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, target, hops)
	if err != nil {
		return nil, err
	}
	return b.openQUICDuplexStream(ctx, setup, payloadPrefix)
}

func (b *CarrierBundle) openQUICDuplexStream(ctx context.Context, setup flowSetup, payloadPrefix []byte) (net.Conn, error) {
	prep, err := b.prepareQUICStream(ctx, setup.header.FlowID)
	if err != nil {
		return nil, fmtError("prepare quic duplex", err)
	}
	setupBytes, err := setup.bytes()
	if err != nil {
		_ = prep.Close()
		return nil, fmtError("encode duplex setup", err)
	}
	conn, err := commitQUICHalf(ctx, prep, appendOpeningPayload(setupBytes, payloadPrefix), false)
	if err != nil {
		_ = prep.Close()
		return nil, err
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
