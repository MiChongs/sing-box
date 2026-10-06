//go:build with_quic

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic/conformance"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestInboundQuicConnConformance(t *testing.T) {
	raw := newConformanceQUICConn()
	adapter := &quicConnAdapter{
		conn:            raw,
		maxDatagramSize: defaultMaxDatagramSize,
		streamGate:      newQUICStreamGate(),
		streamCh:        make(chan quicStreamResult, 1),
		streamDone:      make(chan struct{}),
	}
	adapter.handshakeInfo = func() (wire.TLSHandshakeInfo, error) {
		return wire.TLSHandshakeInfo{
			TLSVersion:     tls.VersionTLS13,
			NegotiatedALPN: wire.DefaultALPN,
		}, nil
	}
	adapter.sendDatagram = func(ctx context.Context, payload []byte) error {
		if raw.roundTrip.Load() {
			select {
			case raw.datagrams <- bytes.Clone(payload):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-raw.ctx.Done():
			return raw.ctx.Err()
		}
	}
	go adapter.pumpStreams()

	base := conformance.Harness{
		ExpectedALPN:     wire.DefaultALPN,
		TLSHandshakeInfo: adapter.TLSHandshakeInfo,
		Send: func(ctx context.Context) error {
			return adapter.SendDatagram(ctx, []byte("test"))
		},
		Receive: func(ctx context.Context) error {
			_, err := adapter.ReceiveDatagram(ctx)
			return err
		},
		Accept: func(ctx context.Context) error {
			_, err := adapter.AcceptStream(ctx)
			return err
		},
		Shutdown:          adapter.Close,
		MarkAuthenticated: adapter.MarkAuthenticated,
		Authenticated: func() bool {
			select {
			case <-adapter.streamGate.authenticated:
				return true
			default:
				return false
			}
		},
	}
	err := conformance.CheckFull(conformance.FullHarness{
		Harness: base,
		DatagramRoundTrip: func(ctx context.Context, payload []byte) ([]byte, error) {
			raw.roundTrip.Store(true)
			defer raw.roundTrip.Store(false)
			if err := adapter.SendDatagram(ctx, payload); err != nil {
				return nil, err
			}
			return adapter.ReceiveDatagram(ctx)
		},
		Invalidate: adapter.Close,
		Close:      adapter.Close,
	})
	if err != nil {
		t.Fatal(err)
	}
}

type conformanceQUICConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
	roundTrip atomic.Bool
	datagrams chan []byte
}

func newConformanceQUICConn() *conformanceQUICConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &conformanceQUICConn{ctx: ctx, cancel: cancel, datagrams: make(chan []byte, 1)}
}

func (c *conformanceQUICConn) AcceptStream(context.Context) (*quic.Stream, error) {
	<-c.ctx.Done()
	return nil, c.ctx.Err()
}

func (c *conformanceQUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if c.roundTrip.Load() {
		select {
		case payload := <-c.datagrams:
			return payload, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

func (c *conformanceQUICConn) SendDatagram([]byte) error {
	<-c.ctx.Done()
	return c.ctx.Err()
}

func (c *conformanceQUICConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.once.Do(c.cancel)
	return nil
}

func (c *conformanceQUICConn) Context() context.Context { return c.ctx }
func (c *conformanceQUICConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (c *conformanceQUICConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }
func (c *conformanceQUICConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}
