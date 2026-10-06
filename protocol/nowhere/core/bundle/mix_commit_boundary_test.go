package bundle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestMixedRouteDoesNotFallbackAfterCommitStarts(t *testing.T) {
	tests := []struct {
		name string
		open func(*CarrierBundle, wire.Target) error
		set  func(*testing.T, *v15AuthSession)
	}{
		{
			name: "flow header commit",
			set: func(_ *testing.T, raw *v15AuthSession) {
				raw.stream.commitErr = io.ErrClosedPipe
			},
			open: func(b *CarrierBundle, target wire.Target) error {
				_, err := b.OpenUDP(context.Background(), target)
				return err
			},
		},
		{
			name: "non-ready setup result",
			set: func(t *testing.T, raw *v15AuthSession) {
				client, peer := net.Pipe()
				raw.stream.conn = client
				t.Cleanup(func() { _ = peer.Close() })
				go func() {
					_ = wire.WriteSetupResult(peer, wire.SetupResultDialFailed)
				}()
			},
			open: func(b *CarrierBundle, target wire.Target) error {
				_, err := b.OpenUDP(context.Background(), target)
				return err
			},
		},
		{
			name: "post-ready payload tail",
			set: func(_ *testing.T, raw *v15AuthSession) {
				raw.stream.conn = &readyRecordingConn{writeErr: io.ErrClosedPipe}
			},
			open: func(b *CarrierBundle, target wire.Target) error {
				payload := bytes.Repeat([]byte{0x5a}, initialTCPPayloadCoalesceLimit+1)
				_, err := b.OpenTCPWithPayload(context.Background(), target, payload)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &v15AuthSession{}
			test.set(t, raw)
			b, tcpDials := newMixedQUICPrimaryTestBundle(t, raw)
			defer b.Close()
			target, err := wire.NewDomainTarget("commit-boundary.example", 443)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.open(b, target); err == nil {
				t.Fatal("expected committed flow failure")
			}
			if got := tcpDials.Load(); got != 0 {
				t.Fatalf("fallback TCP dials = %d, want 0", got)
			}
			if got := raw.prepareCalls; got != 1 {
				t.Fatalf("QUIC stream preparations = %d, want 1", got)
			}
			if got := b.nextFlowID.Load(); got != 2 {
				t.Fatalf("next flow ID = %d, fallback ID was allocated", got)
			}
		})
	}
}

func newMixedQUICPrimaryTestBundle(t *testing.T, raw *v15AuthSession) (*CarrierBundle, *atomic.Int32) {
	t.Helper()
	credentials, err := wire.NewCredentials("mix-commit-boundary")
	if err != nil {
		t.Fatal(err)
	}
	var tcpDials atomic.Int32
	tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address:   "fallback.invalid:443",
		Dialer:    failingCountingTCPDialer{calls: &tcpDials},
		TLSDialer: mixMatrixTLSDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		Credentials: credentials,
		TCP:         tcp,
		QUIC:        &v15AuthBackend{session: raw},
		MixUp:       true,
		MixDown:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for seed := uint64(0); ; seed++ {
		if splitmix64(seed^1)&1 != 0 {
			b.cfg.routeSeed = seed
			break
		}
	}
	return b, &tcpDials
}

type failingCountingTCPDialer struct{ calls *atomic.Int32 }

func (d failingCountingTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("unexpected TCP fallback")
}
