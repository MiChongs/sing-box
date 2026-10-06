package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestOpenAPIsEncodePortalHops(t *testing.T) {
	target, err := wire.NewDomainTarget("hops.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		kind wire.FlowKind
		hops uint8
		open func(*CarrierBundle) error
	}{
		{
			name: "OpenTCP defaults to zero", kind: wire.FlowKindTCP,
			open: func(b *CarrierBundle) error {
				conn, err := b.OpenTCP(context.Background(), target)
				if conn != nil {
					_ = conn.Close()
				}
				return err
			},
		},
		{
			name: "OpenTCPWithPayload defaults to zero", kind: wire.FlowKindTCP,
			open: func(b *CarrierBundle) error {
				conn, err := b.OpenTCPWithPayload(context.Background(), target, nil)
				if conn != nil {
					_ = conn.Close()
				}
				return err
			},
		},
		{
			name: "OpenTCPWithHops uses explicit budget", kind: wire.FlowKindTCP, hops: 5,
			open: func(b *CarrierBundle) error {
				conn, err := b.OpenTCPWithHops(context.Background(), target, 5)
				if conn != nil {
					_ = conn.Close()
				}
				return err
			},
		},
		{
			name: "OpenUDP defaults to zero", kind: wire.FlowKindUDP,
			open: func(b *CarrierBundle) error {
				pc, err := b.OpenUDP(context.Background(), target)
				if pc != nil {
					_ = pc.Close()
				}
				return err
			},
		},
		{
			name: "OpenUDPWithHops uses explicit budget", kind: wire.FlowKindUDP, hops: 6,
			open: func(b *CarrierBundle) error {
				pc, err := b.OpenUDPWithHops(context.Background(), target, 6)
				if pc != nil {
					_ = pc.Close()
				}
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credentials, err := wire.NewCredentials("secret")
			if err != nil {
				t.Fatal(err)
			}
			raw := &v15AuthSession{}
			raw.stream.conn = &readyRecordingConn{}
			b := newV15QUICOnlyBundle(t, credentials, &v15AuthBackend{session: raw})
			defer b.Close()

			if err := test.open(b); err != nil {
				t.Fatalf("open flow: %v", err)
			}
			setup := raw.stream.setup
			if len(setup) < wire.AuthFrameLen+wire.FlowHeaderLen {
				t.Fatalf("setup length=%d", len(setup))
			}
			header, err := wire.DecodeFlowHeader(setup[wire.AuthFrameLen : wire.AuthFrameLen+wire.FlowHeaderLen])
			if err != nil {
				t.Fatalf("decode FLOW: %v", err)
			}
			if header.Kind != test.kind || header.Hops != test.hops {
				t.Fatalf("header=(kind=%v hops=%d), want (kind=%v hops=%d)", header.Kind, header.Hops, test.kind, test.hops)
			}
		})
	}
}

func TestOpenUDPAsyncEncodesZeroPortalHops(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &v15AuthSession{}
	raw.stream.conn = &readyRecordingConn{}
	b := newV15QUICOnlyBundle(t, credentials, &v15AuthBackend{session: raw})
	defer b.Close()
	target, err := wire.NewDomainTarget("async.example", 53)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := b.OpenUDPAsync(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if err := waitForAsyncUDPReady(pc); err != nil {
		t.Fatal(err)
	}
	setup := raw.stream.setup
	if len(setup) < wire.AuthFrameLen+wire.FlowHeaderLen {
		t.Fatalf("setup length=%d", len(setup))
	}
	header, err := wire.DecodeFlowHeader(setup[wire.AuthFrameLen : wire.AuthFrameLen+wire.FlowHeaderLen])
	if err != nil {
		t.Fatal(err)
	}
	if header.Hops != 0 {
		t.Fatalf("OpenUDPAsync HOPS=%d want=0", header.Hops)
	}
}

func waitForAsyncUDPReady(pc net.PacketConn) error {
	async, ok := pc.(*asyncUDPConn)
	if !ok {
		return errors.New("unexpected async UDP connection type")
	}
	<-async.ready
	async.mu.Lock()
	defer async.mu.Unlock()
	return async.setupErr
}

func TestSplitFlowHeadersUseSamePortalHops(t *testing.T) {
	for _, kind := range []wire.FlowKind{wire.FlowKindTCP, wire.FlowKindUDP} {
		for _, carriers := range [][2]wire.Carrier{
			{wire.CarrierTLSTCP, wire.CarrierQUIC},
			{wire.CarrierQUIC, wire.CarrierTLSTCP},
		} {
			open, attach := newSplitFlowHeaders(42, kind, carriers[0], carriers[1], 4)
			if open.Role != wire.FlowRoleOpen || attach.Role != wire.FlowRoleAttach {
				t.Fatalf("roles=(%v,%v)", open.Role, attach.Role)
			}
			if open.Hops != 4 || attach.Hops != 4 {
				t.Fatalf("kind=%v carriers=%v HOPS=(%d,%d)", kind, carriers, open.Hops, attach.Hops)
			}
		}
	}
}

func TestOpenWithHopsWritesEveryCarrierHalf(t *testing.T) {
	for _, kind := range []wire.FlowKind{wire.FlowKindTCP, wire.FlowKindUDP} {
		for _, carriers := range [][2]wire.Carrier{
			{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
			{wire.CarrierQUIC, wire.CarrierQUIC},
			{wire.CarrierTLSTCP, wire.CarrierQUIC},
			{wire.CarrierQUIC, wire.CarrierTLSTCP},
		} {
			kind, carriers := kind, carriers
			name := kindName(kind) + "/" + carrierName(carriers[0]) + "-" + carrierName(carriers[1])
			t.Run(name, func(t *testing.T) {
				credentials, err := wire.NewCredentials("secret")
				if err != nil {
					t.Fatal(err)
				}
				dialer := &matrixTCPDialer{headers: make(chan matrixTCPHeader, 1)}
				var tcpConfig *tcptls.Config
				if carriers[0] == wire.CarrierTLSTCP || carriers[1] == wire.CarrierTLSTCP {
					tcpConfig, err = tcptls.NewConfig(tcptls.TCPOptions{
						Address: "portal.example:443", Dialer: dialer, TLSDialer: matrixTLSDialer{},
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				var raw *v15AuthSession
				var quicBackend *v15AuthBackend
				if carriers[0] == wire.CarrierQUIC || carriers[1] == wire.CarrierQUIC {
					raw = &v15AuthSession{}
					raw.stream.conn = &readyRecordingConn{}
					quicBackend = &v15AuthBackend{session: raw}
				}
				b, err := NewCarrierBundle(BundleOptions{
					TCP: tcpConfig, QUIC: quicBackend, Credentials: credentials,
					Up: carriers[0], Down: carriers[1],
				})
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				target, err := wire.NewDomainTarget("matrix.example", 443)
				if err != nil {
					t.Fatal(err)
				}
				if kind == wire.FlowKindTCP {
					conn, err := b.OpenTCPWithHops(context.Background(), target, 5)
					if err != nil {
						t.Fatalf("OpenTCPWithHops: %v", err)
					}
					_ = conn.Close()
				} else {
					pc, err := b.OpenUDPWithHops(context.Background(), target, 5)
					if err != nil {
						t.Fatalf("OpenUDPWithHops: %v", err)
					}
					_ = pc.Close()
				}

				var headers []wire.FlowHeader
				if tcpConfig != nil {
					select {
					case event := <-dialer.headers:
						if event.err != nil {
							t.Fatalf("read TCP FLOW: %v", event.err)
						}
						headers = append(headers, event.header)
					case <-time.After(time.Second):
						t.Fatal("TCP FLOW was not observed")
					}
				}
				if raw != nil {
					setup := raw.stream.setup
					if len(setup) < wire.AuthFrameLen+wire.FlowHeaderLen {
						t.Fatalf("QUIC setup length=%d", len(setup))
					}
					header, err := wire.DecodeFlowHeader(setup[wire.AuthFrameLen : wire.AuthFrameLen+wire.FlowHeaderLen])
					if err != nil {
						t.Fatalf("read QUIC FLOW: %v", err)
					}
					headers = append(headers, header)
				}
				wantHeaders := 1
				if carriers[0] != carriers[1] {
					wantHeaders = 2
				}
				if len(headers) != wantHeaders {
					t.Fatalf("FLOW halves=%d want=%d", len(headers), wantHeaders)
				}
				for _, header := range headers {
					if header.Kind != kind || header.Hops != 5 || header.Uplink != carriers[0] || header.Downlink != carriers[1] {
						t.Fatalf("FLOW=%+v", header)
					}
				}
			})
		}
	}
}

func TestOpenWithHopsRejectsOutOfRangeBudget(t *testing.T) {
	b := &CarrierBundle{}
	target, err := wire.NewDomainTarget("invalid.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.OpenTCPWithHops(context.Background(), target, wire.MaxPortalHops+1); err == nil {
		t.Fatal("OpenTCPWithHops accepted HOPS=8")
	}
	if _, err := b.OpenUDPWithHops(context.Background(), target, wire.MaxPortalHops+1); err == nil {
		t.Fatal("OpenUDPWithHops accepted HOPS=8")
	}
}

func TestSetupResultErrorExposesStableCode(t *testing.T) {
	err := &SetupResultError{Code: wire.SetupResultMetadataConflict}
	if got := err.SetupResultCode(); got != wire.SetupResultMetadataConflict {
		t.Fatalf("SetupResultCode=%v want=%v", got, wire.SetupResultMetadataConflict)
	}
}

type matrixTCPHeader struct {
	header wire.FlowHeader
	err    error
}

type matrixTCPDialer struct {
	headers chan matrixTCPHeader
}

func (d *matrixTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, portal := net.Pipe()
	go func() {
		defer portal.Close()
		var auth [wire.AuthFrameLen]byte
		if _, err := io.ReadFull(portal, auth[:]); err != nil {
			d.headers <- matrixTCPHeader{err: err}
			return
		}
		header, err := wire.ReadFlowHeader(portal)
		if err == nil && header.CarriesTarget() {
			_, err = wire.ReadTarget(portal)
		}
		d.headers <- matrixTCPHeader{header: header, err: err}
		if err != nil {
			return
		}
		selectedTCP := header.Downlink == wire.CarrierTLSTCP &&
			(header.Role == wire.FlowRoleDuplex || header.Role == wire.FlowRoleAttach)
		if selectedTCP {
			if err := wire.WriteSetupResult(portal, wire.SetupResultReady); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, portal)
	}()
	return client, nil
}

type matrixTLSDialer struct{}

func (matrixTLSDialer) DialTLSConn(_ context.Context, conn net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: wire.TLSHandshakeInfo{
			TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN,
		},
	}, nil
}

func kindName(kind wire.FlowKind) string {
	if kind == wire.FlowKindUDP {
		return "udp"
	}
	return "tcp"
}

func carrierName(carrier wire.Carrier) string {
	if carrier == wire.CarrierQUIC {
		return "quic"
	}
	return "tcp"
}
