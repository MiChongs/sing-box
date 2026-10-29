package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier"
	carrierquic "github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func TestResolvedRouteCommitsUDPDataPaths(t *testing.T) {
	T, Q := wire.CarrierTLSTCP, wire.CarrierQUIC
	cases := []struct {
		name  string
		route resolvedRoute
	}{
		{"tcp_tcp", resolvedRoute{T, T}},
		{"tcp_udp", resolvedRoute{T, Q}},
		{"udp_tcp", resolvedRoute{Q, T}},
		{"udp_udp", resolvedRoute{Q, Q}},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.route.label(), func(t *testing.T) {
			testCommittedRoute(t, tc.route)
		})
	}
}

func TestPolicyMatrixOpensThroughBundle(t *testing.T) {
	cases := []struct {
		name     string
		up, down CarrierMode
	}{
		{"tcp_tcp", ModeTCP, ModeTCP},
		{"tcp_udp", ModeTCP, ModeUDP},
		{"udp_tcp", ModeUDP, ModeTCP},
		{"udp_udp", ModeUDP, ModeUDP},
	}
	for _, tc := range cases {
		for _, kind := range []wire.FlowKind{wire.FlowKindTCP, wire.FlowKindUDP} {
			kindName := "tcp"
			if kind == wire.FlowKindUDP {
				kindName = "udp"
			}
			t.Run(fmt.Sprintf("%s/%s", tc.name, kindName), func(t *testing.T) {
				testBundleOpen(t, tc.up, tc.down, kind)
			})
		}
	}
}

func testBundleOpen(t *testing.T, upMode, downMode CarrierMode, kind wire.FlowKind) {
	t.Helper()
	h := newOpenMatrixHarness()
	credentials, err := wire.NewCredentials("matrix-secret")
	if err != nil {
		t.Fatal(err)
	}
	tcpConfig, err := tcptlsConfigForMatrix(h)
	if err != nil {
		t.Fatal(err)
	}
	up, down := upMode.Selectors(), downMode.Selectors()
	backend := &matrixBackend{session: h.raw}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: tcpConfig, QUIC: backend, Credentials: credentials,
		Up: up, Down: down,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	target, err := wire.NewDomainTarget("bundle-matrix.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if kind == wire.FlowKindTCP {
		conn, err := b.OpenTCP(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("open")); err != nil {
			t.Fatal(err)
		}
		var echo [4]byte
		if _, err := io.ReadFull(conn, echo[:]); err != nil {
			t.Fatal(err)
		}
		if string(echo[:]) != "open" {
			t.Fatalf("echo = %q", echo[:])
		}
	} else {
		packet, err := b.OpenUDP(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		if _, err := packet.WriteTo([]byte("open"), nil); err != nil {
			t.Fatal(err)
		}
		var echo [4]byte
		n, _, err := packet.ReadFrom(echo[:])
		if err != nil {
			t.Fatal(err)
		}
		if string(echo[:n]) != "open" {
			t.Fatalf("echo = %q", echo[:n])
		}
	}
	want := resolvedRoute{uplink: up, downlink: down}
	wantHeaders := 1
	if want.split() {
		wantHeaders = 2
	}
	for i := 0; i < wantHeaders; i++ {
		select {
		case header := <-h.headers:
			if header.Uplink != want.uplink || header.Downlink != want.downlink || header.Kind != kind {
				t.Fatalf("header = %+v, want route=%s kind=%d", header, want.label(), kind)
			}
		case err := <-h.errs:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	h.assertNoError(t)
}

func testCommittedRoute(t *testing.T, route resolvedRoute) {
	t.Helper()
	h := newMatrixHarness(t)
	const flowID wire.FlowID = 7
	lanes, err := h.prepare(route, flowID, wire.FlowKindUDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lanes.Close() })
	target, err := wire.NewDomainTarget("matrix.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	b := &CarrierBundle{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	packet, err := b.commitUDPRoute(ctx, lanes, route, flowID, target, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if _, err := packet.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	n, _, err := packet.ReadFrom(echo[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(echo[:n]) != "ping" {
		t.Fatalf("echo = %q", echo[:n])
	}

	wantHeaders := 1
	if route.split() {
		wantHeaders = 2
	}
	seen := make([]wire.FlowHeader, 0, wantHeaders)
	for len(seen) < wantHeaders {
		select {
		case header := <-h.headers:
			seen = append(seen, header)
		case err := <-h.errs:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatalf("headers = %+v: %v", seen, ctx.Err())
		}
	}
	for _, header := range seen {
		if header.FlowID != flowID || header.Kind != wire.FlowKindUDP ||
			header.Uplink != route.uplink || header.Downlink != route.downlink {
			t.Fatalf("header = %+v route=%s", header, route.label())
		}
		if route.split() && header.Role == wire.FlowRoleDuplex {
			t.Fatalf("split route emitted DUPLEX: %+v", header)
		}
		if !route.split() && header.Role != wire.FlowRoleDuplex {
			t.Fatalf("symmetric route emitted role %d", header.Role)
		}
	}
	h.assertNoError(t)
}

type matrixHarness struct {
	mu      sync.Mutex
	flows   map[wire.FlowID]*matrixFlow
	headers chan wire.FlowHeader
	errs    chan error
	raw     *muxLifecycleSession
	session *quicSessionMux
}

type matrixFlow struct {
	header  wire.FlowHeader
	open    net.Conn
	attach  net.Conn
	duplex  net.Conn
	started bool
}

func newMatrixHarness(t *testing.T) *matrixHarness {
	t.Helper()
	h := &matrixHarness{
		flows:   make(map[wire.FlowID]*matrixFlow),
		headers: make(chan wire.FlowHeader, 4),
		errs:    make(chan error, 8),
	}
	h.raw = &muxLifecycleSession{receive: make(chan []byte, 16)}
	h.raw.send = h.sendDatagram
	backend := &quicMuxBackend{
		backend:          &muxLifecycleBackend{},
		maxUDPQueueBytes: 1 << 20,
		maxPendingCloses: 64,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}
	session, err := newQUICSessionMux(backend, h.raw, wire.AuthFrame{1})
	if err != nil {
		t.Fatal(err)
	}
	h.session = session
	backend.sessions[h.raw] = session
	t.Cleanup(func() {
		session.close(net.ErrClosed)
		<-session.sendLoopDone
	})
	return h
}

func newOpenMatrixHarness() *matrixHarness {
	h := &matrixHarness{
		flows:   make(map[wire.FlowID]*matrixFlow),
		headers: make(chan wire.FlowHeader, 4),
		errs:    make(chan error, 8),
	}
	h.raw = &muxLifecycleSession{
		receive: make(chan []byte, 16),
		fail:    make(chan struct{}),
	}
	h.raw.send = h.sendDatagram
	var prepares atomic.Int32
	h.raw.prepare = func(context.Context) (carrier.QuicPreparedStream, error) {
		skip := 0
		if prepares.Add(1) == 1 {
			skip = wire.AuthFrameLen
		}
		return &matrixPreparedStream{harness: h, skip: skip}, nil
	}
	return h
}

func tcptlsConfigForMatrix(h *matrixHarness) (*tcptls.Config, error) {
	return tcptls.NewConfig(tcptls.TCPOptions{
		Address:   "matrix.invalid:443",
		Dialer:    harnessTCPDialer{harness: h},
		TLSDialer: harnessTLSDialer{},
	})
}

func (h *matrixHarness) prepare(route resolvedRoute, flowID wire.FlowID, kind wire.FlowKind) (*preparedLanes, error) {
	up := h.lane(route.uplink, flowID)
	lanes := &preparedLanes{up: up, split: route.split()}
	if route.split() {
		lanes.down = h.lane(route.downlink, flowID)
	}
	if err := lanes.prepareUDPDownlink(kind, route, flowID); err != nil {
		_ = lanes.Close()
		return nil, err
	}
	return lanes, nil
}

func (h *matrixHarness) lane(selected wire.Carrier, flowID wire.FlowID) *physicalLane {
	if selected == wire.CarrierQUIC {
		return &physicalLane{
			carrier: selected,
			quic: &quicPreparedStream{
				session: h.session,
				stream:  &matrixPreparedStream{harness: h},
				id:      flowID,
			},
		}
	}
	client, peer := net.Pipe()
	go h.readSetup(peer)
	return &physicalLane{carrier: selected, mux: client}
}

func (h *matrixHarness) readSetup(peer net.Conn) {
	header, err := wire.ReadFlowHeader(peer)
	if err != nil {
		h.report(err)
		_ = peer.Close()
		return
	}
	if header.CarriesTarget() {
		if _, err := wire.ReadTarget(peer); err != nil {
			h.report(err)
			_ = peer.Close()
			return
		}
	}
	h.register(header, peer)
}

func (h *matrixHarness) register(header wire.FlowHeader, peer net.Conn) {
	h.headers <- header
	h.mu.Lock()
	flow := h.flows[header.FlowID]
	if flow == nil {
		flow = &matrixFlow{header: header}
		h.flows[header.FlowID] = flow
	}
	switch header.Role {
	case wire.FlowRoleDuplex:
		flow.duplex = peer
	case wire.FlowRoleOpen:
		flow.open = peer
	case wire.FlowRoleAttach:
		flow.attach = peer
	}
	ready := !flow.started && (flow.duplex != nil || flow.open != nil && flow.attach != nil)
	if ready {
		flow.started = true
	}
	h.mu.Unlock()
	if ready {
		go h.serve(flow)
	}
}

func (h *matrixHarness) serve(flow *matrixFlow) {
	down := flow.duplex
	if down == nil {
		down = flow.attach
	}
	if err := wire.WriteSetupResult(down, wire.SetupResultReady); err != nil {
		h.report(err)
		return
	}
	if flow.header.Kind == wire.FlowKindTCP {
		if flow.duplex != nil {
			_, _ = io.Copy(flow.duplex, flow.duplex)
		} else {
			_, _ = io.Copy(flow.attach, flow.open)
		}
		return
	}
	switch {
	case flow.header.Uplink == wire.CarrierTLSTCP && flow.header.Downlink == wire.CarrierTLSTCP:
		h.echoUOT(flow.duplex, func(payload []byte) error { return wire.WriteUDPPacket(flow.duplex, payload) })
	case flow.header.Uplink == wire.CarrierTLSTCP && flow.header.Downlink == wire.CarrierQUIC:
		h.echoUOT(flow.open, func(payload []byte) error {
			frame, err := wire.EncodeUDPData(flow.header.FlowID, payload)
			if err == nil {
				h.raw.receive <- frame
			}
			return err
		})
	}
}

func (h *matrixHarness) echoUOT(conn net.Conn, echo func([]byte) error) {
	for {
		payload, err := wire.ReadUDPPacket(conn)
		if err != nil || payload == nil {
			return
		}
		if err := echo(payload); err != nil {
			h.report(err)
			return
		}
	}
}

func (h *matrixHarness) sendDatagram(encoded []byte) error {
	frame, err := wire.DecodeUDPFrame(encoded)
	if err != nil {
		return err
	}
	if frame.Type != wire.UDPFrameTypeData {
		return nil
	}
	h.mu.Lock()
	flow := h.flows[frame.FlowID]
	h.mu.Unlock()
	if flow == nil {
		return errors.New("matrix: datagram for unknown flow")
	}
	if flow.header.Downlink == wire.CarrierQUIC {
		copyFrame := append([]byte(nil), encoded...)
		h.raw.receive <- copyFrame
		return nil
	}
	if flow.attach == nil {
		return errors.New("matrix: TCP downlink is unavailable")
	}
	payload := append([]byte(nil), frame.Payload...)
	go func() {
		if err := wire.WriteUDPPacket(flow.attach, payload); err != nil {
			h.report(err)
		}
	}()
	return nil
}

func (h *matrixHarness) report(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return
	}
	select {
	case h.errs <- err:
	default:
	}
}

func (h *matrixHarness) assertNoError(t *testing.T) {
	t.Helper()
	select {
	case err := <-h.errs:
		t.Fatal(err)
	default:
	}
}

type matrixPreparedStream struct {
	harness *matrixHarness
	skip    int
	once    sync.Once
	client  net.Conn
	peer    net.Conn
}

func (s *matrixPreparedStream) Commit(_ context.Context, setup []byte, _ bool) (net.Conn, error) {
	committed := false
	s.once.Do(func() {
		committed = true
		s.client, s.peer = net.Pipe()
		go func() {
			if len(setup) < s.skip {
				s.harness.report(io.ErrUnexpectedEOF)
				_ = s.peer.Close()
				return
			}
			payload := setup[s.skip:]
			header, err := wire.ReadFlowHeader(newSliceReader(payload))
			if err != nil {
				s.harness.report(err)
				_ = s.peer.Close()
				return
			}
			reader := newSliceReader(payload[wire.FlowHeaderLen:])
			if header.CarriesTarget() {
				if _, err := wire.ReadTarget(reader); err != nil {
					s.harness.report(err)
					_ = s.peer.Close()
					return
				}
			}
			s.harness.register(header, s.peer)
		}()
	})
	if !committed || s.client == nil {
		return nil, net.ErrClosed
	}
	return s.client, nil
}

func (s *matrixPreparedStream) Close() error {
	var err error
	s.once.Do(func() {})
	if s.client != nil {
		err = s.client.Close()
	}
	if s.peer != nil {
		err = errors.Join(err, s.peer.Close())
	}
	return err
}

type sliceReader struct {
	data []byte
	off  int
}

func newSliceReader(data []byte) *sliceReader { return &sliceReader{data: data} }

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

var _ carrierquic.PreparedStream = (*matrixPreparedStream)(nil)

type harnessTCPDialer struct{ harness *matrixHarness }

func (d harnessTCPDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	client, peer := net.Pipe()
	go func() {
		var auth [wire.AuthFrameLen]byte
		if _, err := io.ReadFull(peer, auth[:]); err != nil {
			d.harness.report(err)
			_ = peer.Close()
			return
		}
		d.harness.readSetup(peer)
	}()
	return client, nil
}

type harnessTLSDialer struct{}

func (harnessTLSDialer) DialTLSConn(_ context.Context, conn net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: wire.TLSHandshakeInfo{
			TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN,
		},
	}, nil
}

type matrixBackend struct {
	session *muxLifecycleSession
	once    sync.Once
}

func (b *matrixBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.session.fail:
		return nil, net.ErrClosed
	default:
		return b.session, nil
	}
}

func (b *matrixBackend) InvalidateSession(carrier.QuicSession) { b.close() }
func (b *matrixBackend) Close() error                          { b.close(); return nil }
func (b *matrixBackend) close() {
	b.once.Do(func() { close(b.session.fail) })
}

var _ carrier.QuicBackend = (*matrixBackend)(nil)
