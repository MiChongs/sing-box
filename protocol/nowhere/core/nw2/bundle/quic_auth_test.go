package bundle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier"
	nquic "github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func TestBundleCoalescesQUICAuthWithFirstFlow(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeQuicAuthSession{}
	backend := &fakeQuicAuthBackend{session: raw}
	b := newQUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatalf("quicClient: %v", err)
	}
	session, err := quic.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	if backend.acquires != 1 {
		t.Fatalf("backend acquire count = %d, want 1", backend.acquires)
	}
	if raw.prepareCalls != 0 || raw.stream.commits != 0 {
		t.Fatalf("AcquireSession opened/wrote a stream: prepares=%d commits=%d", raw.prepareCalls, raw.stream.commits)
	}

	target, err := wire.NewDomainTarget("first.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	firstFlow, err := (flowSetup{
		header: wire.FlowHeader{
			Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindTCP,
			Uplink: wire.CarrierQUIC, Downlink: wire.CarrierQUIC,
		},
		target: target,
	}).bytes()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	conn, err := prepared.Commit(context.Background(), firstFlow, false)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	defer conn.Close()
	if raw.prepareCalls != 1 || raw.stream.commits != 1 || raw.stream.finishWrite {
		t.Fatalf("first flow commit = (prepares=%d commits=%d finish=%v), want (1, 1, false)", raw.prepareCalls, raw.stream.commits, raw.stream.finishWrite)
	}
	if len(raw.stream.setup) != wire.AuthFrameLen+len(firstFlow) {
		t.Fatalf("coalesced bytes = %d, want %d", len(raw.stream.setup), wire.AuthFrameLen+len(firstFlow))
	}
	if !bytes.Equal(raw.stream.setup[wire.AuthFrameLen:], firstFlow) {
		t.Fatalf("first flow bytes = %x, want %x", raw.stream.setup[wire.AuthFrameLen:], firstFlow)
	}
	id, err := wire.ValidateAuthFrame(raw.stream.setup[:wire.AuthFrameLen], credentials, wire.AuthTransportQUIC, raw.exporter)
	if err != nil {
		t.Fatalf("ValidateAuthFrame: %v", err)
	}
	wantID, err := b.SessionID()
	if err != nil {
		t.Fatal(err)
	}
	if id != wantID {
		t.Fatalf("auth session ID = %x, bundle ID = %x", id, wantID)
	}

	// Reacquiring the same physical connection must not derive or write auth
	// again. The Session ID never leaves the injected backend.
	if _, err := quic.AcquireSession(context.Background()); err != nil {
		t.Fatalf("second AcquireSession: %v", err)
	}
	if raw.stream.commits != 1 {
		t.Fatalf("auth commits after reuse = %d, want 1", raw.stream.commits)
	}
}

func TestQUICFirstStreamGateHonorsContextBeforeAuthenticationCommit(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeQuicAuthSession{}
	backend := &fakeQuicAuthBackend{session: raw}
	b := newQUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatal(err)
	}
	session, err := quic.AcquireSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	waitCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.PrepareStream(waitCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("second PrepareStream error = %v, want context.Canceled", err)
	}
	if raw.prepareCalls != 1 {
		t.Fatalf("raw streams before auth commit = %d, want 1", raw.prepareCalls)
	}

	if _, err := first.Commit(context.Background(), []byte("first-flow"), true); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if _, err := session.PrepareStream(context.Background()); err != nil {
		t.Fatalf("PrepareStream after auth commit: %v", err)
	}
	if raw.prepareCalls != 2 {
		t.Fatalf("raw streams after auth commit = %d, want 2", raw.prepareCalls)
	}
}

func TestQUICAbandonedFirstStreamInvalidatesSession(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeQuicAuthSession{}
	backend := &fakeQuicAuthBackend{session: raw}
	b := newQUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatal(err)
	}
	session, err := quic.AcquireSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close first stream: %v", err)
	}
	if backend.invalidated != raw {
		t.Fatal("abandoned first stream did not invalidate the physical session")
	}
}

func TestBundleInvalidatesQUICSessionWhenExporterFails(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeQuicAuthSession{exporterErr: errors.New("exporter unavailable")}
	backend := &fakeQuicAuthBackend{session: raw}
	b := newQUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatalf("quicClient: %v", err)
	}
	if _, err := quic.AcquireSession(context.Background()); !errors.Is(err, raw.exporterErr) {
		t.Fatalf("AcquireSession error = %v, want exporter error", err)
	}
	if backend.invalidated != raw {
		t.Fatal("failed authentication did not invalidate the physical session")
	}
	if raw.prepareCalls != 0 || raw.stream.commits != 0 {
		t.Fatalf("stream touched despite exporter failure: prepares=%d commits=%d", raw.prepareCalls, raw.stream.commits)
	}
}

func newQUICOnlyBundle(t *testing.T, credentials *wire.Credentials, backend carrier.QuicBackend) *CarrierBundle {
	t.Helper()
	b, err := NewCarrierBundle(BundleOptions{
		Credentials: credentials, QUIC: backend, Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fakeQuicAuthBackend struct {
	session     *fakeQuicAuthSession
	acquires    int
	invalidated carrier.QuicSession
}

func (b *fakeQuicAuthBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	b.acquires++
	return b.session, nil
}
func (b *fakeQuicAuthBackend) InvalidateSession(session carrier.QuicSession) { b.invalidated = session }
func (*fakeQuicAuthBackend) Close() error                                    { return nil }

type fakeQuicAuthSession struct {
	exporter     wire.TLSExporter
	exporterErr  error
	stream       fakeQuicAuthPreparedStream
	prepareCalls int
}

func (s *fakeQuicAuthSession) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return wire.TLSHandshakeInfo{
		TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN, Exporter: s.exporter,
	}, s.exporterErr
}
func (s *fakeQuicAuthSession) PrepareStream(context.Context) (nquic.PreparedStream, error) {
	s.prepareCalls++
	return &s.stream, nil
}
func (*fakeQuicAuthSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*fakeQuicAuthSession) CurrentMaxDatagramSize() int                { return 1200 }
func (*fakeQuicAuthSession) SendDatagram(context.Context, []byte) error { return nil }
func (*fakeQuicAuthSession) LocalAddr() net.Addr                        { return &net.UDPAddr{} }

type fakeQuicAuthPreparedStream struct {
	mu          sync.Mutex
	setup       []byte
	finishWrite bool
	commits     int
	conn        net.Conn
	commitErr   error
}

func (s *fakeQuicAuthPreparedStream) Commit(_ context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	s.mu.Lock()
	s.setup = append(s.setup[:0], setup...)
	s.finishWrite = finishWrite
	s.commits++
	conn := s.conn
	commitErr := s.commitErr
	s.mu.Unlock()
	if commitErr != nil {
		return nil, commitErr
	}
	if conn != nil {
		return conn, nil
	}
	return fakeQuicAuthNetConn{}, nil
}
func (*fakeQuicAuthPreparedStream) Close() error { return nil }

type fakeQuicAuthNetConn struct{}

func (fakeQuicAuthNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeQuicAuthNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeQuicAuthNetConn) Close() error                     { return nil }
func (fakeQuicAuthNetConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (fakeQuicAuthNetConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (fakeQuicAuthNetConn) SetDeadline(time.Time) error      { return nil }
func (fakeQuicAuthNetConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeQuicAuthNetConn) SetWriteDeadline(time.Time) error { return nil }

var _ carrier.QuicBackend = (*fakeQuicAuthBackend)(nil)
var _ carrier.QuicSession = (*fakeQuicAuthSession)(nil)
