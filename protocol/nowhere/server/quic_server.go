//go:build with_quic

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	quicpkg "github.com/sagernet/sing-box/protocol/nowhere/carrier/quic"
	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

var errQUICServerStarted = errors.New("nowhere: QUIC server already started")

type quicServerState uint8

const (
	quicServerIdle quicServerState = iota
	quicServerRunning
	quicServerClosed
)

type quicListenFunc func(net.PacketConn) (qtls.Listener, io.Closer, error)

type quicServerRun struct {
	ctx        context.Context
	cancel     context.CancelFunc
	packetConn net.PacketConn
	listener   qtls.Listener
	transport  io.Closer
	done       chan struct{}
	serveWG    sync.WaitGroup
	stopOnce   sync.Once
	stopErr    error
}

func (r *quicServerRun) stop() error {
	if r == nil {
		return nil
	}
	r.stopOnce.Do(func() {
		r.cancel()
		r.stopErr = WithoutErrClosed(E.Errors(r.listener.Close(), r.transport.Close(), r.packetConn.Close()))
	})
	<-r.done
	r.serveWG.Wait()
	return r.stopErr
}

// QUICServer accepts Nowhere QUIC connections and feeds them to the nw2 core Handler.
type QUICServer struct {
	Handler *Handler
	TLS     tls.ServerConfig

	ctx               context.Context
	quicOptions       option.QUICOptions
	congestionControl quicsettings.CongestionControl
	observer          diagnostic.Observer

	mu       sync.Mutex
	state    quicServerState
	current  *quicServerRun
	listenFn quicListenFunc
}

func NewQUICServer(
	ctx context.Context,
	handler *Handler,
	tlsConfig tls.ServerConfig,
	quicOptions option.QUICOptions,
	congestionControl quicsettings.CongestionControl,
	observer diagnostic.Observer,
) *QUICServer {
	server := &QUICServer{
		Handler:           handler,
		TLS:               tlsConfig,
		ctx:               ctx,
		quicOptions:       quicOptions,
		congestionControl: congestionControl,
		observer:          observer,
	}
	server.listenFn = server.listen
	return server
}

func (s *QUICServer) listen(packetConn net.PacketConn) (qtls.Listener, io.Closer, error) {
	tlsConfig, err := s.TLS.STDConfig()
	if err != nil {
		return nil, nil, err
	}
	transport := &quic.Transport{
		Conn:                packetConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	// The transport is built here instead of through qtls, so apply the
	// listener's udp_gso policy the same way qtls.Listen does.
	quicConfig := qtls.ConfigWithGSO(quicpkg.BuildQUICServerConfig(s.quicOptions), packetConn)
	listener, err := transport.Listen(tlsConfig, quicConfig)
	return listener, transport, err
}

// Start transfers ownership of packetConn to the server. It only succeeds
// while the server is idle.
func (s *QUICServer) Start(packetConn net.PacketConn) error {
	if s == nil {
		if packetConn != nil {
			_ = packetConn.Close()
		}
		return net.ErrClosed
	}
	if packetConn == nil {
		return E.New("nowhere: nil QUIC packet connection")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked(packetConn)
}

func (s *QUICServer) startLocked(packetConn net.PacketConn) error {
	switch s.state {
	case quicServerClosed:
		_ = packetConn.Close()
		return net.ErrClosed
	case quicServerRunning:
		_ = packetConn.Close()
		return errQUICServerStarted
	}
	listener, transport, err := s.listenFn(packetConn)
	if err != nil {
		if transport != nil {
			_ = transport.Close()
		}
		_ = packetConn.Close()
		return err
	}
	if listener == nil || transport == nil {
		if transport != nil {
			_ = transport.Close()
		}
		_ = packetConn.Close()
		return E.New("nowhere: incomplete QUIC listener runtime")
	}
	baseCtx := s.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(baseCtx)
	run := &quicServerRun{
		ctx: ctx, cancel: cancel, packetConn: packetConn, listener: listener, transport: transport, done: make(chan struct{}),
	}
	s.current = run
	s.state = quicServerRunning
	go s.acceptLoop(run)
	return nil
}

// Restart stops the active runtime before invoking listenPacket, ensuring the
// previous socket is released before the same address is rebound.
func (s *QUICServer) Restart(listenPacket func() (net.PacketConn, error)) error {
	if s == nil {
		return net.ErrClosed
	}
	if listenPacket == nil {
		return E.New("nowhere: nil QUIC packet listener")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == quicServerClosed {
		return net.ErrClosed
	}
	previous := s.current
	s.current = nil
	s.state = quicServerIdle
	if err := previous.stop(); err != nil {
		diagnostic.Emit(s.ctx, s.observer, diagnostic.Event{
			Level: diagnostic.LevelWarn, Code: "quic_stop_failed", Component: "sing-box-quic", Err: err,
		})
	}
	packetConn, err := listenPacket()
	if err != nil {
		return err
	}
	return s.startLocked(packetConn)
}

func (s *QUICServer) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == quicServerClosed {
		return nil
	}
	s.state = quicServerClosed
	current := s.current
	s.current = nil
	return current.stop()
}

func (s *QUICServer) acceptLoop(run *quicServerRun) {
	defer func() {
		close(run.done)
		// The runtime is dead; release its sockets so the server can be
		// restarted without requiring Restart/Close. If the caller already
		// replaced or closed the runtime, leave its state alone.
		run.stop()
		s.mu.Lock()
		if s.state == quicServerRunning && s.current == run {
			s.state = quicServerIdle
			s.current = nil
		}
		s.mu.Unlock()
	}()
	for {
		conn, err := run.listener.Accept(run.ctx)
		if err != nil {
			if run.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				diagnostic.Emit(run.ctx, s.observer, diagnostic.Event{
					Level: diagnostic.LevelError, Code: "quic_accept_failed", Component: "sing-box-quic", Err: err,
				})
			}
			return
		}
		conn.SetCongestionControl(quicpkg.NewCongestionController(run.ctx, conn, s.congestionControl))
		run.serveWG.Add(1)
		go func() {
			defer run.serveWG.Done()
			err := s.Handler.ServeQUIC(run.ctx, adaptQuicConn(conn))
			if err != nil && run.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				diagnostic.Emit(run.ctx, s.observer, diagnostic.Event{
					Level: diagnostic.LevelError, Code: "quic_serve_failed", Component: "sing-box-quic",
					Source: conn.RemoteAddr(), Err: err,
				})
			}
		}()
	}
}

// --- quic-go → nw2 core QuicConn / QuicStream adapters ---

const defaultMaxDatagramSize = 1200

type quicConnection interface {
	AcceptStream(context.Context) (*quic.Stream, error)
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CloseWithError(quic.ApplicationErrorCode, string) error
	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ConnectionState() quic.ConnectionState
}

// quicStreamGate holds subsequent raw AcceptStream calls until the adapter is
// notified that authentication succeeded. The first stream is always delivered
// for authentication. This is a hold, rather than a reset: Nowhere clients may
// open their first flow immediately after sending Auth, before the server can
// make authentication observable to the client.
type quicStreamGate struct {
	authenticated chan struct{}
	once          sync.Once
}

func newQUICStreamGate() *quicStreamGate {
	return &quicStreamGate{authenticated: make(chan struct{})}
}

func (g *quicStreamGate) markAuthenticated() {
	g.once.Do(func() { close(g.authenticated) })
}

func (g *quicStreamGate) wait(ctx context.Context) error {
	select {
	case <-g.authenticated:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type quicStreamResult struct {
	stream *quic.Stream
}

type quicConnAdapter struct {
	conn quicConnection

	handshakeInfo func() (wire.TLSHandshakeInfo, error)
	sendDatagram  func(context.Context, []byte) error

	maxDatagramMu   sync.Mutex
	maxDatagramSize int

	streamGate     *quicStreamGate
	streamCh       chan quicStreamResult
	streamDone     chan struct{}
	streamDoneOnce sync.Once
	streamErrMu    sync.Mutex
	streamErr      error
}

func adaptQuicConn(conn *quic.Conn) nwserver.QuicConn {
	adapter := &quicConnAdapter{
		conn:            conn,
		maxDatagramSize: defaultMaxDatagramSize,
		streamGate:      newQUICStreamGate(),
		streamCh:        make(chan quicStreamResult, 1),
		streamDone:      make(chan struct{}),
	}
	go adapter.pumpStreams()
	return adapter
}

func (c *quicConnAdapter) AcceptStream(ctx context.Context) (nwserver.QuicStream, error) {
	// Prefer a buffered stream even if the raw QUIC accept loop has already
	// observed a later terminal error.
	select {
	case result := <-c.streamCh:
		return &quicStreamAdapter{Stream: result.stream}, nil
	default:
	}
	select {
	case result := <-c.streamCh:
		return &quicStreamAdapter{Stream: result.stream}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.streamDone:
		return nil, c.streamPumpError()
	}
}

// MarkAuthenticated implements the nw2 core's optional
// QuicAuthenticationNotifier. It is called only after the session has been
// registered and the datagram pump activated.
func (c *quicConnAdapter) MarkAuthenticated() {
	c.streamGate.markAuthenticated()
}

// SetMaxIncomingStreamLimits is a compatibility bridge for the released
// legacy interface. It intentionally does not call into quic-go: the server
// already advertises its configured admission limit and the adapter enforces
// the pre-auth restriction above. The current core calls MarkAuthenticated
// directly after session registration instead.
func (c *quicConnAdapter) SetMaxIncomingStreamLimits(int64, int64) error {
	c.MarkAuthenticated()
	return nil
}

func (c *quicConnAdapter) pumpStreams() {
	var terminalErr error
	firstStream := true
	defer func() {
		c.streamErrMu.Lock()
		c.streamErr = terminalErr
		c.streamErrMu.Unlock()
		c.streamDoneOnce.Do(func() { close(c.streamDone) })
	}()
	for {
		if !firstStream && c.streamGate != nil {
			if err := c.streamGate.wait(c.conn.Context()); err != nil {
				terminalErr = err
				return
			}
		}
		stream, err := c.conn.AcceptStream(c.conn.Context())
		if err != nil {
			terminalErr = err
			return
		}
		select {
		case c.streamCh <- quicStreamResult{stream: stream}:
		case <-c.conn.Context().Done():
			terminalErr = c.conn.Context().Err()
			return
		}
		firstStream = false
	}
}

func (c *quicConnAdapter) streamPumpError() error {
	c.streamErrMu.Lock()
	err := c.streamErr
	c.streamErrMu.Unlock()
	if err == nil {
		return net.ErrClosed
	}
	return err
}

func (c *quicConnAdapter) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	if c.handshakeInfo != nil {
		return c.handshakeInfo()
	}
	state := c.conn.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(
		wire.TLSExporterLabel,
		wire.EmptyTLSExporterContext(),
		wire.TLSExporterLen,
	)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	if len(material) != wire.TLSExporterLen {
		return wire.TLSHandshakeInfo{}, E.New("nowhere: invalid QUIC TLS exporter length")
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion: state.TLS.Version, NegotiatedALPN: state.TLS.NegotiatedProtocol, Exporter: exporter,
	}, nil
}

func (c *quicConnAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *quicConnAdapter) CurrentMaxDatagramSize() int {
	c.maxDatagramMu.Lock()
	defer c.maxDatagramMu.Unlock()
	return c.maxDatagramSize
}

func (c *quicConnAdapter) SendDatagram(ctx context.Context, b []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := c.conn.Context().Err(); err != nil {
		return err
	}
	var err error
	if c.sendDatagram != nil {
		err = c.sendDatagram(ctx, b)
	} else {
		err = c.conn.SendDatagram(b)
	}
	if err == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return c.conn.Context().Err()
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		if tooLarge.MaxDatagramPayloadSize > 0 {
			c.maxDatagramMu.Lock()
			c.maxDatagramSize = int(tooLarge.MaxDatagramPayloadSize)
			c.maxDatagramMu.Unlock()
		}
		return &nwquic.DatagramTooLargeError{
			MaxDatagramSize: c.CurrentMaxDatagramSize(),
			Cause:           err,
		}
	}
	return err
}

func (c *quicConnAdapter) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *quicConnAdapter) Close() error {
	return c.conn.CloseWithError(0, "")
}

func (c *quicConnAdapter) Context() context.Context {
	return c.conn.Context()
}

func (c *quicConnAdapter) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *quicConnAdapter) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

type quicStreamAdapter struct {
	*quic.Stream
	once sync.Once
}

func (s *quicStreamAdapter) CancelRead(code uint64) {
	s.Stream.CancelRead(quic.StreamErrorCode(code))
}

func (s *quicStreamAdapter) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

func (s *quicStreamAdapter) Close() error {
	var err error
	s.once.Do(func() {
		err = s.Stream.Close()
	})
	return err
}

var (
	_ nwserver.QuicConn   = (*quicConnAdapter)(nil)
	_ nwserver.QuicStream = (*quicStreamAdapter)(nil)
)
