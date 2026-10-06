//go:build with_quic

package quic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
)

const defaultMaxDatagramSize = 1200

// Session is one handshaked QUIC connection exposing only transport primitives.
type Session struct {
	cfg *QUICConfig

	conn       *quic.Conn
	rawConn    net.Conn
	openStream func(context.Context) (stream, error)
	cancel     context.CancelFunc
	closed     bool

	receiveDatagram func(context.Context) ([]byte, error)
	sendDatagram    func(context.Context, []byte) error
	localAddr       func() net.Addr
	handshakeInfo   func() (wire.TLSHandshakeInfo, error)
	lifetimeDone    chan struct{}

	mu              sync.Mutex
	dialStarted     bool
	ready           chan struct{}
	readyErr        error
	activeConns     int
	idleTimer       *time.Timer
	idleCloseDelay  time.Duration
	maxDatagramSize int

	closeOnce sync.Once
}

func NewSession(cfg *QUICConfig) *Session {
	idleCloseDelay := cfg.IdleCloseDelay
	if idleCloseDelay == 0 {
		if cfg.QUICConfig != nil && cfg.QUICConfig.MaxIdleTimeout > 0 {
			idleCloseDelay = cfg.QUICConfig.MaxIdleTimeout
		} else {
			idleCloseDelay = defaultIdleTimeout
		}
	}
	return &Session{
		cfg:             cfg,
		ready:           make(chan struct{}),
		lifetimeDone:    make(chan struct{}),
		idleCloseDelay:  idleCloseDelay,
		maxDatagramSize: defaultMaxDatagramSize,
	}
}

func (s *Session) EnsureReady(ctx context.Context) error {
	select {
	case <-s.ready:
		return s.readyError()
	default:
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.finishReady(errSessionClosed)
		return errSessionClosed
	}
	if s.dialStarted {
		s.mu.Unlock()
		select {
		case <-s.ready:
			return s.readyError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.dialStarted = true
	baseCtx := s.cfg.Context
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	dialCtx, cancel := context.WithCancel(baseCtx)
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(dialCtx)

	select {
	case <-s.ready:
		return s.readyError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) readyError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyErr
}

func (s *Session) run(ctx context.Context) {
	defer s.cancel()
	if ctx.Err() != nil || s.IsClosed() {
		s.finishReady(errSessionClosed)
		return
	}
	if err := s.dialAndAuth(ctx); err != nil {
		s.emit(ctx, diagnostic.LevelError, "quic_session_start_failed", err, "")
		s.finishReady(err)
		s.Close()
		return
	}
	s.emit(ctx, diagnostic.LevelInfo, "quic_session_started", nil, s.cfg.CongestionControl.String())
	s.finishReady(nil)
	s.armIdleTimer()

	<-s.conn.Context().Done()
	if !s.IsClosed() {
		s.emit(ctx, diagnostic.LevelWarn, "quic_connection_closed", errConnectionClosed, "")
	}
	s.failSession(errConnectionClosed)
}

func (s *Session) dialAndAuth(ctx context.Context) error {
	dialer := s.cfg.Dialer
	if dialer == nil {
		return errors.New("nowhere: nil dialer")
	}
	if s.cfg.TLSConfig == nil {
		return errors.New("nowhere: nil tls config")
	}
	// An ECH config list fetched from DNS is refreshed by the TCP handshake
	// path; QUIC bypasses it, so refresh it for this dial here.
	tlsConfig, err := tls.QUICDialConfig(ctx, s.cfg.TLSConfig)
	if err != nil {
		return fmt.Errorf("nowhere: quic tls: %w", err)
	}
	dest := M.ParseSocksaddr(s.cfg.Addr)
	udpConn, err := dialer.DialContext(ctx, "udp", dest)
	if err != nil {
		return fmt.Errorf("nowhere: udp dial: %w", err)
	}
	_, bufferControlAvailable := udpConn.(packetConnBufferControl)
	s.emitSocketCapabilities(ctx, bufferControlAvailable)
	qtls.SetDesiredBufferSizes(udpConn)
	if len(s.cfg.MorphSharedKey) > 0 {
		// Morph seals the packet socket below QUIC. Buffer sizing and the
		// capability probe above must see the raw socket first.
		udpConn = newMorphPacketConn(udpConn, s.cfg.MorphSharedKey)
	}
	quicConfig := s.cfg.QUICConfig
	if quicConfig == nil {
		quicConfig = BuildQUICConfig(option.QUICOptions{})
	} else {
		cfgCopy := *quicConfig
		cfgCopy.EnableDatagrams = true
		quicConfig = &cfgCopy
	}
	qconn, err := qtls.Dial(ctx, udpConn, tlsConfig, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNREFUSED) {
			// The local packet socket died mid-handshake (for example an ICMP
			// port unreachable while the server restarts). quic-go tears the
			// transport down and the raw socket error outranks the dial cause,
			// so re-surface it under the transient class the shared dial
			// backoff policy already understands.
			return fmt.Errorf("nowhere: quic dial: connection refused: %w", err)
		}
		return fmt.Errorf("nowhere: quic dial: %w", err)
	}
	s.conn = qconn
	s.rawConn = udpConn
	qconn.SetCongestionControl(NewCongestionController(ctx, qconn, s.cfg.CongestionControl))

	return nil
}

// TLSExporter derives connection-bound authentication material from the real
// completed QUIC TLS handshake. Authentication itself remains core-owned.
func (s *Session) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	s.mu.Lock()
	conn := s.conn
	closed := s.closed
	handshakeInfo := s.handshakeInfo
	s.mu.Unlock()
	if closed {
		return wire.TLSHandshakeInfo{}, errSessionClosed
	}
	if handshakeInfo != nil {
		return handshakeInfo()
	}
	if conn == nil {
		return wire.TLSHandshakeInfo{}, errSessionClosed
	}
	state := conn.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	if len(material) != wire.TLSExporterLen {
		return wire.TLSHandshakeInfo{}, errors.New("nowhere: invalid QUIC TLS exporter length")
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion: state.TLS.Version, NegotiatedALPN: state.TLS.NegotiatedProtocol, Exporter: exporter,
	}, nil
}

func (s *Session) finishReady(err error) {
	s.mu.Lock()
	if s.readyErr == nil && err != nil {
		s.readyErr = err
	} else if err == nil && s.readyErr != nil {
		err = s.readyErr
	}
	select {
	case <-s.ready:
	default:
		close(s.ready)
	}
	s.mu.Unlock()
}

func (s *Session) openQUICStream(ctx context.Context) (stream, error) {
	if s.openStream != nil {
		return s.openStream(ctx)
	}
	s.mu.Lock()
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	if closed || conn == nil {
		return nil, errSessionClosed
	}
	return conn.OpenStreamSync(ctx)
}

func (s *Session) releaseStream() {
	s.mu.Lock()
	s.activeConns--
	if s.activeConns < 0 {
		s.activeConns = 0
	}
	s.armIdleTimerLocked()
	s.mu.Unlock()
}

func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if err := s.EnsureReady(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	receiveDatagram := s.receiveDatagram
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	var (
		data []byte
		err  error
	)
	if closed {
		err = errSessionClosed
	} else if receiveDatagram != nil {
		operationCtx, finish := s.operationContext(ctx)
		data, err = receiveDatagram(operationCtx)
		finish()
	} else if conn != nil {
		data, err = conn.ReceiveDatagram(ctx)
	} else {
		err = errSessionClosed
	}
	if err != nil && !isCallerContextError(ctx, err) {
		s.emit(ctx, diagnostic.LevelWarn, "quic_datagram_receive_failed", err, "")
		s.maybeFailSession(err)
	}
	return data, err
}

func (s *Session) CurrentMaxDatagramSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxDatagramSize
}

func (s *Session) SendDatagram(ctx context.Context, frame []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	sendDatagram := s.sendDatagram
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	var err error
	if closed {
		err = errSessionClosed
	} else if sendDatagram != nil {
		operationCtx, finish := s.operationContext(ctx)
		err = sendDatagram(operationCtx, frame)
		finish()
	} else if conn != nil {
		err = conn.SendDatagram(frame)
	} else {
		err = errSessionClosed
	}
	if err == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		if tooLarge.MaxDatagramPayloadSize > 0 {
			s.mu.Lock()
			s.maxDatagramSize = int(tooLarge.MaxDatagramPayloadSize)
			s.mu.Unlock()
		}
		return &nwquic.DatagramTooLargeError{
			MaxDatagramSize: s.CurrentMaxDatagramSize(),
			Cause:           err,
		}
	}
	s.maybeFailSession(err)
	return err
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	localAddr := s.localAddr
	conn := s.conn
	s.mu.Unlock()
	if localAddr != nil {
		return localAddr()
	}
	if conn == nil {
		return &net.UDPAddr{}
	}
	return conn.LocalAddr()
}

func (s *Session) maybeFailSession(err error) {
	if err == nil {
		return
	}
	// Per-stream EOF/reset must not tear down the shared QUIC session.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) || errors.Is(err, io.EOF) {
		return
	}
	var appErr *quic.ApplicationError
	var transportErr *quic.TransportError
	if errors.Is(err, net.ErrClosed) || errors.Is(err, errSessionClosed) ||
		errors.As(err, &appErr) || errors.As(err, &transportErr) {
		s.failSession(err)
	}
}

func (s *Session) failSession(err error) {
	if err == nil {
		err = errSessionClosed
	}
	s.Close()
}

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		var cancel context.CancelFunc
		var conn *quic.Conn
		var rawConn net.Conn
		s.mu.Lock()
		s.closed = true
		if s.idleTimer != nil {
			s.idleTimer.Stop()
			s.idleTimer = nil
		}
		cancel = s.cancel
		conn = s.conn
		rawConn = s.rawConn
		s.rawConn = nil
		s.mu.Unlock()

		close(s.lifetimeDone)
		s.finishReady(errSessionClosed)
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "")
		}
		if rawConn != nil {
			_ = rawConn.Close()
		}
	})
}

func (s *Session) operationContext(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		select {
		case <-s.lifetimeDone:
			cancel()
		case <-finished:
		}
	}()
	return operationCtx, func() {
		close(finished)
		cancel()
	}
}

func (s *Session) armIdleTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armIdleTimerLocked()
}

func (s *Session) armIdleTimerLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	if s.closed || s.activeConns > 0 {
		return
	}
	s.idleTimer = time.AfterFunc(s.idleCloseDelay, func() {
		s.mu.Lock()
		active := s.activeConns
		s.mu.Unlock()
		if active == 0 {
			s.emit(context.Background(), diagnostic.LevelDebug, "quic_session_idle_closed", nil, s.idleCloseDelay.String())
			s.Close()
		}
	})
}

func (s *Session) emitSocketCapabilities(ctx context.Context, available bool) {
	if s == nil || s.cfg == nil {
		return
	}
	result := "unavailable"
	if available {
		result = "available"
	}
	diagnostic.Emit(ctx, s.cfg.Observer, diagnostic.Event{
		Level:     diagnostic.LevelDebug,
		Code:      "quic_socket_capabilities",
		Component: "sing-box-quic",
		Carrier:   diagnostic.CarrierQUIC,
		State:     "udp_buffer_control",
		Result:    result,
	})
}

func (s *Session) emit(ctx context.Context, level diagnostic.Level, code string, err error, outcome string) {
	if s == nil || s.cfg == nil {
		return
	}
	diagnostic.Emit(ctx, s.cfg.Observer, diagnostic.Event{
		Level: level, Code: code, Component: "sing-box-quic", Target: s.cfg.Addr, Outcome: outcome, Err: err,
	})
}

func (s *Session) disarmIdleTimerLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

var (
	errSessionClosed    = errors.New("nowhere: session closed")
	errConnectionClosed = errors.New("nowhere: connection closed")
)
