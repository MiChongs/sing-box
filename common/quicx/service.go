//go:build with_quic

package quicx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlogwriter"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const (
	AuthFailurePolicyH3Close    = "h3_close"
	AuthFailurePolicySilentDrop = "silent_drop"

	// defaultSilentDropTimeout is how long a silently dropped session is kept
	// before its QUIC connection is reclaimed locally.
	defaultSilentDropTimeout = 30 * time.Second
)

// errAlreadyAuthenticated is returned for a second authentication stream on a
// session which already completed authentication. It is not fatal: the first
// stream authenticated the session, so a peer racing two authentication
// streams (or a buggy client) must not tear the session down.
var errAlreadyAuthenticated = E.New("authentication: multiple authentication requests")

type ServiceOptions struct {
	Context     context.Context
	Logger      logger.Logger
	TLSConfig   aTLS.ServerConfig
	QUICOptions qtls.QUICOptions
	AuthTimeout time.Duration
	Heartbeat   time.Duration
	UDPTimeout  time.Duration
	// SilentDropTimeout is how long a session closed by
	// AuthFailurePolicySilentDrop keeps its QUIC connection before it is
	// reclaimed locally. No CONNECTION_CLOSE is sent before that, so a probe
	// observes a timeout instead of a protocol-identifiable close; without a
	// reclamation timer a peer sending keepalives would pin the session
	// resources until the QUIC idle timeout expires.
	SilentDropTimeout time.Duration
	// ReplayCacheSize is how many authentication nonces the service remembers
	// to reject a replayed 0-RTT flight. The default is 65536 sessions.
	ReplayCacheSize int
	// ReplayCacheTTL is how long an authentication nonce is remembered. The
	// default is 24 hours, which matches how long crypto/tls keeps the session
	// ticket keys a 0-RTT attempt resumes from.
	ReplayCacheTTL    time.Duration
	Handler           ServiceHandler
	AuthFailurePolicy string
	BBRProfile        string
	Tracer            func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx               context.Context
	logger            logger.Logger
	tlsConfig         aTLS.ServerConfig
	heartbeat         time.Duration
	quicConfig        *quic.Config
	usersAccess       sync.RWMutex
	userMap           map[string]U
	authTimeout       time.Duration
	udpTimeout        time.Duration
	handler           ServiceHandler
	authFailurePolicy string
	silentDropTimeout time.Duration
	bbrProfile        congestion_meta2.Profile
	replayCache       *replayCache
	sessionSeq        atomic.Uint64

	quicListener io.Closer

	// Closing a quic-go listener leaves the connections it accepted running,
	// so the service tracks them to close them itself: otherwise a session
	// outlives the inbound until its idle timeout, and never sees the peer's
	// CONNECTION_CLOSE once the inbound released the UDP socket.
	connAccess sync.Mutex
	conns      map[*quic.Conn]struct{}
	closed     bool
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	if options.UDPTimeout == 0 {
		// A zero UDP timeout makes the wrapped packet connection expire
		// immediately, so every UDP message replaces its session. Fall back to
		// the default the sing-box inbound uses.
		options.UDPTimeout = 5 * time.Minute
	}
	bbrProfile, err := parseBBRProfile(options.BBRProfile)
	if err != nil {
		return nil, err
	}
	if options.AuthFailurePolicy == "" {
		options.AuthFailurePolicy = AuthFailurePolicyH3Close
	}
	if options.SilentDropTimeout == 0 {
		options.SilentDropTimeout = defaultSilentDropTimeout
	}
	switch options.AuthFailurePolicy {
	case AuthFailurePolicyH3Close, AuthFailurePolicySilentDrop:
	default:
		return nil, E.New("unknown auth failure policy: ", options.AuthFailurePolicy)
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               true,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
		DisablePathManager:      true,
		Tracer:                  options.Tracer,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Service[U]{
		ctx:               options.Context,
		logger:            options.Logger,
		tlsConfig:         options.TLSConfig,
		heartbeat:         options.Heartbeat,
		quicConfig:        quicConfig,
		userMap:           make(map[string]U),
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		handler:           options.Handler,
		authFailurePolicy: options.AuthFailurePolicy,
		silentDropTimeout: options.SilentDropTimeout,
		bbrProfile:        bbrProfile,
		replayCache:       newReplayCache(options.ReplayCacheSize, options.ReplayCacheTTL),
		conns:             make(map[*quic.Conn]struct{}),
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U, len(userList))
	for index := range userList {
		userMap[passwordList[index]] = userList[index]
	}
	// The map is replaced, never mutated in place, and authentication reads it
	// under the same lock: a runtime update must not race with the
	// authentication path, which would be a concurrent map read/write fatal.
	s.usersAccess.Lock()
	s.userMap = userMap
	s.usersAccess.Unlock()
}

func (s *Service[U]) lookupUser(password string) (U, bool) {
	s.usersAccess.RLock()
	defer s.usersAccess.RUnlock()
	user, loaded := s.userMap[password]
	return user, loaded
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	listener, err := qtls.ListenEarlyWithOptions(conn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		StatelessReset: true,
	})
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	err := common.Close(
		s.quicListener,
	)
	s.connAccess.Lock()
	s.closed = true
	conns := make([]*quic.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.conns = nil
	s.connAccess.Unlock()
	// Closed while the inbound still owns the UDP socket, so the peers get a
	// CONNECTION_CLOSE; the sessions observe it and release their streams.
	for _, conn := range conns {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	}
	return err
}

// trackConn registers an accepted connection until it ends. It reports false
// when the service is already closed, in which case the caller must close it.
func (s *Service[U]) trackConn(conn *quic.Conn) bool {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	context.AfterFunc(conn.Context(), func() {
		s.connAccess.Lock()
		delete(s.conns, conn)
		s.connAccess.Unlock()
	})
	return true
}

func (s *Service[U]) loopConnections(listener qtls.EarlyListener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		if !s.trackConn(connection) {
			_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	setCongestion(s.ctx, connection, s.bbrProfile)
	h3Server := http3.Server{}
	h3Conn, err := h3Server.NewRawServerConn(connection)
	if err != nil {
		_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		return
	}
	sessionCtx, sessionCancel := context.WithCancelCause(s.ctx)
	session := &serverSession[U]{
		Service:    s,
		ctx:        sessionCtx,
		cancel:     sessionCancel,
		quicConn:   connection,
		h3Conn:     h3Conn,
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
		sessionID:  s.sessionSeq.Add(1),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	cancel     context.CancelCauseFunc
	quicConn   *quic.Conn
	h3Conn     *http3.RawServerConn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authAccess sync.Mutex
	authDone   chan struct{}
	authUser   U
	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn
	// sessionID identifies this session to the replay cache: a nonce which was
	// recorded by another session is a replayed 0-RTT flight.
	sessionID uint64

	authTimeoutOnce sync.Once
}

func (s *serverSession[U]) handle() {
	go s.loopSessionDone()
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.loopHeartbeats()
}

// loopSessionDone ends the session when the service context is canceled or the
// QUIC connection is gone. The connection has to be watched for the whole
// lifetime of the session, and not only by the loops which read it: a session
// which never authenticated has no other reader of the connection state
// (loopMessages and loopHeartbeats wait for authentication first, and the accept
// loops just return on error), so a connection which ended by itself — an idle
// timeout, a stateless reset or a peer close — used to be noticed only when the
// authentication timeout expired. The pending request streams were then released
// with "authentication timeout" around authTimeout later, and the close of an
// idle connection was reported as an ERROR.
func (s *serverSession[U]) loopSessionDone() {
	connCtx := s.quicConn.Context()
	select {
	case <-s.connDone:
	case <-s.ctx.Done():
		s.closeWithError(s.ctx.Err())
	case <-connCtx.Done():
		s.closeWithError(context.Cause(connCtx))
	}
}

func (s *serverSession[U]) startAuthTimeout() {
	s.authTimeoutOnce.Do(func() {
		go s.handleAuthTimeout()
	})
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.closeWithError(E.New("authentication timeout"))
	}
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func(stream *quic.ReceiveStream) {
			err := s.handleUniStream(stream)
			if err == nil {
				return
			}
			if errors.Is(err, errAlreadyAuthenticated) {
				// The session is already authenticated by another stream, so
				// this duplicate request is a no-op instead of a session
				// teardown.
				s.logger.Debug(E.Cause(err, "handle uni stream"))
				return
			}
			s.closeWithError(E.Cause(err, "handle uni stream"))
		}(uniStream)
	}
}

func (s *serverSession[U]) handleUniStream(stream *quic.ReceiveStream) error {
	var header [2]byte
	n, _ := stream.Peek(header[:])
	if n > 0 && header[0] == Version && isQUICXUniCommand(header[1]) {
		defer stream.CancelRead(0)
		s.startAuthTimeout()
		return s.handleQUICXUniStream(stream)
	}
	// A unidirectional stream that is not a QUICX command belongs to the
	// standard HTTP/3 machinery (control/QPACK streams). Let the HTTP/3
	// connection consume it so the connection stays well-formed.
	s.h3Conn.HandleUnidirectionalStream(stream)
	return nil
}

func isQUICXUniCommand(command byte) bool {
	switch command {
	case CommandAuthenticate, CommandDissociate:
		return true
	default:
		return false
	}
}

func (s *serverSession[U]) handleQUICXUniStream(stream *quic.ReceiveStream) error {
	buffer := buf.New()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", version)
	}
	command := buffer.Byte(1)
	switch command {
	case CommandAuthenticate:
		// Authentication request message:
		// [version(1)][command(1)][password length(2)][password(variable)]
		// [nonce(AuthNonceLen)]
		if buffer.Len() < 4 {
			_, err = buffer.ReadFullFrom(stream, 4-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		passwordLen := int(binary.BigEndian.Uint16(buffer.Range(2, 4)))
		if passwordLen == 0 {
			return E.New("authentication: empty password")
		}
		requestLen := 4 + passwordLen + AuthNonceLen
		if buffer.Len() < requestLen {
			_, err = buffer.ReadFullFrom(stream, requestLen-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		password := string(buffer.Range(4, 4+passwordLen))
		var nonce [AuthNonceLen]byte
		copy(nonce[:], buffer.Range(4+passwordLen, requestLen))
		if nonce == ([AuthNonceLen]byte{}) {
			return E.New("authentication: missing nonce")
		}
		user, loaded := s.lookupUser(password)
		if !loaded {
			return s.authFailure(E.New("authentication: unknown user"))
		}
		// A replayed 0-RTT flight authenticates with the password it captured,
		// so the nonce is what identifies it as a copy: it was recorded by the
		// session it was captured from and must not be accepted for this one.
		if s.replayCache.checkAndRecord(nonce, s.sessionID) {
			return s.authFailure(E.New("authentication: replayed authentication request"))
		}
		return s.completeAuthentication(user)
	case CommandDissociate:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		if buffer.Len() > 4 {
			return E.New("invalid dissociate message")
		}
		var sessionID uint16
		err = binary.Read(io.MultiReader(bytes.NewReader(buffer.From(2)), stream), binary.BigEndian, &sessionID)
		if err != nil {
			return err
		}
		s.udpAccess.RLock()
		udpConn, loaded := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil
	default:
		return E.New("unknown command ", command)
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func(stream *quic.Stream) {
			err := s.handleStream(stream)
			if err != nil {
				// A request stream which cannot be served is reset, and only
				// that stream: QUICX multiplexes every connection of a client
				// on one session, so ending the session over a single bad
				// stream tears down all of them at once, and the connections
				// which are re-established while it closes produce more of the
				// same bad stream. That loop is what turned one unreadable
				// stream into a reconnect storm. Only protocol level
				// violations (the DATAGRAM path, see loopMessages) and the
				// masquerade policy for unauthenticated sessions terminate a
				// session.
				s.resetStream(stream)
				s.logger.Debug(E.Cause(err, "handle stream request"))
			}
		}(stream)
	}
}

// resetStream discards one request stream without touching the session. It is
// what a standard HTTP/3 server does with a stream it cannot serve, and how
// TUIC handles a failed request stream.
func (s *serverSession[U]) resetStream(stream *quic.Stream) {
	stream.CancelRead(0)
	_ = stream.Close()
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	var header [2]byte
	n, peekErr := stream.Peek(header[:])
	if n > 0 && header[0] == Version && header[1] == CommandConnect {
		s.startAuthTimeout()
		return s.handleQUICXStream(stream)
	}
	if n == 0 {
		// The peer opened a request stream and closed or reset it before the
		// CONNECT header was sent: an abandoned dial, a canceled request or a
		// stream which was reset on the way. There is no request to serve and
		// nothing to masquerade, and a standard HTTP/3 server ignores such a
		// stream as well, so only the stream is reset.
		// The arguments are restricted to the types the logger can format: a
		// named type such as quic.StreamID panics format.ToString.
		s.logger.Debug("stream ", int64(stream.StreamID()), " from ", M.SocksaddrFromNet(s.quicConn.RemoteAddr()), " sent no request (", peekErr, "), resetting the stream")
		s.resetStream(stream)
		return nil
	}
	if s.authenticated() {
		// The session completed authentication, so a stream which is not a
		// QUICX request is not a probe of the masquerade either: it is one
		// broken connection of a client which is known to speak QUICX. Only
		// the offending stream is reset, like a standard HTTP/3 server handles
		// a single malformed request stream.
		s.logger.Debug("stream ", int64(stream.StreamID()), " from ", M.SocksaddrFromNet(s.quicConn.RemoteAddr()), " is not a QUICX request (", int(header[0]), " ", int(header[1]), "), resetting the stream")
		s.resetStream(stream)
		return nil
	}
	// Any other bidirectional stream is a standard HTTP/3 request stream on a
	// session which never authenticated. It is not a QUICX proxy request, so
	// there is no masquerade to serve; the session is terminated following
	// auth_failure_policy, exactly like a failed authentication, keeping the
	// transport indistinguishable from a standard HTTP/3 server.
	s.closeByPolicy(E.New("standard HTTP/3 request"))
	return nil
}

// authenticated reports whether the session completed authentication.
func (s *serverSession[U]) authenticated() bool {
	select {
	case <-s.authDone:
		return true
	default:
		return false
	}
}

func (s *serverSession[U]) handleQUICXStream(stream *quic.Stream) error {
	buffer := buf.NewSize(2 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", version)
	}
	command, _ := buffer.ReadByte()
	if command != CommandConnect {
		return E.New("unsupported stream command ", command)
	}
	destination, err := AddressSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if !buffer.IsEmpty() {
		conn = bufio.NewCachedConn(conn, buffer.ToOwned())
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), conn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) loopHeartbeats() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.connDone:
			return
		case <-ticker.C:
			err := s.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				s.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (s *serverSession[U]) authFailure(err error) error {
	s.closeByPolicy(err)
	return err
}

// completeAuthentication publishes the authenticated user and signals authDone
// exactly once. The check and the state change have to be atomic: two
// authentication streams racing on one connection would otherwise both observe
// an unauthenticated session and execute close(s.authDone) twice, panicking with
// "close of closed channel" and taking the whole process down. Later readers
// observe authUser through the happens-before edge of the channel close.
func (s *serverSession[U]) completeAuthentication(user U) error {
	s.authAccess.Lock()
	defer s.authAccess.Unlock()
	select {
	case <-s.authDone:
		return errAlreadyAuthenticated
	default:
	}
	s.authUser = user
	close(s.authDone)
	return nil
}

// closeByPolicy terminates a session that is not a valid authenticated QUICX
// session, following auth_failure_policy.
func (s *serverSession[U]) closeByPolicy(err error) {
	switch s.authFailurePolicy {
	case AuthFailurePolicyH3Close:
		// Close the connection with H3_NO_ERROR (0x100), the standard HTTP/3
		// code for a normal connection close. This keeps the transport
		// indistinguishable from a standard HTTP/3 server. A GOAWAY frame is
		// intentionally not sent: the session ends before any request was
		// served.
		s.closeSession(quic.ApplicationErrorCode(http3.ErrCodeNoError), "", err)
	case AuthFailurePolicySilentDrop:
		s.silentClose(err)
	}
}

func (s *serverSession[U]) closeWithError(err error) {
	s.closeSession(quic.ApplicationErrorCode(http3.ErrCodeNoError), "", err)
}

// closeSession terminates the session exactly once and keeps cause as the
// session error, so callers of connDone still observe why it ended. Replacing
// it with a generic "connection closed" loses the real reason and reports
// normal closes (canceled contexts, closed pipes, ...) as ERROR level.
func (s *serverSession[U]) closeSession(code quic.ApplicationErrorCode, desc string, cause error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
	}
	if cause == nil {
		cause = E.New("connection closed")
	}
	s.connErr = cause
	close(s.connDone)
	if isNormalSessionEnd(cause) {
		s.logger.Debug(E.Cause(cause, "connection closed"))
	} else {
		s.logger.Error(E.Cause(cause, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(cause)
	}
	_ = s.quicConn.CloseWithError(code, desc)
	_ = s.h3Conn.CloseWithError(code, desc)
}

func (s *serverSession[U]) silentClose(err error) {
	s.connAccess.Lock()
	select {
	case <-s.connDone:
		s.connAccess.Unlock()
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.connAccess.Unlock()
	s.logger.Debug(E.Cause(err, "connection dropped silently"))
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	s.cancel(err)
	// Do not close the QUIC connection: a probe must observe a timeout, not a
	// protocol-identifiable CONNECTION_CLOSE. Keep the connection open for a
	// grace period only, so that a peer sending keepalives cannot pin the
	// session resources until the QUIC idle timeout expires.
	s.scheduleSilentReclaim()
}

// isNormalSessionEnd reports whether a session ended without a protocol or
// transport failure, in which case it must not be reported as an error. The
// QUIC error types below describe a peer which closed the connection on purpose,
// an idle timeout and a stateless reset, none of which is an application error.
func isNormalSessionEnd(err error) bool {
	if E.IsClosedOrCanceled(err) {
		return true
	}
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		return true
	}
	var idleTimeoutErr *quic.IdleTimeoutError
	if errors.As(err, &idleTimeoutErr) {
		return true
	}
	var statelessResetErr *quic.StatelessResetError
	if errors.As(err, &statelessResetErr) {
		return true
	}
	return false
}

// scheduleSilentReclaim tears the QUIC connection down locally after
// silentDropTimeout. It gives up as soon as the connection is gone by itself.
func (s *serverSession[U]) scheduleSilentReclaim() {
	timeout := s.silentDropTimeout
	if timeout <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		case <-s.quicConn.Context().Done():
		}
	}()
}

type serverConn struct {
	*quic.Stream
	destination M.Socksaddr
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
