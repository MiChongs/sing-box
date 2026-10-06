//go:build with_quic

package quicx

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlogwriter"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	ServerAddress M.Socksaddr
	TLSConfig     aTLS.Config
	QUICOptions   qtls.QUICOptions
	Password      string
	Heartbeat     time.Duration
	BBRProfile    string
	Tracer        func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace
	// TLSDialConfig, when set, derives the TLS configuration of one QUIC dial
	// from TLSConfig, for configurations which are refreshed per handshake
	// (an ECH config list fetched from DNS).
	TLSDialConfig func(ctx context.Context, config aTLS.Config) (aTLS.Config, error)
	// Logger receives the dial diagnostics. A failed dial is otherwise only
	// visible as a generic error to the caller, which cannot tell whether the
	// address failed to resolve, the handshake timed out, or the server
	// rejected the authentication.
	Logger logger.Logger
}

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  aTLS.Config
	tlsDial    func(ctx context.Context, config aTLS.Config) (aTLS.Config, error)
	quicConfig *quic.Config
	password   string
	heartbeat  time.Duration
	bbrProfile congestion_meta2.Profile
	logger     logger.Logger

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	bbrProfile, err := parseBBRProfile(options.BBRProfile)
	if err != nil {
		return nil, err
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		MaxIncomingUniStreams:   1 << 60,
		Tracer:                  options.Tracer,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	// 0-RTT requires resuming a previous TLS session, which in turn requires a
	// session ticket cache: without it the client never requests a session
	// ticket, and quic-go has no ticket to resume from.
	if sessionCacheSetter, isSessionCacheSetter := options.TLSConfig.(sessionCacheSetter); isSessionCacheSetter {
		sessionCacheSetter.SetClientSessionCache(tls.NewLRUClientSessionCache(0))
	} else if stdConfig, sErr := options.TLSConfig.STDConfig(); sErr == nil {
		stdConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		tlsConfig:  options.TLSConfig,
		tlsDial:    options.TLSDialConfig,
		quicConfig: quicConfig,
		password:   options.Password,
		heartbeat:  options.Heartbeat,
		bbrProfile: bbrProfile,
		logger:     options.Logger,
	}, nil
}

// sessionCacheSetter is implemented by TLS configs which allow their underlying
// crypto/tls or uTLS configuration to be adjusted.
type sessionCacheSetter interface {
	SetClientSessionCache(cache tls.ClientSessionCache)
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	dialStart := time.Now()
	tlsConfig := c.tlsConfig
	if c.tlsDial != nil {
		var err error
		tlsConfig, err = c.tlsDial(ctx, c.tlsConfig)
		if err != nil {
			c.logger.Error("QUICX dial failed: stage=tls transport=quic server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", err)
			return nil, err
		}
	}
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		// The dialer resolves the configured server address itself, so this
		// stage covers resolving the address and setting up the UDP socket;
		// the error tells which of the two failed. It is logged because the
		// caller only sees a generic dial failure, which is what made an
		// unreachable path indistinguishable from a rejecting server.
		c.logger.Error("QUICX dial failed: stage=dial transport=udp server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, err
	}
	remote := M.SocksaddrFromNet(udpConn.RemoteAddr())
	quicConn, err := qtls.DialEarly(ctx, udpConn, tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		c.logger.Error("QUICX dial failed: stage=handshake transport=quic server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, E.Cause(err, "open connection")
	}
	c.logger.Debug("QUICX dial: stage=handshake transport=quic server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart))
	setCongestion(c.ctx, quicConn, c.bbrProfile)
	// 0-RTT data is not replay protected, so every connection authenticates
	// with a fresh random nonce which the server remembers: a replayed 0-RTT
	// flight presents the nonce of the session it was captured from and is
	// rejected. See AuthNonceLen.
	var authNonce [AuthNonceLen]byte
	if _, err = rand.Read(authNonce[:]); err != nil {
		quicConn.CloseWithError(0, "")
		udpConn.Close()
		return nil, E.Cause(err, "generate authentication nonce")
	}
	connCtx := c.ctx
	if connCtx == nil {
		connCtx = context.Background()
	}
	conn := &clientQUICConnection{
		ctx:        connCtx,
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
		authNonce:  authNonce,
	}
	go func() {
		hErr := c.clientHandshake(conn)
		if hErr != nil {
			c.logger.Error("QUICX dial failed: stage=auth transport=quic server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", hErr)
			conn.closeWithError(hErr)
		}
	}()
	go func() {
		// The cause is the reason the connection ended: an idle timeout, a
		// peer CONNECTION_CLOSE, a local close, or the network change handler.
		<-quicConn.Context().Done()
		closeCause := context.Cause(quicConn.Context())
		select {
		case <-quicConn.HandshakeComplete():
			c.logger.Debug("QUICX connection closed: server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", closeCause)
		default:
			// DialEarly returns before the handshake completes, so a dial that
			// never got an answer fails here, not in the call above. This is
			// the line which separates an unreachable path (a timeout) from a
			// server refusing the connection (a TLS or QUIC error), and the
			// elapsed time is how long the attempt took to fail.
			c.logger.Error("QUICX dial failed: stage=handshake transport=quic server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", closeCause)
		}
	}()
	go c.loopMessages(conn)
	go c.loopHeartbeats(conn)
	return conn, nil
}

// dialElapsed rounds a dial timing to milliseconds: the diagnostics are meant
// to be read from a log file, where sub-millisecond precision is noise.
func dialElapsed(start time.Time) time.Duration {
	return time.Since(start).Round(time.Millisecond)
}

func (c *Client) clientHandshake(conn *clientQUICConnection) error {
	authRequest := buf.NewSize(2 + 2 + len(c.password) + AuthNonceLen)
	defer authRequest.Release()
	authRequest.WriteByte(Version)
	authRequest.WriteByte(CommandAuthenticate)
	var passwordLen [2]byte
	binary.BigEndian.PutUint16(passwordLen[:], uint16(len(c.password)))
	authRequest.Write(passwordLen[:])
	authRequest.WriteString(c.password)
	// The nonce is sent on every connection, not only on a 0-RTT attempt: the
	// server records it for every authenticated session. A resend after a
	// rejected 0-RTT attempt reuses the same message, which the server accepts
	// because it is the same session.
	authRequest.Write(conn.authNonce[:])
	return writeUniStream0RTT(c.ctx, conn.quicConn, authRequest.Bytes())
}

func (c *Client) loopHeartbeats(conn *clientQUICConnection) {
	ticker := time.NewTicker(c.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.connDone:
			return
		case <-ticker.C:
			err := conn.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				conn.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	// The bidirectional stream of the connection is opened lazily, on the
	// first read or write, see clientConn. An application which abandons the
	// connection before its first byte (a canceled dial, a failed handshake
	// report) must not leave an empty request stream behind: the server cannot
	// tell such a stream from an HTTP/3 request and used to end the whole
	// session for it, which killed every connection multiplexed on it.
	return &clientConn{
		parent:      conn,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	conn.udpAccess.Lock()
	select {
	case <-conn.connDone:
		conn.udpAccess.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	// The session ID is chosen before the connection is published, so that the
	// destroy callback captures a value which is never reassigned afterwards.
	sessionID := conn.udpSessionID
	conn.udpSessionID++
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, sessionID, false, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

// openStream0RTT opens a bidirectional stream, recovering from an open-time
// 0-RTT rejection. quic-go reports quic.Err0RTTRejected from OpenStream until
// the handshake completes and the stream maps are reset, so the stream has to be
// opened again afterwards. On a connection without a resumed session no early
// data is sent and quic.Err0RTTRejected never occurs, in which case both helpers
// are equivalent to a plain OpenStream / OpenUniStream call.
func openStream0RTT(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	stream, err := conn.OpenStream()
	if !errors.Is(err, quic.Err0RTTRejected) {
		return stream, err
	}
	_, nerr := conn.NextConnection(ctx)
	if nerr != nil {
		return nil, nerr
	}
	return conn.OpenStream()
}

func openUniStream0RTT(ctx context.Context, conn *quic.Conn) (*quic.SendStream, error) {
	stream, err := conn.OpenUniStream()
	if !errors.Is(err, quic.Err0RTTRejected) {
		return stream, err
	}
	_, nerr := conn.NextConnection(ctx)
	if nerr != nil {
		return nil, nerr
	}
	return conn.OpenUniStream()
}

// writeUniStream0RTT opens a unidirectional stream, writes message on it and
// closes it. A rejected 0-RTT attempt is recovered instead of failing the
// connection, see writeEarlyMessage.
func writeUniStream0RTT(ctx context.Context, conn *quic.Conn, message []byte) error {
	stream, err := openUniStream0RTT(ctx, conn)
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	rejected, err := writeEarlyMessage(ctx, conn, stream, message)
	if err != nil {
		stream.CancelWrite(0)
		return E.Cause(err, "write handshake request")
	}
	if !rejected {
		closeHandshakeStream(stream)
		return nil
	}
	// The early data was discarded by the peer: the message has to be resent on
	// a stream which is valid after the stream maps were reset.
	stream.CancelWrite(0)
	if _, err = conn.NextConnection(ctx); err != nil {
		return E.Cause(err, "wait for handshake after 0-RTT rejection")
	}
	stream, err = conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	_, err = stream.Write(message)
	if err != nil {
		stream.CancelWrite(0)
		return E.Cause(err, "write handshake request")
	}
	closeHandshakeStream(stream)
	return nil
}

// closeHandshakeStream half-closes the send side of the authentication stream.
// The peer only needs the message itself and stops reading the stream as soon as
// it has it, which quic-go reports as closing a canceled stream. The message was
// written before that happens, so the error is not fatal.
func closeHandshakeStream(stream *quic.SendStream) {
	_ = stream.Close()
}

// earlyStream is implemented by both quic-go stream types and gives access to
// the context which quic-go cancels with quic.Err0RTTRejected when the server
// rejects the early data a stream was created in.
type earlyStream interface {
	Write([]byte) (int, error)
	Context() context.Context
}

// writeEarlyMessage reports whether message was discarded because the server
// rejected a 0-RTT attempt.
//
// quic-go reports quic.Err0RTTRejected from Write only when the rejection was
// already processed at the time of the call. A message which fits into a single
// STREAM frame is buffered and reported as written, and is dropped later without
// any further local error, so the outcome of the early data has to be checked
// after the handshake completed.
func writeEarlyMessage(ctx context.Context, conn *quic.Conn, stream earlyStream, message []byte) (rejected bool, err error) {
	select {
	case <-conn.HandshakeComplete():
		// No early data is in flight anymore, a plain write is enough.
		_, err = stream.Write(message)
		return false, err
	default:
	}
	_, err = stream.Write(message)
	if err != nil {
		if errors.Is(err, quic.Err0RTTRejected) {
			// The rejection is already known: recover instead of failing.
			return true, nil
		}
		return false, err
	}
	// The handshake is still running, so the message may have been sent as early
	// data which the peer is allowed to discard. Wait for the handshake outcome,
	// which is also the point where quic-go resets the streams of a rejected
	// attempt.
	select {
	case <-conn.HandshakeComplete():
	case <-conn.Context().Done():
	case <-ctx.Done():
	}
	return errors.Is(context.Cause(stream.Context()), quic.Err0RTTRejected), nil
}

// writeStream0RTT writes message on stream and recovers from a rejected 0-RTT
// attempt by reopening the stream after the handshake. It returns the stream the
// message was written to, which may differ from stream.
func writeStream0RTT(ctx context.Context, conn *quic.Conn, stream *quic.Stream, message []byte) (*quic.Stream, error) {
	rejected, err := writeEarlyMessage(ctx, conn, stream, message)
	if err != nil || !rejected {
		return stream, err
	}
	// A stream created during 0-RTT is unusable once the server rejected the
	// early data: quic-go resets the stream maps, so the request has to be sent
	// again on a stream opened after the handshake.
	if _, err = conn.NextConnection(ctx); err != nil {
		return stream, err
	}
	newStream, err := conn.OpenStream()
	if err != nil {
		return stream, err
	}
	_, err = newStream.Write(message)
	if err != nil {
		return newStream, err
	}
	return newStream, nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	ctx          context.Context
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpAccess    sync.RWMutex
	udpConnMap   map[uint16]*udpPacketConn
	udpSessionID uint16
	authNonce    [AuthNonceLen]byte
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		c.udpAccess.Lock()
		close(c.connDone)
		udpConnMap := c.udpConnMap
		c.udpConnMap = make(map[uint16]*udpPacketConn)
		c.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

// clientConn is one proxied connection on a QUICX session. The stream it runs
// on is created on the first read or write instead of in DialConn: the server
// treats a request stream without a CONNECT header as a standard HTTP/3
// request, so an empty stream left behind by an abandoned connection used to
// end the whole session.
type clientConn struct {
	access         sync.Mutex
	stream         *quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	requestWritten bool
	closed         bool
	readDeadline   time.Time
	writeDeadline  time.Time
}

func (c *clientConn) NeedHandshake() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, qtls.WrapError(net.ErrClosed)
	}
	if !c.requestWritten {
		// The peer cannot answer before it knows the destination, so a reader
		// which never wrote (a server-first protocol) flushes the CONNECT
		// request on its own.
		if err = c.writeRequestLocked(nil); err != nil {
			c.access.Unlock()
			return 0, qtls.WrapError(err)
		}
	}
	stream := c.stream
	c.access.Unlock()
	n, err = stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, qtls.WrapError(net.ErrClosed)
	}
	if !c.requestWritten {
		err = c.writeRequestLocked(b)
		c.access.Unlock()
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(b), nil
	}
	stream := c.stream
	// The stream never changes once the request was written, so the write does
	// not have to hold the lock: a deadline set while it blocks on flow control
	// still reaches the stream.
	c.access.Unlock()
	n, err = stream.Write(b)
	return n, qtls.WrapError(err)
}

// writeRequestLocked opens the stream lazily and sends the CONNECT request
// followed by payload, which is the first data of the proxied connection. The
// caller holds access.
func (c *clientConn) writeRequestLocked(payload []byte) error {
	request := buf.NewSize(2 + AddressSerializer.AddrPortLen(c.destination) + len(payload))
	defer request.Release()
	request.WriteByte(Version)
	request.WriteByte(CommandConnect)
	err := AddressSerializer.WriteAddrPort(request, c.destination)
	if err != nil {
		return err
	}
	request.Write(payload)
	stream, err := c.openStreamLocked()
	if err != nil {
		return err
	}
	// The stream was opened while the handshake may still be running, so the
	// request can be part of the 0-RTT flight. When the server rejects the
	// early data this stream is invalid, and the request is sent again on a
	// stream opened after the handshake instead of failing the session.
	stream, err = writeStream0RTT(c.parent.ctx, c.parent.quicConn, stream, request.Bytes())
	if err != nil {
		// One stream which cannot be written must not end the session: every
		// other connection multiplexed on it would be torn down as well. The
		// stream is reset and the failure is reported to the caller, which
		// closes this connection only.
		resetClientStream(stream)
		return err
	}
	c.stream = stream
	c.requestWritten = true
	c.applyDeadlinesLocked(stream)
	return nil
}

// openStreamLocked creates the stream the connection runs on if it does not
// exist yet. The caller holds access.
func (c *clientConn) openStreamLocked() (*quic.Stream, error) {
	if c.stream != nil {
		return c.stream, nil
	}
	stream, err := openStream0RTT(c.parent.ctx, c.parent.quicConn)
	if err != nil {
		return nil, E.Cause(err, "open stream")
	}
	c.applyDeadlinesLocked(stream)
	return stream, nil
}

// applyDeadlinesLocked transfers the deadlines which were set before the stream
// existed to it. The caller holds access.
func (c *clientConn) applyDeadlinesLocked(stream *quic.Stream) {
	if !c.readDeadline.IsZero() {
		_ = stream.SetReadDeadline(c.readDeadline)
	}
	if !c.writeDeadline.IsZero() {
		_ = stream.SetWriteDeadline(c.writeDeadline)
	}
}

// resetClientStream discards one stream without touching the session it is
// multiplexed on.
func resetClientStream(stream *quic.Stream) {
	stream.CancelWrite(0)
	stream.CancelRead(0)
	_ = stream.Close()
}

func (c *clientConn) Close() error {
	c.access.Lock()
	c.closed = true
	stream := c.stream
	c.stream = nil
	c.access.Unlock()
	if stream == nil {
		// The stream was never opened, so nothing was sent to the peer and
		// there is nothing to reset: this is what keeps an abandoned dial from
		// leaving an empty request stream behind.
		return nil
	}
	stream.CancelRead(0)
	err := stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	stream.SetWriteDeadline(time.Now())
	return err
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.readDeadline = t
	if c.stream == nil {
		return nil
	}
	return c.stream.SetReadDeadline(t)
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.writeDeadline = t
	if c.stream == nil {
		return nil
	}
	return c.stream.SetWriteDeadline(t)
}

func (c *clientConn) SetDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	if c.stream == nil {
		return nil
	}
	return E.Errors(c.stream.SetReadDeadline(t), c.stream.SetWriteDeadline(t))
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
