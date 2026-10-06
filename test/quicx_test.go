package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
	"github.com/sagernet/sing-box/common/quicx"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

const quicxTestPassword = "password"

var quicxTestDestination = M.ParseSocksaddrHostPort("example.com", 80)

// TestQUICXZeroRTT proves that a QUICX client really sends 0-RTT data and that
// the authenticated session works on the resumed connection. The box
// configuration has no switch for this, so the QUICX client and server are
// driven directly here with a qlog tracer injected, which is the only way to
// observe the packet types of a connection.
func TestQUICXZeroRTT(t *testing.T) {
	ctx := context.Background()
	qlogDir := t.TempDir()
	t.Setenv("QLOGDIR", qlogDir)
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, quicxTestTracer)
	client, clientTLS := newQUICXTestClient(t, ctx, server.address, quicxTestPassword, quicxTestTracer)

	// A session ticket is required before 0-RTT can be attempted, and the client
	// has to install the cache for it on its own.
	stdConfig, err := clientTLS.STDConfig()
	require.NoError(t, err)
	require.NotNil(t, stdConfig.ClientSessionCache, "the QUICX client did not install a TLS session cache")
	cache := &quicxTestSessionCache{inner: stdConfig.ClientSessionCache}
	stdConfig.ClientSessionCache = cache

	// The first connection performs a full handshake and authenticates with the
	// configured user.
	firstConn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, firstConn, []byte("ping"))
	require.Equal(t, []int{0}, server.handler.userList(), "the first connection was not authenticated")

	// The session ticket of the handshake arrives with a delay.
	time.Sleep(2 * time.Second)
	require.NoError(t, firstConn.Close())
	// Force a new QUIC connection: the interesting case is the re-established
	// tunnel, which resumes the session and sends its authentication in 0-RTT.
	client.CloseWithError(os.ErrClosed)

	secondConn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, secondConn, []byte("pong"))
	require.NoError(t, secondConn.Close())
	require.Equal(t, []int{0, 0}, server.handler.userList(), "the resumed connection was not authenticated")

	require.GreaterOrEqual(t, cache.gets, 2, "the second connection did not look for a resumed session")
	traces, err := filepath.Glob(filepath.Join(qlogDir, "*_client.sqlog"))
	require.NoError(t, err)
	require.NotEmpty(t, traces, "no client qlog traces were written")
	trace, err := os.ReadFile(quicxTestNewest(t, traces))
	require.NoError(t, err)
	require.Contains(t, string(trace), `"packet_type":"0RTT"`, "the second connection did not send any 0-RTT packet")
}

// TestQUICXZeroRTTRejected covers a 0-RTT attempt which the server rejects: a
// session ticket is only usable by the server which issued it, so a restarted or
// re-keyed server answers with a full handshake and discards all early data.
// quic-go cannot always report that on the write which buffered the message, so
// the client has to resend the authentication after the handshake instead of
// closing the connection.
func TestQUICXZeroRTTRejected(t *testing.T) {
	ctx := context.Background()
	qlogDir := t.TempDir()
	t.Setenv("QLOGDIR", qlogDir)
	serverA := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, quicxTestTracer)
	serverB := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, quicxTestTracer)
	setQUICXTestTicketKey(t, serverA, 0x11)
	setQUICXTestTicketKey(t, serverB, 0x22)

	// Both clients share one TLS configuration, and therefore one session cache:
	// the ticket issued by server A is offered to server B.
	clientTLS := newQUICXTestClientTLS(t, ctx)
	clientA, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        &quicxTestDialer{},
		ServerAddress: serverA.address,
		TLSConfig:     clientTLS,
		QUICOptions:   qtls.QUICOptions{},
		Password:      quicxTestPassword,
		Tracer:        quicxTestTracer,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		clientA.CloseWithError(os.ErrClosed)
	})
	clientB, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        &quicxTestDialer{},
		ServerAddress: serverB.address,
		TLSConfig:     clientTLS,
		QUICOptions:   qtls.QUICOptions{},
		Password:      quicxTestPassword,
		Tracer:        quicxTestTracer,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		clientB.CloseWithError(os.ErrClosed)
	})
	stdConfig, err := clientTLS.STDConfig()
	require.NoError(t, err)
	require.NotNil(t, stdConfig.ClientSessionCache)
	cache := &quicxTestSessionCache{inner: stdConfig.ClientSessionCache}
	stdConfig.ClientSessionCache = cache

	connA, err := clientA.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, connA, []byte("ping"))
	// The session ticket is delivered after the handshake completed.
	time.Sleep(2 * time.Second)

	connB, err := clientB.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	// Without the resend after the rejected 0-RTT attempt the server never
	// authenticates the session and this echo times out.
	quicxEchoConn(t, connB, []byte("pong"))
	require.NoError(t, connB.Close())
	require.Equal(t, []int{0}, serverA.handler.userList())
	require.Equal(t, []int{0}, serverB.handler.userList(), "the rejected 0-RTT authentication was not retried")

	require.GreaterOrEqual(t, cache.gets, 1, "the second connection did not look for a resumed session")
	traces, err := filepath.Glob(filepath.Join(qlogDir, "*_client.sqlog"))
	require.NoError(t, err)
	require.NotEmpty(t, traces, "no client qlog traces were written")
	require.True(t, quicxTestAnyTraceContains(t, traces, `"packet_type":"0RTT"`), "no client connection attempted 0-RTT")
}

// TestQUICXZeroRTTRequestData proves what a replayed 0-RTT flight carries: the
// CONNECT request and the first payload of the proxied connection are sent as
// early data, which is why the server has to reject a replayed flight instead
// of letting it reach the destination a second time. The service's socket is
// held back while the client dials, which keeps the handshake pending and makes
// the request deterministically part of the 0-RTT flight instead of racing the
// handshake (the trace of the existing zero-RTT test only proves that the
// authentication was sent as early data).
func TestQUICXZeroRTTRequestData(t *testing.T) {
	ctx := context.Background()
	qlogDir := t.TempDir()
	t.Setenv("QLOGDIR", qlogDir)
	gate := &quicxTestGatePacketConn{}
	server := startQUICXTestServerWithPacketConn(t, ctx, []string{quicxTestPassword}, logger.NOP(), quicxTestTracer, func(packetConn net.PacketConn) net.PacketConn {
		gate.PacketConn = packetConn
		return gate
	})
	client, clientTLS := newQUICXTestClient(t, ctx, server.address, quicxTestPassword, quicxTestTracer)
	stdConfig, err := clientTLS.STDConfig()
	require.NoError(t, err)
	require.NotNil(t, stdConfig.ClientSessionCache, "the QUICX client did not install a TLS session cache")

	// The first connection performs a full handshake and leaves the session
	// ticket the tunnel is resumed from.
	firstConn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, firstConn, []byte("ping"))
	time.Sleep(2 * time.Second)
	require.NoError(t, firstConn.Close())
	client.CloseWithError(os.ErrClosed)

	// The resumed connection: the server's flight is held back, so the client
	// cannot complete the handshake before it wrote its request.
	payload := []byte("pong")
	gate.arm()
	secondConn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	require.NoError(t, secondConn.SetDeadline(time.Now().Add(10*time.Second)))
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := secondConn.Write(payload)
		writeResult <- writeErr
	}()
	// The write cannot return while the handshake is held back: give the client
	// time to pack the request into the 0-RTT flight, then let it finish.
	time.Sleep(200 * time.Millisecond)
	gate.release()
	require.NoError(t, <-writeResult)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(secondConn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)
	require.NoError(t, secondConn.Close())
	client.CloseWithError(os.ErrClosed)

	// The request was written on the first bidirectional stream (the
	// authentication uses a unidirectional one), and the trace has to show
	// those bytes inside a 0-RTT packet.
	expected := int64(2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination) + len(payload))
	traces, err := filepath.Glob(filepath.Join(qlogDir, "*_client.sqlog"))
	require.NoError(t, err)
	require.NotEmpty(t, traces, "no client qlog traces were written")
	require.Eventually(t, func() bool {
		return quicxTestZeroRTTStreamBytes(t, traces, 0) >= expected
	}, 10*time.Second, 100*time.Millisecond, "the CONNECT request was not sent as 0-RTT data")
}

// TestQUICXConcurrentAuthentication covers two authentication streams racing on
// one connection. Publishing the authenticated user used to be a check-then-act
// sequence, so the second stream closed the notification channel a second time
// and panicked with "close of closed channel", killing the process.
func TestQUICXConcurrentAuthentication(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	authHeader := []byte{quicx.Version, quicx.CommandAuthenticate}
	for round := 0; round < 8; round++ {
		conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
		// Every connection authenticates with its own nonce, so the rounds are
		// not mistaken for replays of each other. The two streams of a round
		// race on the same session and therefore share one nonce.
		authNonce := quicxTestNonce(byte(0x11 + round))
		authBody := make([]byte, 2+len(quicxTestPassword)+quicx.AuthNonceLen)
		binary.BigEndian.PutUint16(authBody[0:2], uint16(len(quicxTestPassword)))
		copy(authBody[2:], quicxTestPassword)
		copy(authBody[2+len(quicxTestPassword):], authNonce[:])
		streams := make([]*quic.SendStream, 2)
		for index := range streams {
			stream, err := conn.OpenUniStream()
			require.NoError(t, err)
			_, err = stream.Write(authHeader)
			require.NoError(t, err)
			streams[index] = stream
		}
		// Both handlers are blocked reading the password length now, so the
		// passwords wake them up at the same time.
		time.Sleep(100 * time.Millisecond)
		var group sync.WaitGroup
		for _, stream := range streams {
			group.Add(1)
			go func(stream *quic.SendStream) {
				defer group.Done()
				_, _ = stream.Write(authBody)
				_ = stream.Close()
			}(stream)
		}
		group.Wait()
		// A duplicate authentication request must not take the session down: the
		// session stays authenticated and usable.
		rawQUICXEcho(t, conn, []byte("ping"))
	}
	require.NotEmpty(t, server.handler.userList())
}

// TestQUICXSmallDatagramLimit covers a peer forging a tiny
// max_datagram_frame_size: the packet size derived from the reported DATAGRAM
// limit must never become negative or zero, otherwise fragmenting a UDP message
// panics or loops forever.
func TestQUICXSmallDatagramLimit(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{
		EnableDatagrams:      true,
		MaxDatagramFrameSize: 1,
	})
	rawQUICXAuthenticate(t, conn, quicxTestPassword)
	rawQUICXEcho(t, conn, []byte("ping"))
	// The echo handler answers with a DATAGRAM, which the forged peer limit
	// rejects: the server has to report the error instead of panicking.
	rawQUICXSendUDPMessage(t, conn, 1, 1, 1, 0, []byte("datagram"))
	require.Eventually(t, func() bool {
		return server.handler.udpPackets.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "the server did not receive the UDP message")
	require.Eventually(t, func() bool {
		return server.handler.udpWriteErrors.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "the server did not try to answer the UDP message")
	// The session is still usable and the service is still alive.
	rawQUICXEcho(t, conn, []byte("pong"))
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXFragmentLengthOverflow covers a peer sending more fragment data than
// the uint16 length field of the protocol can express. The accumulated length
// used to wrap around, allocating a buffer which is too small and panicking with
// "short buffer".
func TestQUICXFragmentLengthOverflow(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticate(t, conn, quicxTestPassword)
	rawQUICXEcho(t, conn, []byte("ping"))
	// 70 fragments of 1000 bytes are 70000 bytes in total, which is more than
	// the reassembled message length field can hold. DATAGRAM frames are not
	// retransmitted, so the fragments are paced and repeated until the server
	// rejects the message.
	const (
		fragmentTotal = 70
		fragmentSize  = 1000
	)
	for attempt := 0; attempt < 5 && !quicxConnectionClosed(conn); attempt++ {
		for index := 0; index < fragmentTotal; index++ {
			rawQUICXSendUDPMessage(t, conn, 1, 1, fragmentTotal, uint8(index), bytes.Repeat([]byte{byte(index)}, fragmentSize))
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The protocol violation terminates the offending session instead of
	// crashing the service.
	require.Eventually(t, func() bool {
		return quicxConnectionClosed(conn)
	}, 5*time.Second, 50*time.Millisecond, "the server did not reject the oversized reassembly")
	requireQUICXServiceAlive(t, ctx, server)
}

// quicxConnectionClosed reports whether the connection is gone.
func quicxConnectionClosed(conn *quic.Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

// TestQUICXEmptyTargetUDPFragment covers the sessions which are created from the
// first DATAGRAM of a fragmented UDP message: fragments used to carry the
// destination in the head fragment only, and the routing decision of a session
// is made once, from its first message, so a tail fragment which arrived first
// created a session routed to an empty destination (":0"). Such a message is
// dropped without a session now, and the session of a message whose tail
// fragment arrived first is routed to the destination of the message.
func TestQUICXEmptyTargetUDPFragment(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticate(t, conn, quicxTestPassword)

	// The tail fragment of a message of the protocol before the destination was
	// repeated in every fragment: it carries none, so this sessionID must not
	// get a session at all — a session created here would be routed (and
	// reported, and dialed) to ":0".
	rawQUICXSendUDPMessageTo(t, conn, 1, 1, 2, 1, M.Socksaddr{}, []byte("tail"))
	time.Sleep(500 * time.Millisecond)
	require.Empty(t, server.handler.packetTargetList(), "a message without a destination created a session")
	require.False(t, quicxConnectionClosed(conn), "a message without a destination ended the session")

	// The same message with the destination every fragment carries: the tail
	// fragment arrives first, and the session has to be routed to the
	// destination of the message instead of an empty address.
	rawQUICXSendUDPMessageTo(t, conn, 2, 2, 2, 1, quicxTestDestination, []byte("tail"))
	rawQUICXSendUDPMessageTo(t, conn, 2, 2, 2, 0, quicxTestDestination, []byte("head"))
	require.Eventually(t, func() bool {
		return server.handler.udpPackets.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "the fragmented UDP message was not delivered")
	require.Equal(t, []M.Socksaddr{quicxTestDestination}, server.handler.packetTargetList(), "the session was not routed to the destination of its first message")
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXConnectionCloseCancelsPendingStreams covers a session which never
// authenticated: its request stream waits for the authentication of the session,
// and nothing else watches the QUIC connection in that state (the datagram and
// the heartbeat loops wait for authentication first, and the accept loops just
// return), so a connection which ended by itself — an idle timeout, a stateless
// reset or a peer close — used to be noticed only when the authentication
// timeout expired. The pending stream was then released with "authentication
// timeout" around authTimeout (3 seconds in the test service) later, and the
// close of the connection was reported as an ERROR.
func TestQUICXConnectionCloseCancelsPendingStreams(t *testing.T) {
	ctx := context.Background()
	testLogger := &quicxTestLogger{Logger: logger.NOP()}
	server := startQUICXTestServerWithLogger(t, ctx, []string{quicxTestPassword}, testLogger, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write(quicxTestRequestBytes(t, quicxTestDestination, []byte("ping")))
	require.NoError(t, err)

	// The server reads the request and waits for the authentication of the
	// session, which never comes.
	time.Sleep(300 * time.Millisecond)
	require.Empty(t, server.handler.userList(), "an unauthenticated session reached the handler")
	require.NoError(t, conn.CloseWithError(0, ""))

	// The pending stream is released with the real cause of the session end,
	// well before the authentication timeout of the service.
	require.Eventually(t, func() bool {
		return strings.Contains(strings.Join(testLogger.debugList(), "\n"), "handle stream request")
	}, 2*time.Second, 20*time.Millisecond, "the pending request stream was not released when the connection closed")

	// Waiting past the authentication timeout must not report the session: the
	// connection was closed, which is not an error of the service.
	time.Sleep(3 * time.Second)
	require.Empty(t, testLogger.errorList(), "the closed connection was reported as an error")
	require.Empty(t, server.handler.userList(), "an unauthenticated session reached the handler")
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXWrongPassword covers the authentication failure path: a session which
// cannot authenticate must not serve any request, must not crash the service and
// must not be reported as authenticated.
func TestQUICXWrongPassword(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticate(t, conn, "wrong-password")
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	defer stream.Close()
	request := buf.NewSize(2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination) + 4)
	defer request.Release()
	request.WriteByte(quicx.Version)
	request.WriteByte(quicx.CommandConnect)
	require.NoError(t, quicx.AddressSerializer.WriteAddrPort(request, quicxTestDestination))
	request.Write([]byte("ping"))
	_, err = stream.Write(request.Bytes())
	require.NoError(t, err)
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
	response := make([]byte, 4)
	_, err = io.ReadFull(stream, response)
	require.Error(t, err, "an unauthenticated session served a request")
	require.Empty(t, server.handler.userList(), "an unauthenticated session reached the handler")
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXReplayedAuthentication covers a replayed 0-RTT flight: an attacker
// who captured a client's early data can send it to the server again, and the
// transport cannot tell the copy from the original. The replayed authentication
// presents the nonce of the session it was captured from, so the server must
// reject it instead of authenticating the session and dialing the destination
// of the CONNECT request the flight carries.
func TestQUICXReplayedAuthentication(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	nonce := quicxTestNonce(0x42)

	// The original session: its nonce is what the server remembers.
	original := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticateNonce(t, original, quicxTestPassword, nonce)
	rawQUICXEcho(t, original, []byte("ping"))
	require.Equal(t, []int{0}, server.handler.userList())

	// The replayed flight: both streams are opened before the authentication is
	// sent, because the server may already have closed the session by the time
	// the request is written. A failed write is fine: a session the server
	// closed cannot reach the destination either way.
	replay := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	replayStream, err := replay.OpenStream()
	require.NoError(t, err)
	rawQUICXAuthenticateNonce(t, replay, quicxTestPassword, nonce)
	request := buf.NewSize(2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination) + 4)
	request.WriteByte(quicx.Version)
	request.WriteByte(quicx.CommandConnect)
	require.NoError(t, quicx.AddressSerializer.WriteAddrPort(request, quicxTestDestination))
	request.Write([]byte("pong"))
	_, _ = replayStream.Write(request.Bytes())
	request.Release()

	require.Eventually(t, func() bool {
		return quicxConnectionClosed(replay)
	}, 5*time.Second, 50*time.Millisecond, "the replayed authentication was accepted")
	require.Equal(t, []int{0}, server.handler.userList(), "the replayed session reached the handler")
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXNormalCloseLogsNoError covers a session which ends because the peer
// closed the connection: the real reason must be preserved and reported below
// the error level, instead of replacing it with "connection closed" and logging
// every close as a failure.
func TestQUICXNormalCloseLogsNoError(t *testing.T) {
	ctx := context.Background()
	testLogger := &quicxTestLogger{Logger: logger.NOP()}
	server := startQUICXTestServerWithLogger(t, ctx, []string{quicxTestPassword}, testLogger, nil)
	client, _ := newQUICXTestClient(t, ctx, server.address, quicxTestPassword, nil)
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, conn, []byte("ping"))
	require.NoError(t, conn.Close())
	client.CloseWithError(os.ErrClosed)
	// Give the service time to observe the closed connection.
	time.Sleep(500 * time.Millisecond)
	require.Empty(t, testLogger.errorList(), "a normal close was reported as an error")
}

// TestQUICXServiceCloseClosesConnections covers the shutdown of an inbound
// whose context outlives it, which is how a sing-box instance closes its
// inbounds: closing a quic-go listener leaves the connections it accepted
// running, so the service has to close them itself. Otherwise an established
// session lingers until its idle timeout and, once the inbound released the
// UDP socket, never even sees the peer's CONNECTION_CLOSE.
func TestQUICXServiceCloseClosesConnections(t *testing.T) {
	ctx := context.Background()
	testLogger := &quicxTestLogger{Logger: logger.NOP()}
	server := startQUICXTestServerWithLogger(t, ctx, []string{quicxTestPassword}, testLogger, nil)
	client, _ := newQUICXTestClient(t, ctx, server.address, quicxTestPassword, nil)
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	defer conn.Close()
	quicxEchoConn(t, conn, []byte("ping"))

	require.NoError(t, server.service.Close())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the service left the connection open after Close")
	require.Empty(t, testLogger.errorList(), "closing the service was reported as an error")
}

// TestQUICXAbandonedDialKeepsSession covers the client half of the reconnect
// storm: DialConn used to open the request stream right away, so a connection
// which was abandoned before its first byte (a canceled dial, a failed handshake
// report) closed an empty stream. The server cannot tell such a stream from a
// standard HTTP/3 request and ended the whole session for it, which killed
// every other connection of the client and made them reconnect into the same
// state. The stream is created on the first read or write now.
func TestQUICXAbandonedDialKeepsSession(t *testing.T) {
	ctx := context.Background()
	testLogger := &quicxTestLogger{Logger: logger.NOP()}
	server := startQUICXTestServerWithLogger(t, ctx, []string{quicxTestPassword}, testLogger, nil)
	dialer := &quicxTestCountingDialer{}
	client, _ := newQUICXTestClientWithDialer(t, ctx, server.address, quicxTestPassword, dialer, nil)

	healthy, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	quicxEchoConn(t, healthy, []byte("ping"))
	require.Equal(t, []int{0}, server.handler.userList(), "the first connection was not served")
	require.Equal(t, int64(1), dialer.dials.Load(), "expected exactly one QUIC connection")

	// The abandoned dial: no byte is ever written and the application closes
	// the connection.
	abandoned, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	require.True(t, N.NeedHandshakeForWrite(abandoned), "the connection wrote its request before anything was sent")
	require.NoError(t, abandoned.Close())

	time.Sleep(time.Second)
	t.Logf("server error log after an abandoned dial: %v", testLogger.errorList())
	// The abandoned connection must not have sent a request stream, so the
	// session must be untouched: the healthy connection keeps working and the
	// client does not have to redial.
	require.Empty(t, testLogger.errorList(), "an abandoned dial ended the session")
	require.Equal(t, []int{0}, server.handler.userList(), "an abandoned dial served a request")
	quicxEchoConn(t, healthy, []byte("pong"))
	require.Equal(t, int64(1), dialer.dials.Load(), "the session was replaced after an abandoned dial")
}

// TestQUICXLazyRequestStream observes the client's streams on the wire with a
// QUIC endpoint which speaks no protocol at all: an abandoned connection must
// not open a request stream, the first write must open it with the CONNECT
// request and its payload, and a reader which never wrote must get the CONNECT
// request flushed so a server-first protocol can answer.
func TestQUICXLazyRequestStream(t *testing.T) {
	ctx := context.Background()
	endpoint := startQUICXTestRawEndpoint(t, ctx)
	client, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        &quicxTestDialer{},
		ServerAddress: endpoint.address,
		TLSConfig:     newQUICXTestClientTLS(t, ctx),
		QUICOptions:   qtls.QUICOptions{},
		Password:      quicxTestPassword,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.CloseWithError(os.ErrClosed)
	})

	// 1. A connection which is abandoned before its first byte sends nothing at
	// all, so the first request stream of the session belongs to the connection
	// which really writes one.
	abandoned, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	require.True(t, N.NeedHandshakeForWrite(abandoned), "the connection wrote its request before anything was sent")
	require.NoError(t, abandoned.Close())

	// 2. The first write carries the CONNECT request and the payload on the
	// first bidirectional stream of the session.
	payload := []byte("ping")
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	firstStream := endpoint.acceptStream(t, 10*time.Second)
	require.Equal(t, quic.StreamID(0), firstStream.StreamID(), "the abandoned dial left a request stream behind")
	requestPayloadLen := 2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination)
	require.Equal(t, quicxTestRequestBytes(t, quicxTestDestination, payload), quicxTestReadStream(t, firstStream, requestPayloadLen+len(payload)))

	// 3. A connection which only reads flushes its CONNECT request before it
	// waits for the answer, which is what a server-first protocol needs.
	banner := []byte("banner")
	serverFirst, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	require.NoError(t, serverFirst.SetReadDeadline(time.Now().Add(10*time.Second)))
	bannerResult := make(chan []byte, 1)
	bannerError := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(banner))
		_, readErr := io.ReadFull(serverFirst, buffer)
		if readErr != nil {
			bannerError <- readErr
			return
		}
		bannerResult <- buffer
	}()
	secondStream := endpoint.acceptStream(t, 10*time.Second)
	require.Equal(t, quic.StreamID(4), secondStream.StreamID())
	requestLen := 2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination)
	require.Equal(t, quicxTestRequestBytes(t, quicxTestDestination, nil), quicxTestReadStream(t, secondStream, requestLen))
	_, err = secondStream.Write(banner)
	require.NoError(t, err)
	select {
	case readErr := <-bannerError:
		require.NoError(t, readErr, "the flushed request was not answered")
	case received := <-bannerResult:
		require.Equal(t, banner, received)
	case <-time.After(10 * time.Second):
		require.Fail(t, "the reader was never answered")
	}
}

// TestQUICXStreamWriteFailureKeepsSession covers the other half of the client
// fix: a request stream which cannot be written used to close the whole QUIC
// connection, which tore down every other connection multiplexed on it. The
// peer stops reading the stream (STOP_SENDING) while the first write is blocked
// on the stream's flow control window, which makes that write fail.
func TestQUICXStreamWriteFailureKeepsSession(t *testing.T) {
	ctx := context.Background()
	endpoint := startQUICXTestRawEndpointWithWindow(t, ctx, 16<<10)
	dialer := &quicxTestCountingDialer{}
	client, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        dialer,
		ServerAddress: endpoint.address,
		TLSConfig:     newQUICXTestClientTLS(t, ctx),
		QUICOptions:   qtls.QUICOptions{},
		Password:      quicxTestPassword,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.CloseWithError(os.ErrClosed)
	})

	// The write is larger than the whole stream window of the peer, so it can
	// only complete if the peer reads it.
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(bytes.Repeat([]byte{0x42}, 1<<20))
		writeResult <- writeErr
	}()
	failedStream := endpoint.acceptStream(t, 10*time.Second)
	failedStream.CancelRead(0)
	failedStream.CancelWrite(0)
	select {
	case writeErr := <-writeResult:
		require.Error(t, writeErr, "a write the peer stopped reading succeeded")
	case <-time.After(10 * time.Second):
		require.Fail(t, "the write did not fail after the peer stopped reading")
	}

	// A failed stream must not end the session: the client keeps its QUIC
	// connection and the next request is served on it, which means the next
	// stream is a later one of the same session and no redial happened.
	again, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	_, err = again.Write([]byte("ping"))
	require.NoError(t, err)
	nextStream := endpoint.acceptStream(t, 10*time.Second)
	require.Equal(t, quic.StreamID(4), nextStream.StreamID(), "the session was replaced after one failed stream")
	require.Equal(t, int64(1), dialer.dials.Load(), "the session was replaced after one failed stream")
	require.Equal(t,
		quicxTestRequestBytes(t, quicxTestDestination, []byte("ping")),
		quicxTestReadStream(t, nextStream, 2+quicx.AddressSerializer.AddrPortLen(quicxTestDestination)+4),
	)
}

// TestQUICXBrokenRequestStreamKeepsSession covers the server half of the
// reconnect storm: a request stream the server cannot serve must only be reset.
// Ending the session for it tears down every other connection of the client at
// once, and the connections re-established while it closes produce more of the
// same stream.
func TestQUICXBrokenRequestStreamKeepsSession(t *testing.T) {
	ctx := context.Background()
	testLogger := &quicxTestLogger{Logger: logger.NOP()}
	server := startQUICXTestServerWithLogger(t, ctx, []string{quicxTestPassword}, testLogger, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticate(t, conn, quicxTestPassword)
	rawQUICXEcho(t, conn, []byte("ping"))

	// An empty stream which is closed without a request: the abandoned dial of
	// a client which still opens its streams eagerly.
	empty, err := conn.OpenStream()
	require.NoError(t, err)
	require.NoError(t, empty.Close())

	// A stream which is reset before anything was sent.
	canceled, err := conn.OpenStream()
	require.NoError(t, err)
	canceled.CancelWrite(0)
	canceled.CancelRead(0)

	// A CONNECT request which the peer truncated.
	truncated, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = truncated.Write([]byte{quicx.Version, quicx.CommandConnect})
	require.NoError(t, err)
	require.NoError(t, truncated.Close())

	// A stream which is not a QUICX request at all, on an authenticated session.
	foreign, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = foreign.Write([]byte{0x01, 0x40, 0x64, 0x00, 0x00})
	require.NoError(t, err)
	require.NoError(t, foreign.Close())

	time.Sleep(time.Second)
	t.Logf("server error log after broken request streams: %v", testLogger.errorList())
	require.Empty(t, testLogger.errorList(), "a broken request stream ended the session")
	require.False(t, quicxConnectionClosed(conn), "a broken request stream closed the session")
	// The reset streams are reported, so a recurring headerless stream can be
	// told apart from a quiet session without another investigation.
	debugLog := strings.Join(testLogger.debugList(), "\n")
	require.Contains(t, debugLog, "sent no request", "the streams without a request were not reported")
	require.Contains(t, debugLog, "is not a QUICX request", "the non-QUICX stream was not reported")
	require.Contains(t, debugLog, "read request destination", "the truncated CONNECT request was not reported")
	// The session and its other streams keep working.
	rawQUICXEcho(t, conn, []byte("pong"))
	require.Equal(t, []int{0, 0}, server.handler.userList())
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXUnauthenticatedStreamFollowsPolicy covers the masquerade which the
// stream handling must preserve: a bidirectional stream which is not a QUICX
// request on a session which never authenticated is still terminated following
// auth_failure_policy, so a probe cannot keep a session alive with it.
func TestQUICXUnauthenticatedStreamFollowsPolicy(t *testing.T) {
	ctx := context.Background()
	server := startQUICXTestServer(t, ctx, []string{quicxTestPassword}, nil)
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0x01, 0x40, 0x64, 0x00})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return quicxConnectionClosed(conn)
	}, 2*time.Second, 50*time.Millisecond, "an unauthenticated stream was not terminated by policy")
	require.Empty(t, server.handler.userList(), "an unauthenticated session reached the handler")
	requireQUICXServiceAlive(t, ctx, server)
}

// TestQUICXSilentDropReclaimsConnection covers the reclamation of a connection
// whose session was closed by auth_failure_policy silent_drop. The grace period
// is what keeps a peer sending keepalives from pinning the session resources, so
// the connection has to be reclaimed locally, and not before the grace period
// ended: anything sent earlier would turn the silent drop back into a
// protocol-identifiable close. This was the only QUICX fix without a regression
// test.
func TestQUICXSilentDropReclaimsConnection(t *testing.T) {
	const gracePeriod = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server := startQUICXTestServerWithOptions(t, ctx, []string{quicxTestPassword}, logger.NOP(), nil, nil, func(options *quicx.ServiceOptions) {
		options.AuthFailurePolicy = quicx.AuthFailurePolicySilentDrop
		options.SilentDropTimeout = gracePeriod
	})
	conn := dialRawQUICX(t, ctx, server.address, &quic.Config{EnableDatagrams: true})
	rawQUICXAuthenticate(t, conn, "wrong-password")

	// While the grace period runs the peer must observe nothing at all, which is
	// the whole point of the silent drop.
	select {
	case <-conn.Context().Done():
		t.Fatal("the silently dropped connection was closed before the grace period ended")
	case <-time.After(gracePeriod / 2):
	}

	// The reclaim closes the connection locally instead of waiting for the QUIC
	// idle timeout, which is what bounds the resources of a probe.
	select {
	case <-conn.Context().Done():
	case <-time.After(gracePeriod + 10*time.Second):
		t.Fatal("the silently dropped connection was not reclaimed after the grace period")
	}
	var applicationErr *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &applicationErr)
	require.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), applicationErr.ErrorCode)
}

// quicxTestLogger records the error level messages of a service. It formats
// every message exactly like the production logger does, so a message which the
// logger cannot format (an unsupported argument type panics format.ToString)
// fails the test instead of the service.
type quicxTestLogger struct {
	logger.Logger
	access sync.Mutex
	errors []string
	debugs []string
}

func (l *quicxTestLogger) Error(args ...any) {
	l.access.Lock()
	l.errors = append(l.errors, F.ToString(args...))
	l.access.Unlock()
}

func (l *quicxTestLogger) Debug(args ...any) {
	l.access.Lock()
	l.debugs = append(l.debugs, F.ToString(args...))
	l.access.Unlock()
}

func (l *quicxTestLogger) errorList() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string{}, l.errors...)
}

func (l *quicxTestLogger) debugList() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string{}, l.debugs...)
}

func quicxTestTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracer(ctx, isClient, connID)
}

func quicxTestNewest(t *testing.T, paths []string) string {
	t.Helper()
	var newest string
	var newestTime time.Time
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.ModTime().After(newestTime) {
			newest, newestTime = path, info.ModTime()
		}
	}
	require.NotEmpty(t, newest, "no qlog trace found")
	return newest
}

func quicxTestAnyTraceContains(t *testing.T, paths []string, content string) bool {
	t.Helper()
	for _, path := range paths {
		trace, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if bytes.Contains(trace, []byte(content)) {
			return true
		}
	}
	return false
}

// quicxTestQLOGEvent is the subset of a qlog event the tests inspect: it is
// enough to tell which stream data the client sent in a 0-RTT packet.
type quicxTestQLOGEvent struct {
	Name string `json:"name"`
	Data struct {
		Header struct {
			PacketType string `json:"packet_type"`
		} `json:"header"`
		Frames []struct {
			FrameType string  `json:"frame_type"`
			StreamID  *uint64 `json:"stream_id"`
			Offset    int64   `json:"offset"`
			Length    int64   `json:"length"`
		} `json:"frames"`
	} `json:"data"`
}

// quicxTestZeroRTTStreamBytes returns how many bytes of the given stream the
// client sent in 0-RTT packets, according to its qlog traces.
func quicxTestZeroRTTStreamBytes(t *testing.T, paths []string, streamID uint64) int64 {
	t.Helper()
	var maxEnd int64
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			line = bytes.Trim(line, "\x1e\r")
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var event quicxTestQLOGEvent
			if err = json.Unmarshal(line, &event); err != nil {
				continue
			}
			if event.Data.Header.PacketType != "0RTT" {
				continue
			}
			for _, frame := range event.Data.Frames {
				if frame.FrameType != "stream" || frame.StreamID == nil || *frame.StreamID != streamID {
					continue
				}
				if end := frame.Offset + frame.Length; end > maxEnd {
					maxEnd = end
				}
			}
		}
	}
	return maxEnd
}

// quicxTestSessionCache counts how often the installed cache is consulted.
type quicxTestSessionCache struct {
	inner  tls.ClientSessionCache
	access sync.Mutex
	gets   int
}

func (c *quicxTestSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, loaded := c.inner.Get(key)
	c.access.Lock()
	c.gets++
	c.access.Unlock()
	return session, loaded
}

func (c *quicxTestSessionCache) Put(key string, session *tls.ClientSessionState) {
	c.inner.Put(key, session)
}

// quicxTestServer is a QUICX service serving an echo handler on a random
// loopback port.
type quicxTestServer struct {
	service   *quicx.Service[int]
	tlsConfig boxTLS.ServerConfig
	address   M.Socksaddr
	handler   *quicxTestEchoHandler
}

func startQUICXTestServer(t *testing.T, ctx context.Context, passwords []string, tracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace) *quicxTestServer {
	t.Helper()
	return startQUICXTestServerWithLogger(t, ctx, passwords, logger.NOP(), tracer)
}

func startQUICXTestServerWithLogger(t *testing.T, ctx context.Context, passwords []string, serviceLogger logger.Logger, serviceTracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace) *quicxTestServer {
	t.Helper()
	return startQUICXTestServerWithPacketConn(t, ctx, passwords, serviceLogger, serviceTracer, nil)
}

// startQUICXTestServerWithPacketConn starts a service whose UDP socket is
// wrapped by wrapPacketConn, which a test uses to hold back the datagrams the
// service sends.
func startQUICXTestServerWithPacketConn(t *testing.T, ctx context.Context, passwords []string, serviceLogger logger.Logger, serviceTracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace, wrapPacketConn func(net.PacketConn) net.PacketConn) *quicxTestServer {
	t.Helper()
	return startQUICXTestServerWithOptions(t, ctx, passwords, serviceLogger, serviceTracer, wrapPacketConn, nil)
}

// startQUICXTestServerWithOptions is startQUICXTestServerWithPacketConn with a
// hook which adjusts the service options: it is how a test selects an
// authentication failure policy or shortens its silent drop grace period.
func startQUICXTestServerWithOptions(t *testing.T, ctx context.Context, passwords []string, serviceLogger logger.Logger, serviceTracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace, wrapPacketConn func(net.PacketConn) net.PacketConn, adjustOptions func(*quicx.ServiceOptions)) *quicxTestServer {
	t.Helper()
	// The service context is canceled on cleanup, which terminates the sessions
	// of connections a test did not close itself, exactly like a shutdown of the
	// owning instance does.
	ctx, cancelService := context.WithCancel(ctx)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:         true,
		CertificatePath: certPem,
		KeyPath:         keyPem,
		ALPN:            []string{"h3"},
	})
	require.NoError(t, err)
	handler := &quicxTestEchoHandler{}
	serviceOptions := quicx.ServiceOptions{
		Context:     ctx,
		Logger:      serviceLogger,
		TLSConfig:   serverTLS,
		QUICOptions: qtls.QUICOptions{},
		UDPTimeout:  5 * time.Minute,
		Handler:     handler,
		Tracer:      serviceTracer,
	}
	if adjustOptions != nil {
		adjustOptions(&serviceOptions)
	}
	service, err := quicx.NewService[int](serviceOptions)
	require.NoError(t, err)
	userList := make([]int, 0, len(passwords))
	passwordList := make([]string, 0, len(passwords))
	for index, password := range passwords {
		userList = append(userList, index)
		passwordList = append(passwordList, password)
	}
	service.UpdateUsers(userList, passwordList)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var serviceConn net.PacketConn = packetConn
	if wrapPacketConn != nil {
		serviceConn = wrapPacketConn(packetConn)
	}
	require.NoError(t, service.Start(serviceConn))
	t.Cleanup(func() {
		cancelService()
		service.Close()
		packetConn.Close()
	})
	return &quicxTestServer{
		service:   service,
		tlsConfig: serverTLS,
		address:   M.SocksaddrFromNet(packetConn.LocalAddr()),
		handler:   handler,
	}
}

// setQUICXTestTicketKey pins the TLS session ticket keys of a test server, which
// is how a restarted or re-keyed server rejects a 0-RTT attempt.
func setQUICXTestTicketKey(t *testing.T, server *quicxTestServer, seed byte) {
	t.Helper()
	stdConfig, err := server.tlsConfig.STDConfig()
	require.NoError(t, err)
	var ticketKey [32]byte
	for index := range ticketKey {
		ticketKey[index] = seed
	}
	stdConfig.SetSessionTicketKeys([][32]byte{ticketKey})
}

func newQUICXTestClientTLS(t *testing.T, ctx context.Context) boxTLS.Config {
	t.Helper()
	clientTLS, err := boxTLS.NewClient(ctx, logger.NOP(), "example.org", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
		Insecure:   true,
		ALPN:       []string{"h3"},
	})
	require.NoError(t, err)
	return clientTLS
}

func newQUICXTestClient(t *testing.T, ctx context.Context, serverAddress M.Socksaddr, password string, tracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace) (*quicx.Client, boxTLS.Config) {
	t.Helper()
	return newQUICXTestClientWithDialer(t, ctx, serverAddress, password, &quicxTestDialer{}, tracer)
}

func newQUICXTestClientWithDialer(t *testing.T, ctx context.Context, serverAddress M.Socksaddr, password string, dialer N.Dialer, tracer func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace) (*quicx.Client, boxTLS.Config) {
	t.Helper()
	clientTLS := newQUICXTestClientTLS(t, ctx)
	client, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        dialer,
		ServerAddress: serverAddress,
		TLSConfig:     clientTLS,
		QUICOptions:   qtls.QUICOptions{},
		Password:      password,
		Tracer:        tracer,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.CloseWithError(os.ErrClosed)
	})
	return client, clientTLS
}

// quicxTestRequestBytes builds the CONNECT request a client sends for
// destination, with payload as its first data.
func quicxTestRequestBytes(t *testing.T, destination M.Socksaddr, payload []byte) []byte {
	t.Helper()
	request := buf.NewSize(2 + quicx.AddressSerializer.AddrPortLen(destination) + len(payload))
	defer request.Release()
	request.WriteByte(quicx.Version)
	request.WriteByte(quicx.CommandConnect)
	require.NoError(t, quicx.AddressSerializer.WriteAddrPort(request, destination))
	request.Write(payload)
	return append([]byte{}, request.Bytes()...)
}

// quicxTestReadStream reads exactly length bytes of a request stream.
func quicxTestReadStream(t *testing.T, stream *quic.Stream, length int) []byte {
	t.Helper()
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(10*time.Second)))
	request := make([]byte, length)
	_, err := io.ReadFull(stream, request)
	require.NoError(t, err)
	return request
}

// quicxTestRawEndpoint is a QUIC endpoint which speaks no protocol at all: it
// hands every request stream a client opens to a test, which is how the client's
// streams are observed on the wire.
type quicxTestRawEndpoint struct {
	address M.Socksaddr
	streams chan *quic.Stream
}

func startQUICXTestRawEndpoint(t *testing.T, ctx context.Context) *quicxTestRawEndpoint {
	t.Helper()
	return startQUICXTestRawEndpointWithWindow(t, ctx, 0)
}

// startQUICXTestRawEndpointWithWindow starts the endpoint with a fixed stream
// receive window. A small window makes a client write which is larger than the
// window block until the test reads it.
func startQUICXTestRawEndpointWithWindow(t *testing.T, ctx context.Context, streamWindow uint64) *quicxTestRawEndpoint {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:         true,
		CertificatePath: certPem,
		KeyPath:         keyPem,
		ALPN:            []string{"h3"},
	})
	require.NoError(t, err)
	quicConfig := &quic.Config{
		EnableDatagrams:    true,
		MaxIncomingStreams: 1 << 20,
	}
	if streamWindow > 0 {
		quicConfig.InitialStreamReceiveWindow = streamWindow
		quicConfig.MaxStreamReceiveWindow = streamWindow
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	listener, err := qtls.ListenEarlyWithOptions(packetConn, serverTLS, quicConfig, qtls.ListenOptions{})
	require.NoError(t, err)
	endpoint := &quicxTestRawEndpoint{
		address: M.SocksaddrFromNet(packetConn.LocalAddr()),
		streams: make(chan *quic.Stream, 32),
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			go func(conn *quic.Conn) {
				for {
					stream, streamErr := conn.AcceptStream(ctx)
					if streamErr != nil {
						return
					}
					endpoint.streams <- stream
				}
			}(conn)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		packetConn.Close()
	})
	return endpoint
}

// acceptStream returns the next request stream the client opened.
func (e *quicxTestRawEndpoint) acceptStream(t *testing.T, timeout time.Duration) *quic.Stream {
	t.Helper()
	select {
	case stream := <-e.streams:
		return stream
	case <-time.After(timeout):
		require.FailNow(t, "the client did not open a request stream")
		return nil
	}
}

// quicxTestCountingDialer counts the QUIC connections a client opens, which is
// how a test observes that a session was replaced instead of kept.
type quicxTestCountingDialer struct {
	dials atomic.Int64
}

func (d *quicxTestCountingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "udp", destination.String())
}

func (d *quicxTestCountingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

// quicxEchoConn writes payload on conn and verifies that the echo handler sends
// it back.
func quicxEchoConn(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)
	require.NoError(t, conn.SetDeadline(time.Time{}))
}

// requireQUICXServiceAlive verifies that the service still authenticates and
// serves a new client after a malformed session was handled.
func requireQUICXServiceAlive(t *testing.T, ctx context.Context, server *quicxTestServer) {
	t.Helper()
	client, _ := newQUICXTestClient(t, ctx, server.address, quicxTestPassword, nil)
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	defer conn.Close()
	quicxEchoConn(t, conn, []byte("alive"))
}

// dialRawQUICX establishes a raw QUIC connection to a test service, which allows
// the tests to speak the QUICX wire protocol directly.
func dialRawQUICX(t *testing.T, ctx context.Context, serverAddress M.Socksaddr, quicConfig *quic.Config) *quic.Conn {
	t.Helper()
	clientTLS := newQUICXTestClientTLS(t, ctx)
	udpConn, err := net.Dial("udp", serverAddress.String())
	require.NoError(t, err)
	conn, err := qtls.DialEarly(ctx, udpConn, clientTLS, quicConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.CloseWithError(0, "")
		udpConn.Close()
	})
	return conn
}

// quicxTestNonce returns a deterministic authentication nonce. The raw protocol
// tests use it when two connections have to present the same one, which is what
// a replayed 0-RTT flight does.
func quicxTestNonce(seed byte) [quicx.AuthNonceLen]byte {
	var nonce [quicx.AuthNonceLen]byte
	for index := range nonce {
		nonce[index] = seed
	}
	return nonce
}

func rawQUICXAuthenticate(t *testing.T, conn *quic.Conn, password string) {
	t.Helper()
	var nonce [quicx.AuthNonceLen]byte
	_, err := rand.Read(nonce[:])
	require.NoError(t, err)
	rawQUICXAuthenticateNonce(t, conn, password, nonce)
}

// rawQUICXAuthenticateNonce sends an authentication request with an explicit
// nonce, which is how a test presents the nonce of another session.
func rawQUICXAuthenticateNonce(t *testing.T, conn *quic.Conn, password string, nonce [quicx.AuthNonceLen]byte) {
	t.Helper()
	stream, err := conn.OpenUniStream()
	require.NoError(t, err)
	authRequest := make([]byte, 4+len(password)+quicx.AuthNonceLen)
	authRequest[0] = quicx.Version
	authRequest[1] = quicx.CommandAuthenticate
	binary.BigEndian.PutUint16(authRequest[2:4], uint16(len(password)))
	copy(authRequest[4:], password)
	copy(authRequest[4+len(password):], nonce[:])
	_, err = stream.Write(authRequest)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
}

// rawQUICXEcho opens a CONNECT stream, sends payload and verifies the echo.
func rawQUICXEcho(t *testing.T, conn *quic.Conn, payload []byte) {
	t.Helper()
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	defer stream.Close()
	request := buf.NewSize(2 + quicx.AddressSerializer.AddrPortLen(quicxTestDestination) + len(payload))
	defer request.Release()
	request.WriteByte(quicx.Version)
	request.WriteByte(quicx.CommandConnect)
	require.NoError(t, quicx.AddressSerializer.WriteAddrPort(request, quicxTestDestination))
	request.Write(payload)
	_, err = stream.Write(request.Bytes())
	require.NoError(t, err)
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(10*time.Second)))
	response := make([]byte, len(payload))
	_, err = io.ReadFull(stream, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)
}

// rawQUICXSendUDPMessage sends a single UDP message frame, optionally as one
// fragment of a larger message.
func rawQUICXSendUDPMessage(t *testing.T, conn *quic.Conn, sessionID uint16, packetID uint16, fragmentTotal uint8, fragmentID uint8, data []byte) {
	t.Helper()
	rawQUICXSendUDPMessageTo(t, conn, sessionID, packetID, fragmentTotal, fragmentID, M.ParseSocksaddrHostPort("127.0.0.1", 53), data)
}

// rawQUICXSendUDPMessageTo sends a single UDP message frame with an explicit
// destination, which a test uses to send a message without one, as the tail
// fragments of the protocol before the destination was repeated in every
// fragment looked on the wire.
func rawQUICXSendUDPMessageTo(t *testing.T, conn *quic.Conn, sessionID uint16, packetID uint16, fragmentTotal uint8, fragmentID uint8, destination M.Socksaddr, data []byte) {
	t.Helper()
	message := buf.NewSize(2 + 10 + quicx.AddressSerializer.AddrPortLen(destination) + len(data))
	defer message.Release()
	message.WriteByte(quicx.Version)
	message.WriteByte(quicx.CommandPacket)
	_ = binary.Write(message, binary.BigEndian, sessionID)
	_ = binary.Write(message, binary.BigEndian, packetID)
	message.WriteByte(fragmentTotal)
	message.WriteByte(fragmentID)
	_ = binary.Write(message, binary.BigEndian, uint16(len(data)))
	require.NoError(t, quicx.AddressSerializer.WriteAddrPort(message, destination))
	message.Write(data)
	require.NoError(t, conn.SendDatagram(message.Bytes()))
}

type quicxTestDialer struct{}

func (d *quicxTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", destination.String())
}

func (d *quicxTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

// quicxTestGatePacketConn holds back the datagrams the service sends while it
// is armed. A test uses it to keep a client handshake pending, which makes the
// client's first request deterministically part of its 0-RTT flight.
type quicxTestGatePacketConn struct {
	net.PacketConn
	access sync.Mutex
	gate   chan struct{}
}

func (c *quicxTestGatePacketConn) arm() {
	c.access.Lock()
	if c.gate == nil {
		c.gate = make(chan struct{})
	}
	c.access.Unlock()
}

func (c *quicxTestGatePacketConn) release() {
	c.access.Lock()
	if c.gate != nil {
		close(c.gate)
		c.gate = nil
	}
	c.access.Unlock()
}

func (c *quicxTestGatePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	gate := c.gate
	c.access.Unlock()
	if gate != nil {
		<-gate
	}
	return c.PacketConn.WriteTo(p, addr)
}

// quicxTestEchoHandler serves the requests of the tests: TCP streams are echoed
// back and UDP packets are sent back to their source. It records the
// authenticated user and the destination of every accepted connection, which is
// the destination the service routed (and created) its session with.
type quicxTestEchoHandler struct {
	access         sync.Mutex
	users          []int
	packetTargets  []M.Socksaddr
	udpPackets     atomic.Int64
	udpWriteErrors atomic.Int64
}

func (h *quicxTestEchoHandler) recordUser(ctx context.Context) {
	userID, _ := auth.UserFromContext[int](ctx)
	h.access.Lock()
	h.users = append(h.users, userID)
	h.access.Unlock()
}

func (h *quicxTestEchoHandler) userList() []int {
	h.access.Lock()
	defer h.access.Unlock()
	return append([]int{}, h.users...)
}

func (h *quicxTestEchoHandler) recordPacketTarget(destination M.Socksaddr) {
	h.access.Lock()
	h.packetTargets = append(h.packetTargets, destination)
	h.access.Unlock()
}

func (h *quicxTestEchoHandler) packetTargetList() []M.Socksaddr {
	h.access.Lock()
	defer h.access.Unlock()
	return append([]M.Socksaddr{}, h.packetTargets...)
}

func (h *quicxTestEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.recordUser(ctx)
	go func() {
		defer closeQUICXTestConnection(conn, onClose)
		buffer := make([]byte, 4096)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				if _, err = conn.Write(buffer[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (h *quicxTestEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.recordUser(ctx)
	h.recordPacketTarget(destination)
	go func() {
		defer closeQUICXTestConnection(conn, onClose)
		for {
			buffer := buf.New()
			packetDestination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			h.udpPackets.Add(1)
			// WritePacket takes ownership of the buffer.
			if err = conn.WritePacket(buffer, packetDestination); err != nil {
				h.udpWriteErrors.Add(1)
				return
			}
		}
	}()
}

// closeQUICXTestConnection closes the connection of a test handler. The QUICX
// service passes a nil callback when it serves the connection itself.
func closeQUICXTestConnection(conn io.Closer, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		onClose(nil)
	}
	conn.Close()
}
