package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/dialgate"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// TestNowherePortalLoopback is the H3 gate.
// Matrices: mixed-in → nowhere-out → nowhere-in → direct
func TestNowherePortalLoopback(t *testing.T) {
	t.Run("tcp-tcp", func(t *testing.T) {
		testNowhereMatrix(t, "tcp", "tcp", option.NetworkList(N.NetworkTCP), "", testTCP)
	})
	t.Run("udp-udp", func(t *testing.T) {
		// Compact QUIC DATAGRAM payload is MTU-bound (~1200); avoid 1500/4096 large-UDP suits.
		testNowhereMatrix(t, "udp", "udp", option.NetworkList(N.NetworkUDP), "", testNowhereUDPUDP)
	})
	t.Run("tcp-udp", func(t *testing.T) {
		testNowhereMatrix(t, "tcp", "udp", option.NetworkList(N.NetworkTCP+"\n"+N.NetworkUDP), "", testNowhereUDPUDP)
	})
	t.Run("udp-tcp", func(t *testing.T) {
		testNowhereMatrix(t, "udp", "tcp", option.NetworkList(N.NetworkTCP+"\n"+N.NetworkUDP), "", testNowhereUDPUDP)
	})
}

func TestNowhereQUICCongestionControl(t *testing.T) {
	for _, congestionControl := range []string{"bbr", "bbr_standard", "bbr2", "bbr2_variant", "cubic", "reno"} {
		t.Run(congestionControl, func(t *testing.T) {
			testNowhereMatrix(t, "udp", "udp", option.NetworkList(N.NetworkUDP), congestionControl, testNowhereBasicTCPUDP)
		})
	}
}

func TestNowhereAuthenticationFailures(t *testing.T) {
	t.Run("wrong-password-tcp", func(t *testing.T) {
		startNowhereInstance(t, "tcp", "tcp", option.NetworkList(N.NetworkTCP), "", "server-secret", "client-secret")
		expectNowhereDialFailure(t)
	})
}

func TestNowhereQUICInterfaceUpdate(t *testing.T) {
	instance := startNowhereInstance(t, "udp", "udp", option.NetworkList(N.NetworkUDP), "", "nowhere-h3-secret", "nowhere-h3-secret")
	testNowhereBasicTCPUDP(t, clientPort, testPort)

	inbound, loaded := instance.Inbound().Get("nowhere-in")
	require.True(t, loaded)
	inbound.(adapter.InterfaceUpdateListener).InterfaceUpdated(context.Background())
	outbound, loaded := instance.Outbound().Outbound("nowhere-out")
	require.True(t, loaded)
	outbound.(adapter.InterfaceUpdateListener).InterfaceUpdated(context.Background())

	testNowhereBasicTCPUDP(t, clientPort, testPort)
}

func TestNowhereServiceRestart(t *testing.T) {
	first := startNowhereInstance(t, "udp", "udp", option.NetworkList(N.NetworkUDP), "", "nowhere-h3-secret", "nowhere-h3-secret")
	testNowhereBasicTCPUDP(t, clientPort, testPort)
	require.NoError(t, first.Close())

	startNowhereInstance(t, "udp", "udp", option.NetworkList(N.NetworkUDP), "", "nowhere-h3-secret", "nowhere-h3-secret")
	testNowhereBasicTCPUDP(t, clientPort, testPort)
}

func TestNowhereServerRestartReusesOutbound(t *testing.T) {
	const restartIdleTimeout = time.Second
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	destination := startNowhereLifecycleEcho(t, 1)
	serverBox := startNowhereServerBox(t, certPem, keyPem)
	clientBox := startNowhereClientBoxWithQUICOptions(t, certPem, option.QUICOptions{
		HTTP2Options: option.HTTP2Options{
			IdleTimeout: badoption.Duration(restartIdleTimeout),
		},
	})
	outbound := nowhereLifecycleOutbound(t, clientBox)

	baselineCtx, baselineCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer baselineCancel()
	oldUDPFlow, err := outbound.ListenPacket(baselineCtx, destination)
	require.NoError(t, err)
	t.Cleanup(func() { _ = oldUDPFlow.Close() })
	require.NoError(t, roundTripNowhereLifecycleUDP(baselineCtx, oldUDPFlow, destination, []byte("old!")))
	require.NoError(t, oldUDPFlow.SetDeadline(time.Time{}))

	serverCloseDone := make(chan error, 1)
	go func() { serverCloseDone <- serverBox.Close() }()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	select {
	case closeErr := <-serverCloseDone:
		require.NoError(t, closeErr)
	case <-shutdownCtx.Done():
		t.Fatal("server did not stop within shutdown deadline")
	}

	// CONNECTION_CLOSE can be lost over UDP. Wait for the test-bounded local
	// idle timeout to retire the old physical session before reusing the outbound;
	// this avoids treating a lossy remote close packet as synchronization.
	oldFlowTerminal := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, _, readErr := oldUDPFlow.ReadFrom(buffer)
		oldFlowTerminal <- readErr
	}()
	select {
	case terminalErr := <-oldFlowTerminal:
		require.Error(t, terminalErr)
	case <-time.After(4 * restartIdleTimeout):
		_ = oldUDPFlow.Close()
		t.Fatal("old QUIC session did not reach a terminal state within idle deadline")
	}
	_ = oldUDPFlow.Close()

	// Restart only the server on the same configured port. The client Box and
	// its outbound remain untouched; fresh TCP and UDP flows must recover.
	startNowhereServerBox(t, certPem, keyPem)
	require.Same(t, outbound, nowhereLifecycleOutbound(t, clientBox))
	requireNowhereLifecycleTCPUDP(t, outbound, destination, 5*time.Second)
}

func TestNowhereDelayedServerStartConcurrentRecovery(t *testing.T) {
	const flowCount = 8
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	destination := startNowhereLifecycleEcho(t, flowCount/2+1)
	serverAddress := M.ParseSocksaddrHostPort("127.0.0.1", serverPort).String()
	blackhole, err := net.ListenPacket(N.NetworkUDP, serverAddress)
	require.NoError(t, err)
	blackholeOpen := true
	t.Cleanup(func() {
		if blackholeOpen {
			_ = blackhole.Close()
		}
	})

	clientBox := startNowhereClientBox(t, certPem)
	outbound := nowhereLifecycleOutbound(t, clientBox)

	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer recoveryCancel()
	release := make(chan struct{})
	entered := make(chan struct{}, flowCount)
	results := make(chan error, flowCount)
	runFlow := func(index int) error {
		payload := []byte(fmt.Sprintf("%04d", index))
		flow := runNowhereLifecycleTCPFlow
		network := "TCP"
		if index%2 != 0 {
			flow = runNowhereLifecycleUDPFlow
			network = "UDP"
		}
		for {
			flowErr := flow(recoveryCtx, outbound, destination, payload)
			if flowErr == nil {
				return nil
			}
			// Closing the blackhole before binding the real listener creates a
			// narrow UDP port handoff. Retry only errors covered by the shared dial
			// backoff policy; ClassOther still makes the AlwaysCoalesce regression
			// fail immediately.
			if dialgate.Classify(flowErr) != dialgate.ClassRetryable {
				return fmt.Errorf("%s flow %d: %w", network, index, flowErr)
			}
			select {
			case <-recoveryCtx.Done():
				return fmt.Errorf("%s flow %d: %w", network, index, flowErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	for index := 0; index < flowCount; index++ {
		index := index
		go func() {
			<-release
			entered <- struct{}{}
			results <- runFlow(index)
		}()
	}
	close(release)
	for index := 0; index < flowCount; index++ {
		select {
		case <-entered:
		case <-recoveryCtx.Done():
			t.Fatalf("only %d/%d delayed flows entered before deadline", index, flowCount)
		}
	}

	// The local blackhole proves at least one QUIC attempt happened while the
	// real server was absent, without an external endpoint or a fixed sleep.
	require.NoError(t, blackhole.SetReadDeadline(time.Now().Add(2*time.Second)))
	probe := make([]byte, 2048)
	n, _, err := blackhole.ReadFrom(probe)
	require.NoError(t, err)
	require.Positive(t, n)
	require.NoError(t, blackhole.Close())
	blackholeOpen = false

	startNowhereServerBox(t, certPem, keyPem)
	for completed := 0; completed < flowCount; completed++ {
		select {
		case flowErr := <-results:
			require.NoError(t, flowErr, "delayed flow %d/%d failed", completed+1, flowCount)
		case <-recoveryCtx.Done():
			t.Fatalf("only %d/%d delayed flows recovered before deadline", completed, flowCount)
		}
	}
	require.Same(t, outbound, nowhereLifecycleOutbound(t, clientBox))
	requireNowhereLifecycleTCPUDP(t, outbound, destination, 5*time.Second)
}

func nowhereLifecycleOutbound(t *testing.T, clientBox *box.Box) adapter.Outbound {
	t.Helper()
	outbound, loaded := clientBox.Outbound().Outbound("nowhere-out")
	require.True(t, loaded)
	return outbound
}

func requireNowhereLifecycleTCPUDP(t *testing.T, dialer N.Dialer, destination M.Socksaddr, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	require.NoError(t, runNowhereLifecycleTCPFlow(ctx, dialer, destination, []byte("tcp!")), "fresh TCP flow")
	require.NoError(t, runNowhereLifecycleUDPFlow(ctx, dialer, destination, []byte("udp!")), "fresh UDP flow")
}

func runNowhereLifecycleTCPFlow(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, payload []byte) error {
	deadline, loaded := ctx.Deadline()
	if !loaded {
		return errors.New("nowhere lifecycle TCP flow requires a deadline")
	}
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return fmt.Errorf("dial TCP flow: %w", err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set TCP flow deadline: %w", err)
	}
	written, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write TCP flow: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("write TCP flow: wrote %d bytes, want %d", written, len(payload))
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read TCP flow: %w", err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("unexpected TCP response %q", response)
	}
	return nil
}

func runNowhereLifecycleUDPFlow(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, payload []byte) error {
	packetConn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		return fmt.Errorf("open UDP flow: %w", err)
	}
	defer packetConn.Close()
	return roundTripNowhereLifecycleUDP(ctx, packetConn, destination, payload)
}

func roundTripNowhereLifecycleUDP(ctx context.Context, packetConn net.PacketConn, destination M.Socksaddr, payload []byte) error {
	deadline, loaded := ctx.Deadline()
	if !loaded {
		return errors.New("nowhere lifecycle UDP flow requires a deadline")
	}
	if err := packetConn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set UDP flow deadline: %w", err)
	}
	written, err := packetConn.WriteTo(payload, destination.UDPAddr())
	if err != nil {
		return fmt.Errorf("write UDP flow: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("write UDP flow: wrote %d bytes, want %d", written, len(payload))
	}
	response := make([]byte, len(payload)+1)
	n, _, err := packetConn.ReadFrom(response)
	if err != nil {
		return fmt.Errorf("read UDP flow: %w", err)
	}
	if !bytes.Equal(response[:n], payload) {
		return fmt.Errorf("unexpected UDP response %q", response[:n])
	}
	return nil
}

func startNowhereLifecycleEcho(t *testing.T, tcpFlowCount int) M.Socksaddr {
	t.Helper()
	tcpListener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddress := tcpListener.Addr().(*net.TCPAddr)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddress.Port))
	udpListener, err := net.ListenPacket(N.NetworkUDP, address)
	if err != nil {
		_ = tcpListener.Close()
		require.NoError(t, err)
	}

	serverErrors := make(chan error, 2)
	tcpStop := make(chan struct{})
	udpStop := make(chan struct{})
	go serveNowhereTCPEcho(tcpListener, tcpFlowCount, tcpStop, serverErrors)
	go serveNowhereUDPEcho(udpListener, udpStop, serverErrors)
	t.Cleanup(func() {
		close(tcpStop)
		_ = tcpListener.Close()
		close(udpStop)
		_ = udpListener.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		for completed := 0; completed < 2; completed++ {
			select {
			case serveErr := <-serverErrors:
				if serveErr != nil {
					t.Errorf("lifecycle echo server: %v", serveErr)
				}
			case <-cleanupCtx.Done():
				t.Errorf("only %d/2 lifecycle echo listeners stopped", completed)
				return
			}
		}
	})
	return M.ParseSocksaddr(address)
}

func TestNowhereConcurrentQUICFlows(t *testing.T) {
	instance := startNowhereInstance(t, "udp", "udp", option.NetworkList(N.NetworkUDP), "", "nowhere-h3-secret", "nowhere-h3-secret")
	outbound, loaded := instance.Outbound().Outbound("nowhere-out")
	require.True(t, loaded)
	testNowhereConcurrentTCPUDP(t, outbound, 32)
}

// TestNowhereTCPQUICCanceledFlowChurn verifies that a fresh flow can still
// connect and read a complete response after repeated canceled flows.
func TestNowhereTCPQUICCanceledFlowChurn(t *testing.T) {
	const (
		canceledFlowCount = 8
		responseSize      = 512 * 1024
		sentinelMarker    = byte(0xff)
		handlerTimeout    = 8 * time.Second
	)
	response := bytes.Repeat([]byte{0x5a}, responseSize)
	var outboundQUICOptions option.QUICOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"stream_receive_window": "256 KB",
		"connection_receive_window": "1 MB"
	}`), &outboundQUICOptions))
	require.Equal(t, uint64(256*1024), outboundQUICOptions.StreamReceiveWindow.Value())
	require.Equal(t, uint64(1024*1024), outboundQUICOptions.ConnectionReceiveWindow.Value())
	instance := startNowhereInstanceWithQUICOptions(
		t,
		"tcp",
		"udp",
		option.NetworkList(N.NetworkTCP+"\n"+N.NetworkUDP),
		"",
		"nowhere-h3-secret",
		"nowhere-h3-secret",
		outboundQUICOptions,
	)
	outbound, loaded := instance.Outbound().Outbound("nowhere-out")
	require.True(t, loaded)

	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddress := listener.Addr().(*net.TCPAddr)
	destination := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpAddress.Port))

	type handlerResult struct {
		marker int
		err    error
	}
	type serverResult struct {
		accepted int
		err      error
	}
	type serverState struct {
		mu                sync.Mutex
		shuttingDown      bool
		activeConnections map[net.Conn]struct{}
	}

	canceledReady := make(chan byte, canceledFlowCount)
	writerFinished := make(chan byte, canceledFlowCount)
	startWriters := make(chan struct{})
	stopServer := make(chan struct{})
	handlerResults := make(chan handlerResult, canceledFlowCount+1)
	acceptDone := make(chan struct{})
	serverDone := make(chan serverResult, 1)
	var startWritersOnce sync.Once
	var stopServerOnce sync.Once
	state := serverState{activeConnections: make(map[net.Conn]struct{})}

	go func() {
		var handlers sync.WaitGroup
		result := serverResult{}
		for result.accepted < canceledFlowCount+1 {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				state.mu.Lock()
				shuttingDown := state.shuttingDown
				state.mu.Unlock()
				if !shuttingDown {
					result.err = acceptErr
				}
				break
			}
			state.mu.Lock()
			if state.shuttingDown {
				state.mu.Unlock()
				if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					result.err = fmt.Errorf("close connection accepted during shutdown: %w", closeErr)
				}
				break
			}
			state.activeConnections[conn] = struct{}{}
			state.mu.Unlock()
			result.accepted++
			handlers.Add(1)
			go func(conn net.Conn) {
				defer handlers.Done()
				flowResult := handlerResult{marker: -1}
				defer func() {
					if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && flowResult.err == nil {
						flowResult.err = fmt.Errorf("close handler connection: %w", closeErr)
					}
					state.mu.Lock()
					delete(state.activeConnections, conn)
					state.mu.Unlock()
					handlerResults <- flowResult
				}()
				if deadlineErr := conn.SetDeadline(time.Now().Add(handlerTimeout)); deadlineErr != nil {
					flowResult.err = fmt.Errorf("set handler deadline: %w", deadlineErr)
					return
				}
				request := []byte{0}
				if _, readErr := io.ReadFull(conn, request); readErr != nil {
					flowResult.err = fmt.Errorf("read request marker: %w", readErr)
					return
				}
				flowResult.marker = int(request[0])
				if request[0] != sentinelMarker {
					select {
					case canceledReady <- request[0]:
					case <-stopServer:
						flowResult.err = errors.New("server stopped before canceled-flow barrier")
						return
					}
					select {
					case <-startWriters:
					case <-stopServer:
						flowResult.err = errors.New("server stopped before canceled-flow write")
						return
					}
				}
				written, writeErr := io.Copy(conn, bytes.NewReader(response))
				if request[0] != sentinelMarker {
					select {
					case writerFinished <- request[0]:
					case <-stopServer:
						flowResult.err = errors.New("server stopped while finishing canceled-flow write")
						return
					}
				}
				if writeErr != nil {
					flowResult.err = fmt.Errorf("write response for marker %d: %w", request[0], writeErr)
					return
				}
				if written != int64(len(response)) {
					flowResult.err = fmt.Errorf("write response for marker %d: wrote %d bytes, want %d", request[0], written, len(response))
				}
			}(conn)
		}
		close(acceptDone)
		handlers.Wait()
		close(handlerResults)
		serverDone <- result
	}()

	serverJoined := false
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), handlerTimeout)
		defer cleanupCancel()

		state.mu.Lock()
		state.shuttingDown = true
		state.mu.Unlock()
		stopServerOnce.Do(func() { close(stopServer) })
		startWritersOnce.Do(func() { close(startWriters) })
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", closeErr)
		}
		select {
		case <-acceptDone:
		case <-cleanupContext.Done():
			t.Errorf("TCP accept loop did not stop within handler deadline")
		}

		state.mu.Lock()
		if !state.shuttingDown {
			t.Error("TCP server shutdown state was cleared before cleanup")
		}
		connections := make([]net.Conn, 0, len(state.activeConnections))
		for conn := range state.activeConnections {
			connections = append(connections, conn)
		}
		state.mu.Unlock()
		for _, conn := range connections {
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Errorf("close active handler connection: %v", closeErr)
			}
		}
		if !serverJoined {
			select {
			case <-serverDone:
			case <-cleanupContext.Done():
				t.Errorf("TCP handlers did not stop within handler deadline")
			}
		}
	}()

	closeFlow := func(conn net.Conn, stage string) {
		t.Helper()
		if closeErr := conn.Close(); closeErr != nil {
			require.ErrorContains(t, closeErr, "close called for canceled stream", stage)
		}
	}
	for index := 0; index < canceledFlowCount; index++ {
		func(index int) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			conn, dialErr := outbound.DialContext(ctx, N.NetworkTCP, destination)
			if conn != nil {
				defer closeFlow(conn, fmt.Sprintf("close canceled flow %d", index))
			}
			cancel()
			require.NoError(t, dialErr, "dial canceled flow %d", index)
			require.NotNil(t, conn, "dial canceled flow %d returned a nil connection", index)
			require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)), "set canceled flow %d deadline", index)
			written, writeErr := conn.Write([]byte{byte(index)})
			require.NoError(t, writeErr, "write canceled flow %d marker", index)
			require.Equal(t, 1, written, "write canceled flow %d marker length", index)
		}(index)
	}
	waitNowhereFlowMarkers(t, canceledReady, canceledFlowCount, 3*time.Second, "canceled handlers ready")
	startWritersOnce.Do(func() { close(startWriters) })
	waitNowhereFlowMarkers(t, writerFinished, canceledFlowCount, 3*time.Second, "canceled writers finished")

	func() {
		sentinelContext, sentinelCancel := context.WithTimeout(context.Background(), 3*time.Second)
		sentinel, dialErr := outbound.DialContext(sentinelContext, N.NetworkTCP, destination)
		if sentinel != nil {
			defer closeFlow(sentinel, "close sentinel flow")
		}
		sentinelCancel()
		require.NoError(t, dialErr)
		require.NotNil(t, sentinel, "dial sentinel flow returned a nil connection")
		require.NoError(t, sentinel.SetDeadline(time.Now().Add(3*time.Second)))
		written, writeErr := sentinel.Write([]byte{sentinelMarker})
		require.NoError(t, writeErr)
		require.Equal(t, 1, written)
		received := make([]byte, len(response))
		_, readErr := io.ReadFull(sentinel, received)
		require.NoError(t, readErr)
		require.Equal(t, response, received)
	}()

	var summary serverResult
	select {
	case summary = <-serverDone:
		serverJoined = true
	case <-time.After(handlerTimeout):
		t.Fatal("TCP server did not finish within handler deadline")
	}
	require.NoError(t, summary.err)
	require.Equal(t, canceledFlowCount+1, summary.accepted)

	seenCanceled := make(map[int]bool, canceledFlowCount)
	seenSentinel := false
	for result := range handlerResults {
		switch {
		case result.marker == int(sentinelMarker):
			require.False(t, seenSentinel, "duplicate sentinel handler result")
			seenSentinel = true
			require.NoError(t, result.err)
		case result.marker >= 0 && result.marker < canceledFlowCount:
			require.False(t, seenCanceled[result.marker], "duplicate canceled handler result %d", result.marker)
			seenCanceled[result.marker] = true
			if result.err != nil {
				t.Logf("canceled handler %d stopped with expected write-side error: %v", result.marker, result.err)
			}
		default:
			t.Errorf("unexpected handler result marker %d: %v", result.marker, result.err)
		}
	}
	require.True(t, seenSentinel)
	require.Len(t, seenCanceled, canceledFlowCount)
}

func waitNowhereFlowMarkers(t *testing.T, markers <-chan byte, count int, timeout time.Duration, stage string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	seen := make(map[byte]bool, count)
	for len(seen) < count {
		select {
		case marker := <-markers:
			require.Less(t, int(marker), count, "%s: unexpected marker", stage)
			require.False(t, seen[marker], "%s: duplicate marker %d", stage, marker)
			seen[marker] = true
		case <-deadline.C:
			t.Fatalf("%s: received %d/%d markers before deadline", stage, len(seen), count)
		}
	}
}

func TestNowhereConcurrentFourMatrixBurst(t *testing.T) {
	cases := []struct {
		name           string
		up, down       string
		inboundNetwork option.NetworkList
		tcpCount       int
		udpCount       int
	}{
		{"tcp-tcp", "tcp", "tcp", option.NetworkList(N.NetworkTCP), 128, 0},
		{"udp-udp", "udp", "udp", option.NetworkList(N.NetworkUDP), 0, 64},
		{"tcp-udp", "tcp", "udp", option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP), 128, 64},
		{"udp-tcp", "udp", "tcp", option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP), 128, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			instance := startNowhereInstance(t, tc.up, tc.down, tc.inboundNetwork, "", "nowhere-h3-secret", "nowhere-h3-secret")
			outbound, loaded := instance.Outbound().Outbound("nowhere-out")
			require.True(t, loaded)
			testNowhereConcurrentBurst(t, outbound, tc.tcpCount, tc.udpCount)
		})
	}
}

// TestNowhereStressBaseline is the H3 high-pressure regression baseline.
// Full defaults: 500 short TCP, 50 concurrent, 1000 UDP req/resp per matrix.
// -short shrinks counts; NOWHERE_H3_STRESS_SHORT / _CONCURRENT / _UDP override.
func TestNowhereStressBaseline(t *testing.T) {
	shortN := 500
	concurrent := 50
	udpN := 1000
	if testing.Short() {
		shortN = 50
		concurrent = 10
		udpN = 100
	}
	if v := os.Getenv("NOWHERE_H3_STRESS_SHORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			shortN = n
		}
	}
	if v := os.Getenv("NOWHERE_H3_STRESS_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrent = n
		}
	}
	if v := os.Getenv("NOWHERE_H3_STRESS_UDP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			udpN = n
		}
	}

	matrices := []struct {
		name           string
		up, down       string
		inboundNetwork option.NetworkList
		doTCP, doUDP   bool
	}{
		{"tcp-tcp", "tcp", "tcp", option.NetworkList(N.NetworkTCP), true, false},
		{"udp-udp", "udp", "udp", option.NetworkList(N.NetworkUDP), false, true},
		{"tcp-udp", "tcp", "udp", option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP), true, true},
		{"udp-tcp", "udp", "tcp", option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP), true, true},
	}
	for _, tc := range matrices {
		t.Run(tc.name, func(t *testing.T) {
			instance := startNowhereInstance(t, tc.up, tc.down, tc.inboundNetwork, "", "nowhere-h3-secret", "nowhere-h3-secret")
			outbound, loaded := instance.Outbound().Outbound("nowhere-out")
			require.True(t, loaded)

			if tc.doTCP {
				t.Run("short-connect", func(t *testing.T) {
					testNowhereSequentialTCP(t, outbound, shortN)
				})
				t.Run("concurrent-establish", func(t *testing.T) {
					testNowhereConcurrentBurst(t, outbound, concurrent, 0)
				})
				t.Run("sustained-stream", func(t *testing.T) {
					testNowhereSustainedTCP(t, outbound, 10)
				})
			}
			if tc.doUDP {
				t.Run("udp-reqresp", func(t *testing.T) {
					testNowhereConcurrentBurstLimited(t, outbound, 0, udpN, concurrent)
				})
			}
		})
	}
}

func testNowhereMatrix(t *testing.T, up, down string, inboundNetwork option.NetworkList, congestionControl string, suit func(*testing.T, uint16, uint16)) {
	startNowhereInstance(t, up, down, inboundNetwork, congestionControl, "nowhere-h3-secret", "nowhere-h3-secret")
	suit(t, clientPort, testPort)
}

func startNowhereInstance(
	t *testing.T,
	up, down string,
	inboundNetwork option.NetworkList,
	congestionControl string,
	inboundPassword, outboundPassword string,
) *box.Box {
	t.Helper()
	return startNowhereInstanceWithQUICOptions(t, up, down, inboundNetwork, congestionControl, inboundPassword, outboundPassword, option.QUICOptions{})
}

func startNowhereInstanceWithQUICOptions(
	t *testing.T,
	up, down string,
	inboundNetwork option.NetworkList,
	congestionControl string,
	inboundPassword, outboundPassword string,
	outboundQUICOptions option.QUICOptions,
) *box.Box {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	return startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
			{
				Type: C.TypeNowhere,
				Tag:  "nowhere-in",
				Options: &option.NowhereInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Password:              inboundPassword,
					Network:               inboundNetwork,
					QUICCongestionControl: congestionControl,
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
							ALPN:            badoption.Listable[string]{"nw2"},
							MinVersion:      "1.3",
							MaxVersion:      "1.3",
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
			{
				Type: C.TypeNowhere,
				Tag:  "nowhere-out",
				Options: &option.NowhereOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: serverPort,
					},
					Password:              outboundPassword,
					Up:                    up,
					Down:                  down,
					QUICCongestionControl: congestionControl,
					QUICOptions:           outboundQUICOptions,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							ALPN:            badoption.Listable[string]{"nw2"},
							MinVersion:      "1.3",
							MaxVersion:      "1.3",
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{"mixed-in"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "nowhere-out",
							},
						},
					},
				},
			},
		},
	})
}

func startNowhereServerBox(t *testing.T, certPem, keyPem string) *box.Box {
	t.Helper()
	return startNowhereServerBoxWithContext(t, globalCtx, certPem, keyPem, option.NetworkList(N.NetworkUDP))
}

func startNowhereServerBoxWithContext(t *testing.T, parent context.Context, certPem, keyPem string, network option.NetworkList) *box.Box {
	t.Helper()
	return startInstanceWithContext(t, parent, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeNowhere,
				Tag:  "nowhere-in",
				Options: &option.NowhereInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Password: "nowhere-h3-secret",
					Network:  network,
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
							ALPN:            badoption.Listable[string]{"nw2"},
							MinVersion:      "1.3",
							MaxVersion:      "1.3",
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect},
		},
	})
}

func startNowhereClientBox(t *testing.T, certPem string) *box.Box {
	t.Helper()
	return startNowhereClientBoxWithQUICOptions(t, certPem, option.QUICOptions{})
}

func startNowhereClientBoxWithQUICOptions(t *testing.T, certPem string, quicOptions option.QUICOptions) *box.Box {
	t.Helper()
	return startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect},
			{
				Type: C.TypeNowhere,
				Tag:  "nowhere-out",
				Options: &option.NowhereOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: serverPort,
					},
					Password:    "nowhere-h3-secret",
					Up:          "udp",
					Down:        "udp",
					QUICOptions: quicOptions,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							ALPN:            badoption.Listable[string]{"nw2"},
							MinVersion:      "1.3",
							MaxVersion:      "1.3",
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{"mixed-in"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "nowhere-out",
							},
						},
					},
				},
			},
		},
	})
}

func expectNowhereDialFailure(t *testing.T) {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		_, writeErr := conn.Write([]byte("probe"))
		if writeErr != nil {
			err = writeErr
		} else {
			buffer := make([]byte, 1)
			_, err = conn.Read(buffer)
		}
	}
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	require.GreaterOrEqual(t, time.Since(started), 3500*time.Millisecond)
}

func testNowhereConcurrentTCPUDP(t *testing.T, dialer N.Dialer, count int) {
	t.Helper()
	testNowhereConcurrentBurst(t, dialer, count, count)
}

func testNowhereSequentialTCP(t *testing.T, dialer N.Dialer, count int) {
	t.Helper()
	destination := M.ParseSocksaddrHostPort("127.0.0.1", testPort)
	listener, err := net.Listen(N.NetworkTCP, destination.String())
	require.NoError(t, err)
	defer listener.Close()
	serverErrors := make(chan error, 1)
	stop := make(chan struct{})
	go serveNowhereTCPEcho(listener, count, stop, serverErrors)
	for i := 0; i < count; i++ {
		require.NoError(t, runNowhereTCPFlow(dialer, destination), "short connect %d", i)
	}
	close(stop)
	_ = listener.Close()
	require.NoError(t, <-serverErrors)
}

func testNowhereSustainedTCP(t *testing.T, dialer N.Dialer, count int) {
	t.Helper()
	destination := M.ParseSocksaddrHostPort("127.0.0.1", testPort)
	listener, err := net.Listen(N.NetworkTCP, destination.String())
	require.NoError(t, err)
	defer listener.Close()
	serverErrors := make(chan error, 1)
	stop := make(chan struct{})
	go serveNowhereTCPBulkEcho(listener, count, stop, serverErrors)
	var wg sync.WaitGroup
	errs := make(chan error, count)
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
			if err != nil {
				errs <- fmt.Errorf("stream %d dial: %w", index, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				errs <- fmt.Errorf("stream %d write: %w", index, err)
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- fmt.Errorf("stream %d read: %w", index, err)
				return
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(stop)
	_ = listener.Close()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, <-serverErrors)
}

func serveNowhereTCPBulkEcho(listener net.Listener, count int, stop <-chan struct{}, result chan<- error) {
	var handlers sync.WaitGroup
	for index := 0; index < count; index++ {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				result <- nil
			default:
				result <- err
			}
			return
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer conn.Close()
			buffer := make([]byte, 32*1024)
			if _, err := io.ReadFull(conn, buffer); err == nil {
				_, _ = conn.Write(buffer)
			}
		}()
	}
	handlers.Wait()
	result <- nil
}

func testNowhereConcurrentBurst(t *testing.T, dialer N.Dialer, tcpCount, udpCount int) {
	t.Helper()
	testNowhereConcurrentBurstLimited(t, dialer, tcpCount, udpCount, udpCount)
}

func testNowhereConcurrentBurstLimited(t *testing.T, dialer N.Dialer, tcpCount, udpCount, udpConcurrent int) {
	t.Helper()
	address := M.ParseSocksaddrHostPort("127.0.0.1", testPort).String()
	var tcpListener net.Listener
	var udpListener net.PacketConn
	var err error
	serverErrors := make(chan error, 2)
	tcpStop := make(chan struct{})
	udpStop := make(chan struct{})
	expectedServers := 0
	if tcpCount > 0 {
		tcpListener, err = net.Listen(N.NetworkTCP, address)
		require.NoError(t, err)
		defer tcpListener.Close()
		expectedServers++
		go serveNowhereTCPEcho(tcpListener, tcpCount, tcpStop, serverErrors)
	}
	if udpCount > 0 {
		udpListener, err = net.ListenPacket(N.NetworkUDP, address)
		require.NoError(t, err)
		defer udpListener.Close()
		expectedServers++
		go serveNowhereUDPEcho(udpListener, udpStop, serverErrors)
	}

	var clients sync.WaitGroup
	clientErrors := make(chan error, tcpCount+udpCount)
	destination := M.ParseSocksaddrHostPort("127.0.0.1", testPort)
	for index := 0; index < tcpCount; index++ {
		clients.Add(1)
		go func(index int) {
			defer clients.Done()
			if err := runNowhereTCPFlow(dialer, destination); err != nil {
				clientErrors <- fmt.Errorf("TCP flow %d: %w", index, err)
				return
			}
			clientErrors <- nil
		}(index)
	}
	if udpConcurrent <= 0 || udpConcurrent > udpCount {
		udpConcurrent = udpCount
	}
	udpSlots := make(chan struct{}, udpConcurrent)
	for index := 0; index < udpCount; index++ {
		clients.Add(1)
		go func(index int) {
			defer clients.Done()
			udpSlots <- struct{}{}
			defer func() { <-udpSlots }()
			if err := runNowhereUDPFlow(dialer, destination, index); err != nil {
				clientErrors <- fmt.Errorf("UDP flow %d: %w", index, err)
				return
			}
			clientErrors <- nil
		}(index)
	}
	clients.Wait()
	close(tcpStop)
	if tcpListener != nil {
		_ = tcpListener.Close()
	}
	close(udpStop)
	if udpListener != nil {
		_ = udpListener.Close()
	}
	close(clientErrors)
	for err := range clientErrors {
		require.NoError(t, err)
	}
	for i := 0; i < expectedServers; i++ {
		require.NoError(t, <-serverErrors)
	}
}

func serveNowhereTCPEcho(listener net.Listener, count int, stop <-chan struct{}, result chan<- error) {
	var handlers sync.WaitGroup
	for index := 0; index < count; index++ {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				result <- nil
			default:
				result <- err
			}
			return
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer conn.Close()
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(conn, buffer); err == nil {
				_, _ = conn.Write(buffer)
			}
		}()
	}
	handlers.Wait()
	result <- nil
}

func serveNowhereUDPEcho(conn net.PacketConn, stop <-chan struct{}, result chan<- error) {
	buffer := make([]byte, 64)
	for {
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			select {
			case <-stop:
				result <- nil
			default:
				result <- err
			}
			return
		}
		if _, err := conn.WriteTo(buffer[:n], source); err != nil {
			result <- err
			return
		}
	}
}

func runNowhereTCPFlow(dialer N.Dialer, destination M.Socksaddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		return err
	}
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(conn, buffer); err != nil {
		return err
	}
	if string(buffer) != "ping" {
		return fmt.Errorf("unexpected TCP response %q", buffer)
	}
	return nil
}

func runNowhereUDPFlow(dialer N.Dialer, destination M.Socksaddr, index int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := []byte(fmt.Sprintf("u%03d", index))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err = conn.WriteTo(payload, destination.UDPAddr()); err != nil {
			return err
		}
		buffer := make([]byte, len(payload))
		n, _, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			if timeout, loaded := readErr.(net.Error); loaded && timeout.Timeout() {
				continue
			}
			return readErr
		}
		if string(buffer[:n]) != string(payload) {
			return fmt.Errorf("unexpected UDP response %q", buffer[:n])
		}
		return nil
	}
	return fmt.Errorf("UDP echo timed out")
}

func testNowhereBasicTCPUDP(t *testing.T, clientPort uint16, testPort uint16) {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	dialTCP := func() (net.Conn, error) {
		return dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	}
	dialUDP := func() (net.PacketConn, error) {
		return dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	}
	require.NoError(t, testPingPongWithConn(t, testPort, dialTCP))
	require.NoError(t, testPingPongWithPacketConn(t, testPort, dialUDP))
}

func testNowhereUDPUDP(t *testing.T, clientPort uint16, testPort uint16) {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	dialTCP := func() (net.Conn, error) {
		return dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	}
	dialUDP := func() (net.PacketConn, error) {
		return dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	}
	require.NoError(t, testPingPongWithConn(t, testPort, dialTCP))
	require.NoError(t, testPingPongWithPacketConn(t, testPort, dialUDP))
	require.NoError(t, testLargeDataWithConn(t, testPort, dialTCP))
	require.NoError(t, testLargeDataWithPacketConnSize(t, testPort, 800, dialUDP))
}
