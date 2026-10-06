package nowhere

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TestInboundChainedPortalForwarding exercises native Portal chaining:
// client outbound -> relay inbound (next) -> origin Portal -> echo target,
// for both TCP and UDP flows. The tcp/tcp matrix carries UDP over UoT with
// TCP-only ingress, so the test runs with and without the with_quic tag.
func TestInboundChainedPortalForwarding(t *testing.T) {
	t.Parallel()
	t.Run("default-unverified", func(t *testing.T) {
		t.Parallel()
		// No pin and no server_name: certificate verification is disabled by
		// default (Rust semantics), so the self-signed origin is accepted.
		testInboundChainedPortalForwarding(t, chainTestCase{})
	})
	t.Run("certificate-pin", func(t *testing.T) {
		t.Parallel()
		testInboundChainedPortalForwarding(t, chainTestCase{pin: true})
	})
	t.Run("custom-alpn", func(t *testing.T) {
		t.Parallel()
		// The chained upstream inherits the relay listener ALPN; the origin
		// accepts only the custom ALPN, so a default-ALPN upstream would fail.
		testInboundChainedPortalForwarding(t, chainTestCase{alpn: "custom/1"})
	})
}

type chainTestCase struct {
	pin  bool
	alpn string
}

func testInboundChainedPortalForwarding(t *testing.T, testCase chainTestCase) {
	t.Helper()

	keyPair, certPEM, keyPEM := chainTestKeyPair(t)
	echoAddr := startChainTestEcho(t)
	originPort := startChainTestOrigin(t, keyPair, testCase.alpn)
	relayPort := chainTestFreePort(t)

	alpn := badoption.Listable[string]{defaultALPN}
	if testCase.alpn != "" {
		alpn = badoption.Listable[string]{testCase.alpn}
	}
	next := &option.NowhereNextOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: originPort},
		Password:      "origin-key",
		Up:            "tcp",
		Down:          "tcp",
	}
	if testCase.pin {
		next.Pin = wire.LeafCertificateSHA256Hex(keyPair.Certificate[0])
	}

	logger := log.NewNOPFactory().Logger()
	relay, err := NewInbound(context.Background(), nil, logger, "relay", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: relayPort,
		},
		Password: "relay-key",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ALPN:        alpn,
				Certificate: badoption.Listable[string]{string(certPEM)},
				Key:         badoption.Listable[string]{string(keyPEM)},
			},
		},
		Next: next,
	})
	require.NoError(t, err)
	require.NoError(t, relay.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = relay.(*Inbound).Close() })

	client, err := NewOutbound(context.Background(), nil, logger, "client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: relayPort},
		Password:      "relay-key",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          common.Ptr(0),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: true,
				ALPN:     alpn,
			},
		},
	})
	require.NoError(t, err)
	clientOutbound := client.(*Outbound)
	t.Cleanup(func() { _ = clientOutbound.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	tcpPayload := []byte("chain-tcp")
	_, err = conn.Write(tcpPayload)
	require.NoError(t, err)
	tcpReply := make([]byte, len(tcpPayload))
	_, err = io.ReadFull(conn, tcpReply)
	require.NoError(t, err)
	require.Equal(t, tcpPayload, tcpReply)
	require.NoError(t, conn.Close())

	packetConn, err := client.ListenPacket(ctx, echoAddr)
	require.NoError(t, err)
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	udpPayload := []byte("chain-udp")
	_, err = packetConn.WriteTo(udpPayload, echoAddr.UDPAddr())
	require.NoError(t, err)
	udpReply := make([]byte, len(udpPayload)+1)
	n, _, err := packetConn.ReadFrom(udpReply)
	require.NoError(t, err)
	require.Equal(t, udpPayload, udpReply[:n])
	_ = packetConn.Close()

	// A flow arriving at a forwarding Portal with HOPS=1 has no remaining
	// forwarding budget and must be rejected with the v1.7 FLOW_LIMIT code.
	echoTarget, err := targetFromSocksaddr(echoAddr)
	require.NoError(t, err)
	_, err = clientOutbound.bundle.OpenTCPWithHops(ctx, echoTarget, 1)
	require.Equal(t, wire.SetupResultFlowLimit, chainTestSetupResultCode(t, err))

	// A next-hop setup failure is returned unchanged by PortalUpstream. Compare
	// the direct origin result with the result observed through the relay.
	rejectedListener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	rejectedAddress := M.ParseSocksaddr(rejectedListener.Addr().String())
	require.NoError(t, rejectedListener.Close())
	rejectedTarget, err := targetFromSocksaddr(rejectedAddress)
	require.NoError(t, err)
	direct, err := NewOutbound(context.Background(), nil, logger, "origin-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: originPort},
		Password:      "origin-key",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          common.Ptr(0),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: alpn},
		},
	})
	require.NoError(t, err)
	directOutbound := direct.(*Outbound)
	t.Cleanup(func() { _ = directOutbound.Close() })
	_, directErr := directOutbound.bundle.OpenTCP(ctx, rejectedTarget)
	_, relayedErr := clientOutbound.bundle.OpenTCP(ctx, rejectedTarget)
	require.Equal(t, chainTestSetupResultCode(t, directErr), chainTestSetupResultCode(t, relayedErr))

	// Interface updates rotate the chained upstream even though this relay
	// listens on TCP only. The retired bundle is closed after its active flows
	// return, while new flows use the replacement generation.
	relayInbound := relay.(*Inbound)
	oldBundle := relayInbound.nextUpstream.currentBundleForTest()
	require.NotNil(t, oldBundle)
	relayInbound.InterfaceUpdated(context.Background())
	newBundle := relayInbound.nextUpstream.currentBundleForTest()
	require.NotNil(t, newBundle)
	require.NotSame(t, oldBundle, newBundle)
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 9)
	require.NoError(t, err)
	_, err = oldBundle.OpenTCP(context.Background(), target)
	require.Error(t, err)

	conn, err = client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	updatePayload := []byte("after-update")
	_, err = conn.Write(updatePayload)
	require.NoError(t, err)
	updateReply := make([]byte, len(updatePayload))
	_, err = io.ReadFull(conn, updateReply)
	require.NoError(t, err)
	require.Equal(t, updatePayload, updateReply)
	require.NoError(t, conn.Close())

	require.NoError(t, clientOutbound.Close())
	require.NoError(t, relay.(*Inbound).Close())
	// relay.(*Inbound).Close() must close the chained bundle after the handler drained
	// (PortalUpstream's non-owning contract): the next hop rejects new flows.
	_, err = newBundle.OpenTCP(context.Background(), target)
	require.Error(t, err)
}

func chainTestSetupResultCode(t *testing.T, err error) wire.SetupResult {
	t.Helper()
	require.Error(t, err)
	var setupError *bundle.SetupResultError
	require.ErrorAs(t, err, &setupError)
	return setupError.SetupResultCode()
}

func TestNewInboundRejectsChainedPortalWithoutPassword(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
		},
	})
	require.ErrorContains(t, err, "missing next password")
}

func TestInboundMultiHopPortalForwarding(t *testing.T) {
	t.Parallel()
	keyPair, certPEM, keyPEM := chainTestKeyPair(t)
	echoAddr := startChainTestEcho(t)
	originPort := startChainTestOrigin(t, keyPair, "")
	relay2, relay2Port := startChainTestRelay(t, certPEM, keyPEM, "relay-2-key", originPort, "origin-key")
	_, relay1Port := startChainTestRelay(t, certPEM, keyPEM, "relay-1-key", relay2Port, "relay-2-key")

	logger := log.NewNOPFactory().Logger()
	client, err := NewOutbound(context.Background(), nil, logger, "multi-hop-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: relay1Port},
		Password:      "relay-1-key",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          common.Ptr(0),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: badoption.Listable[string]{defaultALPN}},
		},
	})
	require.NoError(t, err)
	clientOutbound := client.(*Outbound)
	t.Cleanup(func() { _ = clientOutbound.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.NoError(t, err)
	payload := []byte("multi-hop")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
	require.NoError(t, conn.Close())

	packetConn, err := client.ListenPacket(ctx, echoAddr)
	require.NoError(t, err)
	_, err = packetConn.WriteTo(payload, echoAddr.UDPAddr())
	require.NoError(t, err)
	packetReply := make([]byte, len(payload)+1)
	n, _, err := packetConn.ReadFrom(packetReply)
	require.NoError(t, err)
	require.Equal(t, payload, packetReply[:n])
	require.NoError(t, packetConn.Close())

	// HOPS=2 reaches relay 2 with HOPS=1 and is rejected there, proving that
	// each Portal consumes exactly one unit from the v1.7 forwarding budget.
	target, err := targetFromSocksaddr(echoAddr)
	require.NoError(t, err)
	_, err = clientOutbound.bundle.OpenTCPWithHops(ctx, target, 2)
	require.Equal(t, wire.SetupResultFlowLimit, chainTestSetupResultCode(t, err))
	require.NotNil(t, relay2.nextUpstream.currentBundleForTest())
}

func startChainTestRelay(t *testing.T, certPEM, keyPEM []byte, password string, nextPort uint16, nextPassword string) (*Inbound, uint16) {
	t.Helper()
	listenPort := chainTestFreePort(t)
	logger := log.NewNOPFactory().Logger()
	relay, err := NewInbound(context.Background(), nil, logger, password, option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: password,
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ALPN:        badoption.Listable[string]{defaultALPN},
				Certificate: badoption.Listable[string]{string(certPEM)},
				Key:         badoption.Listable[string]{string(keyPEM)},
			},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: nextPort},
			Password:      nextPassword,
			Up:            "tcp",
			Down:          "tcp",
		},
	})
	require.NoError(t, err)
	relayInbound := relay.(*Inbound)
	require.NoError(t, relayInbound.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = relayInbound.Close() })
	return relayInbound, listenPort
}

func TestNewInboundRejectsChainedPortalWithoutServer(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
		Next: &option.NowhereNextOptions{
			Password: "origin-key",
		},
	})
	require.ErrorContains(t, err, "missing next server")
}

func TestNewInboundRejectsChainedPortalInvalidCarrier(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      "origin-key",
			Up:            "quic",
			Down:          "quic",
		},
	})
	require.ErrorContains(t, err, "invalid carrier selector")
}

func TestNewInboundAcceptsChainedPortalNoneServerNameAndPin(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	relay, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      "origin-key",
			Up:            "tcp",
			Down:          "tcp",
			ServerName:    "none",
			Pin:           "none",
		},
	})
	require.NoError(t, err)
	_ = relay.(*Inbound).Close()
}

func TestNewInboundRejectsChainedPortalInvalidServerName(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      "origin-key",
			Up:            "tcp",
			Down:          "tcp",
			ServerName:    "127.0.0.1",
		},
	})
	require.ErrorContains(t, err, "must be an ASCII DNS name")
}

func chainTestKeyPair(t *testing.T) (keyPair *stdtls.Certificate, certPEM, keyPEM []byte) {
	t.Helper()
	keyPair, err := tls.GenerateKeyPair(nil, nil, nil, "example.org")
	require.NoError(t, err)
	for _, der := range keyPair.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(keyPair.PrivateKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return keyPair, certPEM, keyPEM
}

func startChainTestEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	tcpListener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	address := tcpListener.Addr().String()
	udpConn, err := net.ListenPacket(N.NetworkUDP, address)
	require.NoError(t, err)
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, source, err := udpConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udpConn.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpConn.Close()
	})
	return M.ParseSocksaddr(address)
}

// startChainTestOrigin runs a standalone nw2 core Portal that dials targets
// directly. Its QUIC listener is an idle stub: the relay chains over tcp/tcp,
// so UDP flows arrive as UoT on the TCP carrier. alpn restricts the origin to
// a single accepted ALPN (empty keeps the default nw2).
func startChainTestOrigin(t *testing.T, keyPair *stdtls.Certificate, alpn string) uint16 {
	t.Helper()
	credentials, err := wire.NewCredentials("origin-key")
	require.NoError(t, err)
	config, err := nwserver.NewConfig(nwserver.ConfigOptions{
		Credentials: credentials,
		Networks:    []nwserver.Network{nwserver.NetworkTCP, nwserver.NetworkUDP},
		ALPN:        alpn,
	})
	require.NoError(t, err)
	origin, err := nwserver.NewServer(nwserver.ServerOptions{
		Config:       config,
		TLS:          &stdtls.Config{Certificates: []stdtls.Certificate{*keyPair}},
		Upstream:     nwserver.NewDialUpstream(nil),
		QUICListener: chainTestIdleQUICListener{},
	})
	require.NoError(t, err)
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = origin.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = origin.Shutdown(shutdownCtx)
		select {
		case <-serveDone:
		case <-shutdownCtx.Done():
			t.Error("origin Portal did not stop within shutdown deadline")
		}
	})
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

type chainTestIdleQUICListener struct{}

func (chainTestIdleQUICListener) Accept(ctx context.Context) (nwserver.QuicConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (chainTestIdleQUICListener) Close() error { return nil }

func chainTestFreePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}
