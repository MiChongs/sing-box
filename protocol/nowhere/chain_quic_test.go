//go:build with_quic

package nowhere

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TestInboundChainedPortalCarrierMatrices covers every v1.7 carrier matrix on
// both sides of a forwarding Portal. An intermediate Portal accepts TCP and
// QUIC and chains over tcp/tcp to the standalone direct-dial origin.
func TestInboundChainedPortalCarrierMatrices(t *testing.T) {
	keyPair, certPEM, keyPEM := chainTestKeyPair(t)
	echoAddr := startChainTestEcho(t)
	directOriginPort := startChainTestOrigin(t, keyPair, "")
	matrixOriginPort := startChainTestMatrixRelay(t, certPEM, keyPEM, "matrix-origin-key", directOriginPort, "origin-key", "tcp", "tcp")

	matrices := [][2]string{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp", "udp"}, {"udp", "tcp"}}
	for _, nextMatrix := range matrices {
		nextUp, nextDown := nextMatrix[0], nextMatrix[1]
		t.Run("next-"+nextUp+"/"+nextDown, func(t *testing.T) {
			relayPort := startChainTestMatrixRelay(t, certPEM, keyPEM, "matrix-relay-key", matrixOriginPort, "matrix-origin-key", nextUp, nextDown)
			for _, clientMatrix := range matrices {
				up, down := clientMatrix[0], clientMatrix[1]
				t.Run(up+"/"+down, func(t *testing.T) {
					client := startChainTestMatrixClient(t, relayPort, up, down)
					assertChainTestTCP(t, client, echoAddr)
					assertChainTestUDP(t, client, echoAddr)
				})
			}
		})
	}
}

func startChainTestMatrixRelay(t *testing.T, certPEM, keyPEM []byte, password string, nextPort uint16, nextPassword, up, down string) uint16 {
	t.Helper()
	listenPort := chainTestFreePort(t)
	logger := log.NewNOPFactory().Logger()
	relay, err := NewInbound(context.Background(), nil, logger, password, option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: password,
		Network:  option.NetworkList(""),
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
			Up:            up,
			Down:          down,
		},
	})
	require.NoError(t, err)
	relayInbound := relay.(*Inbound)
	require.NoError(t, relayInbound.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = relayInbound.Close() })
	return listenPort
}

func startChainTestMatrixClient(t *testing.T, serverPort uint16, up, down string) *Outbound {
	t.Helper()
	client, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "matrix-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort},
		Password:      "matrix-relay-key",
		Up:            up,
		Down:          down,
		Pool:          common.Ptr(0),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: true,
				ALPN:     badoption.Listable[string]{defaultALPN},
			},
		},
	})
	require.NoError(t, err)
	clientOutbound := client.(*Outbound)
	t.Cleanup(func() { _ = clientOutbound.Close() })
	return clientOutbound
}

func assertChainTestTCP(t *testing.T, client *Outbound, echoAddr M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("matrix-tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)

	// This topology has two forwarding Portals before the direct origin.
	// HOPS=2 must reach the second Portal as 1 and return FLOW_LIMIT for every
	// client/next carrier pairing, including QUIC-owned route tasks.
	target, err := targetFromSocksaddr(echoAddr)
	require.NoError(t, err)
	_, err = client.bundle.OpenTCPWithHops(ctx, target, 2)
	require.Equal(t, wire.SetupResultFlowLimit, chainTestSetupResultCode(t, err))
}

func assertChainTestUDP(t *testing.T, client *Outbound, echoAddr M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx, echoAddr)
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("matrix-udp")
	_, err = packetConn.WriteTo(payload, echoAddr.UDPAddr())
	require.NoError(t, err)
	reply := make([]byte, len(payload)+1)
	n, _, err := packetConn.ReadFrom(reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply[:n])
}
