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
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// TestNowhereV3QUICForwarding runs a full Nowhere 3 endpoint pair over the QUIC
// carrier with Morph on (the v3 default): the portal serves a sealed UDP socket
// below QUIC, and both TCP flows and UDP datagrams reach the echo target.
func TestNowhereV3QUICForwarding(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	echo := startChainTestEcho(t)
	router := &nw3TestRouter{target: echo}
	listenPort := chainTestFreePort(t)

	server, err := NewInbound(context.Background(), router, logger, "nw3-quic-server", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: testNw3Key,
		Net:      nowhereV3NetUDP,
		Network:  option.NetworkList(N.NetworkUDP),
		Morph:    common.Ptr(true),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				Certificate: badoption.Listable[string]{string(certPEM)},
				Key:         badoption.Listable[string]{string(keyPEM)},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = common.Close(server) })

	client, err := NewOutbound(context.Background(), router, logger, "nw3-quic-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Net:           nowhereV3NetUDP,
		Morph:         common.Ptr(true),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	require.NoError(t, err)
	clientOutbound := client.(*OutboundV3)
	t.Cleanup(func() { _ = clientOutbound.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clientOutbound.DialContext(ctx, N.NetworkTCP, echo)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("nw3-quic-tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
	require.NoError(t, conn.Close())

	packetConn, err := clientOutbound.ListenPacket(ctx, echo)
	require.NoError(t, err)
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	udpPayload := []byte("nw3-quic-udp")
	_, err = packetConn.WriteTo(udpPayload, echo.UDPAddr())
	require.NoError(t, err)
	udpReply := make([]byte, len(udpPayload)+1)
	n, _, err := packetConn.ReadFrom(udpReply)
	require.NoError(t, err)
	require.Equal(t, udpPayload, udpReply[:n])
	_ = packetConn.Close()

	require.Equal(t, int64(1), router.tcpFlows.Load())
	require.Equal(t, int64(1), router.udpFlows.Load())
}

// TestNowhereV3EgressRegistration covers the exit bridge: a Portal in egress
// mode forwards authenticated flows to the single registered Egress client, a
// second Egress is told the exit is busy and keeps retrying without preempting
// the owner, and after the owner drops the waiting Egress takes over.
func TestNowhereV3EgressRegistration(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	echo := startChainTestEcho(t)
	primaryRouter := &nw3TestRouter{target: echo}
	secondaryRouter := &nw3TestRouter{target: echo}
	listenPort := chainTestFreePort(t)

	portal, err := NewInbound(context.Background(), nil, logger, "nw3-egress-portal", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: testNw3Key,
		Net:      nowhereV3NetUDP,
		Network:  option.NetworkList(N.NetworkUDP),
		Egress:   true,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				Certificate: badoption.Listable[string]{string(certPEM)},
				Key:         badoption.Listable[string]{string(keyPEM)},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, portal.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = common.Close(portal) })

	client, err := NewOutbound(context.Background(), nil, logger, "nw3-egress-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Net:           nowhereV3NetUDP,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	require.NoError(t, err)
	clientOutbound := client.(*OutboundV3)
	t.Cleanup(func() { _ = clientOutbound.Close() })

	primary, err := NewEgressInbound(context.Background(), primaryRouter, logger, "nw3-egress-primary", option.NowhereEgressInboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Insecure:      true,
	})
	require.NoError(t, err)
	require.NoError(t, primary.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = common.Close(primary) })

	// The primary exit registers asynchronously; flows succeed once it owns the
	// Portal. Registration has no success signal, so poll the data path.
	require.Eventually(t, func() bool {
		return nw3EgressFlowWorks(t, clientOutbound, echo)
	}, 15*time.Second, 100*time.Millisecond)
	require.Equal(t, int64(1), primaryRouter.tcpFlows.Load())
	require.Equal(t, int64(0), secondaryRouter.tcpFlows.Load())

	// A second Egress is rejected with ErrBusy and keeps retrying. Give it more
	// than two reconnect cycles, then prove the owner still serves every flow
	// and the challenger never routed anything.
	secondary, err := NewEgressInbound(context.Background(), secondaryRouter, logger, "nw3-egress-secondary", option.NowhereEgressInboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Insecure:      true,
	})
	require.NoError(t, err)
	require.NoError(t, secondary.Start(adapter.StartStateStart, nil))
	time.Sleep(2*nowhereEgressReconnectDelay + time.Second)
	require.True(t, nw3EgressFlowWorks(t, clientOutbound, echo))
	require.Equal(t, int64(2), primaryRouter.tcpFlows.Load())
	require.Equal(t, int64(0), secondaryRouter.tcpFlows.Load())

	// Dropping the owner releases the exit; the waiting Egress reconnects and
	// takes over within one cooldown.
	require.NoError(t, common.Close(primary))
	require.Eventually(t, func() bool {
		return nw3EgressFlowWorks(t, clientOutbound, echo)
	}, 15*time.Second, 100*time.Millisecond)
	require.Equal(t, int64(1), secondaryRouter.tcpFlows.Load())
}

func nw3EgressFlowWorks(t *testing.T, client adapter.Outbound, echo M.Socksaddr) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, N.NetworkTCP, echo)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false
	}
	payload := []byte("nw3-egress")
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return string(reply) == string(payload)
}
