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

// TestInboundTCPMorphRoundTrip covers the sing-box listener path, which does
// not use core Server.serveTCP. Morph must be unwrapped before the TLS handshake.
func TestInboundTCPMorphRoundTrip(t *testing.T) {
	t.Parallel()
	relayPort, echoAddr := startMorphTCPRelay(t)
	client := newMorphTCPClient(t, relayPort, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("morph-tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
	require.NoError(t, conn.Close())
}

// TestInboundTCPMorphMismatchRejectsBareTLS keeps a morph=0 client from
// completing a handshake against a morph inbound.
func TestInboundTCPMorphMismatchRejectsBareTLS(t *testing.T) {
	t.Parallel()
	relayPort, echoAddr := startMorphTCPRelay(t)
	client := newMorphTCPClient(t, relayPort, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.DialContext(ctx, N.NetworkTCP, echoAddr)
	require.Error(t, err)
}

func startMorphTCPRelay(t *testing.T) (uint16, M.Socksaddr) {
	t.Helper()
	keyPair, certPEM, keyPEM := chainTestKeyPair(t)
	echoAddr := startChainTestEcho(t)
	originPort := startChainTestOrigin(t, keyPair, "")
	relayPort := chainTestFreePort(t)
	logger := log.NewNOPFactory().Logger()
	// next.morph stays off so the origin, which speaks bare TLS, is not asked
	// to morph. Only the accepted TCP carrier under test is morphed.
	relay, err := NewInbound(context.Background(), nil, logger, "relay", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: relayPort,
		},
		Password: "relay-key",
		Morph:    true,
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
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: originPort},
			Password:      "origin-key",
			Up:            "tcp",
			Down:          "tcp",
			Morph:         common.Ptr(false),
		},
	})
	require.NoError(t, err)
	require.NoError(t, relay.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { _ = relay.(*Inbound).Close() })
	return relayPort, echoAddr
}

func newMorphTCPClient(t *testing.T, relayPort uint16, morph bool) *Outbound {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	client, err := NewOutbound(context.Background(), nil, logger, "client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: relayPort},
		Password:      "relay-key",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          common.Ptr(0),
		Morph:         morph,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: true,
				ALPN:     badoption.Listable[string]{defaultALPN},
			},
		},
	})
	require.NoError(t, err)
	outbound := client.(*Outbound)
	t.Cleanup(func() { _ = outbound.Close() })
	return outbound
}
