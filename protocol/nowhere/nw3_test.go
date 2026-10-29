package nowhere

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// testNw3Key is a Nowhere 3 service key: exactly 32 lowercase hex characters.
// The nw2 keys in chain_test.go are deliberately not reused here: the two
// stacks have different key rules and must not be mixed.
const testNw3Key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestResolveNowhereStack(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		alpn  []string
		stack nowhereStack
	}{
		{nil, nowhereStackNw3},
		{[]string{""}, nowhereStackNw3},
		{[]string{"nw3"}, nowhereStackNw3},
		{[]string{"nw2"}, nowhereStackNw2},
		{[]string{"custom/1"}, nowhereStackNw2},
	} {
		stack, err := resolveNowhereStack(badoption.Listable[string](testCase.alpn))
		require.NoError(t, err)
		require.Equal(t, testCase.stack, stack)
	}
	_, err := resolveNowhereStack(badoption.Listable[string]{"nw2", "nw3"})
	require.ErrorContains(t, err, "exactly one ALPN")
}

func TestResolveNowhereMorph(t *testing.T) {
	t.Parallel()
	require.False(t, resolveNowhereMorph(nil, nowhereStackNw2))
	require.True(t, resolveNowhereMorph(nil, nowhereStackNw3))
	require.True(t, resolveNowhereMorph(common.Ptr(true), nowhereStackNw2))
	require.False(t, resolveNowhereMorph(common.Ptr(false), nowhereStackNw3))
}

func TestNowhereV3Net(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		raw string
		net string
	}{
		{"", nowhereV3NetTCP},
		{"tcp", nowhereV3NetTCP},
		{"udp", nowhereV3NetUDP},
	} {
		net, err := nowhereV3Net(testCase.raw)
		require.NoError(t, err)
		require.Equal(t, testCase.net, net)
	}
	_, err := nowhereV3Net("quic")
	require.ErrorContains(t, err, "net must be tcp or udp")
}

func TestValidateNowhereNw2RejectsNowhere3Fields(t *testing.T) {
	t.Parallel()
	require.ErrorContains(t, validateNowhereNw2OutboundOptions(&option.NowhereOutboundOptions{
		Net: "tcp",
	}), "net is a Nowhere 3 field")
	require.NoError(t, validateNowhereNw2OutboundOptions(&option.NowhereOutboundOptions{}))
	require.ErrorContains(t, validateNowhereNw2InboundOptions(&option.NowhereInboundOptions{
		Net: "udp",
	}), "net is a Nowhere 3 field")
	require.ErrorContains(t, validateNowhereNw2InboundOptions(&option.NowhereInboundOptions{
		Egress: true,
	}), "egress is a Nowhere 3 field")
	require.NoError(t, validateNowhereNw2InboundOptions(&option.NowhereInboundOptions{}))
}

func TestValidateNowhereV3InboundOptions(t *testing.T) {
	t.Parallel()
	require.NoError(t, validateNowhereV3InboundOptions(&option.NowhereInboundOptions{}))
	require.ErrorContains(t, validateNowhereV3InboundOptions(&option.NowhereInboundOptions{
		Next: &option.NowhereNextOptions{},
	}), "does not support next chaining")
	require.ErrorContains(t, validateNowhereV3InboundOptions(&option.NowhereInboundOptions{
		MaxUnauthenticatedConnections: common.Ptr(1),
	}), "admission limits are fixed")
	require.ErrorContains(t, validateNowhereV3InboundOptions(&option.NowhereInboundOptions{
		MaxUnauthenticatedPerSource: common.Ptr(1),
	}), "admission limits are fixed")
}

func TestValidateNowhereV3InboundNetworks(t *testing.T) {
	t.Parallel()
	require.NoError(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{}, nowhereV3NetTCP))
	require.NoError(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{
		Network: option.NetworkList(N.NetworkTCP),
	}, nowhereV3NetTCP))
	require.NoError(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{
		Network: option.NetworkList(N.NetworkUDP),
	}, nowhereV3NetUDP))
	require.ErrorContains(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{
		Network: option.NetworkList(N.NetworkUDP),
	}, nowhereV3NetTCP), "implies network tcp")
	require.ErrorContains(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{
		Network: option.NetworkList(N.NetworkTCP),
	}, nowhereV3NetUDP), "implies network udp")
	require.ErrorContains(t, validateNowhereV3InboundNetworks(&option.NowhereInboundOptions{
		Network: option.NetworkList("tcp,udp"),
	}, nowhereV3NetTCP), "implies network tcp")
}

func TestValidateNowhereV3OutboundOptions(t *testing.T) {
	t.Parallel()
	require.NoError(t, validateNowhereV3OutboundOptions(&option.NowhereOutboundOptions{}))
	for name, options := range map[string]*option.NowhereOutboundOptions{
		"up":               {Up: "tcp"},
		"down":             {Down: "tcp"},
		"mux":              {Mux: common.Ptr(1)},
		"pool":             {Pool: common.Ptr(0)},
		"prewarm_on_start": {PrewarmOnStart: true},
		"max_concurrent":   {MaxConcurrentDials: common.Ptr(1)},
		"warm_backoff":     {WarmBackoffInitial: badoption.Duration(time.Second)},
		"warm_backoff_max": {WarmBackoffMax: badoption.Duration(time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateNowhereV3OutboundOptions(options))
		})
	}
}

func TestNewInboundV3RejectsUnsupportedFields(t *testing.T) {
	t.Parallel()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	tlsContainer := option.InboundTLSOptionsContainer{
		TLS: &option.InboundTLSOptions{
			Enabled:     true,
			Certificate: badoption.Listable[string]{string(certPEM)},
			Key:         badoption.Listable[string]{string(keyPEM)},
		},
	}
	base := func() option.NowhereInboundOptions {
		return option.NowhereInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
				ListenPort: chainTestFreePort(t),
			},
			Password:                   testNw3Key,
			InboundTLSOptionsContainer: tlsContainer,
		}
	}
	for name, mutate := range map[string]func(*option.NowhereInboundOptions){
		"net":           func(o *option.NowhereInboundOptions) { o.Net = "ws" },
		"key":           func(o *option.NowhereInboundOptions) { o.Password = "xyz" },
		"key-length":    func(o *option.NowhereInboundOptions) { o.Password = "0123456789abcdef0123456789abcdef01234567" },
		"next":          func(o *option.NowhereInboundOptions) { o.Next = &option.NowhereNextOptions{} },
		"max-unauth":    func(o *option.NowhereInboundOptions) { o.MaxUnauthenticatedConnections = common.Ptr(1) },
		"network":       func(o *option.NowhereInboundOptions) { o.Network = option.NetworkList(N.NetworkUDP) },
		"egress-on-tcp": func(o *option.NowhereInboundOptions) { o.Egress = true },
		"tls-version":   func(o *option.NowhereInboundOptions) { o.TLS.MinVersion = "1.2" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := base()
			mutate(&options)
			_, err := NewInbound(context.Background(), &nw3TestRouter{}, log.NewNOPFactory().Logger(), "nw3", options)
			require.Error(t, err)
		})
	}
}

func TestNewOutboundV3RejectsUnsupportedFields(t *testing.T) {
	t.Parallel()
	base := func() option.NowhereOutboundOptions {
		return option.NowhereOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      testNw3Key,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
			},
		}
	}
	for name, mutate := range map[string]func(*option.NowhereOutboundOptions){
		"net":            func(o *option.NowhereOutboundOptions) { o.Net = "ws" },
		"password":       func(o *option.NowhereOutboundOptions) { o.Password = "" },
		"key":            func(o *option.NowhereOutboundOptions) { o.Password = "xyz" },
		"key-length":     func(o *option.NowhereOutboundOptions) { o.Password = "0123456789abcdef0123456789abcdef01234567" },
		"up":             func(o *option.NowhereOutboundOptions) { o.Up = "tcp" },
		"down":           func(o *option.NowhereOutboundOptions) { o.Down = "tcp" },
		"mux":            func(o *option.NowhereOutboundOptions) { o.Mux = common.Ptr(1) },
		"pool":           func(o *option.NowhereOutboundOptions) { o.Pool = common.Ptr(0) },
		"prewarm":        func(o *option.NowhereOutboundOptions) { o.PrewarmOnStart = true },
		"max-concurrent": func(o *option.NowhereOutboundOptions) { o.MaxConcurrentDials = common.Ptr(1) },
		"warm-backoff":   func(o *option.NowhereOutboundOptions) { o.WarmBackoffInitial = badoption.Duration(time.Second) },
		"tls-missing":    func(o *option.NowhereOutboundOptions) { o.TLS = nil },
		"tls-reality": func(o *option.NowhereOutboundOptions) {
			o.TLS.Reality = &option.OutboundRealityOptions{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := base()
			mutate(&options)
			_, err := NewOutbound(context.Background(), &nw3TestRouter{}, log.NewNOPFactory().Logger(), "nw3", options)
			require.Error(t, err)
		})
	}
}

func TestNewOutboundDispatchesStackByALPN(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	legacy := func() option.NowhereOutboundOptions {
		return option.NowhereOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      "secret",
			Up:            "tcp",
			Down:          "tcp",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: badoption.Listable[string]{"nw2"}},
			},
		}
	}
	out, err := NewOutbound(context.Background(), &nw3TestRouter{}, logger, "nw2", legacy())
	require.NoError(t, err)
	require.IsType(t, &Outbound{}, out)
	require.NoError(t, out.(*Outbound).Close())

	withNet := legacy()
	withNet.Net = "tcp"
	_, err = NewOutbound(context.Background(), &nw3TestRouter{}, logger, "nw2", withNet)
	require.ErrorContains(t, err, "net is a Nowhere 3 field")
}

func TestNewInboundDispatchesStackByALPN(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	legacy := func() option.NowhereInboundOptions {
		return option.NowhereInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
				ListenPort: chainTestFreePort(t),
			},
			Password: testPortalKey,
			Network:  option.NetworkList(N.NetworkTCP),
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled:     true,
					ALPN:        badoption.Listable[string]{"nw2"},
					Certificate: badoption.Listable[string]{string(certPEM)},
					Key:         badoption.Listable[string]{string(keyPEM)},
				},
			},
		}
	}
	in, err := NewInbound(context.Background(), &nw3TestRouter{}, logger, "nw2", legacy())
	require.NoError(t, err)
	require.IsType(t, &Inbound{}, in)
	require.NoError(t, common.Close(in))

	withEgress := legacy()
	withEgress.Egress = true
	_, err = NewInbound(context.Background(), &nw3TestRouter{}, logger, "nw2", withEgress)
	require.ErrorContains(t, err, "egress is a Nowhere 3 field")

	// An omitted ALPN selects the default Nowhere 3 stack.
	v3 := legacy()
	v3.Password = testNw3Key
	v3.TLS.ALPN = nil
	v3Inbound, err := NewInbound(context.Background(), &nw3TestRouter{}, logger, "nw3", v3)
	require.NoError(t, err)
	require.IsType(t, &InboundV3{}, v3Inbound)
	require.NoError(t, common.Close(v3Inbound))
}

// TestNowhereV3TCPForwarding runs a full Nowhere 3 endpoint pair over the TCP
// transport with Morph on (the v3 default): inbound Portal -> sing-box router ->
// echo target and back, for TCP flows and for UDP flows carried over the TLS
// connection as UoT.
func TestNowhereV3TCPForwarding(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	echo := startChainTestEcho(t)
	router := &nw3TestRouter{target: echo}
	listenPort := chainTestFreePort(t)

	server, err := NewInbound(context.Background(), router, logger, "nw3-server", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: testNw3Key,
		Net:      nowhereV3NetTCP,
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

	client, err := NewOutbound(context.Background(), router, logger, "nw3-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Net:           nowhereV3NetTCP,
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

	conn, err := client.DialContext(ctx, N.NetworkTCP, echo)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("nw3-tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
	require.NoError(t, conn.Close())

	packetConn, err := client.ListenPacket(ctx, echo)
	require.NoError(t, err)
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	udpPayload := []byte("nw3-udp")
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

// TestOutboundV3InterfaceUpdatedKeepsDialing guards the v3 outbound against the
// nil-client trap: InterfaceUpdated used to drop the cached client reference,
// and getClient reports a nil one as net.ErrClosed, so the first network event
// after startup killed every later flow. The vendored Vector rebuilds its QUIC
// session on its own after Close, and the TCP transport dials each flow
// through the same client, so the reference has to survive the update.
func TestOutboundV3InterfaceUpdatedKeepsDialing(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	echo := startChainTestEcho(t)
	router := &nw3TestRouter{target: echo}
	listenPort := chainTestFreePort(t)

	server, err := NewInbound(context.Background(), router, logger, "nw3-server", option.NowhereInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: listenPort,
		},
		Password: testNw3Key,
		Net:      nowhereV3NetTCP,
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

	client, err := NewOutbound(context.Background(), router, logger, "nw3-client", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: listenPort},
		Password:      testNw3Key,
		Net:           nowhereV3NetTCP,
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

	echoRoundTrip := func() error {
		conn, err := client.DialContext(ctx, N.NetworkTCP, echo)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		payload := []byte("nw3-iface")
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if string(reply) != string(payload) {
			return fmt.Errorf("unexpected echo reply %q", reply)
		}
		return nil
	}

	require.NoError(t, echoRoundTrip())
	clientOutbound.InterfaceUpdated(context.Background())
	require.NoError(t, echoRoundTrip())
}

// nw3TestRouter routes every admitted flow to a fixed echo target, standing in
// for a default direct outbound behind the sing-box router.
type nw3TestRouter struct {
	target   M.Socksaddr
	tcpFlows atomic.Int64
	udpFlows atomic.Int64
}

func (r *nw3TestRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (r *nw3TestRouter) Close() error                                   { return nil }
func (r *nw3TestRouter) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{}
}
func (r *nw3TestRouter) HijackDNSPacket(context.Context, []byte, N.PacketWriter, adapter.InboundContext) {
}
func (r *nw3TestRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}
func (r *nw3TestRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (r *nw3TestRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.tcpFlows.Add(1)
	go func() {
		defer conn.Close()
		upstream, err := net.DialTimeout(N.NetworkTCP, r.target.String(), 5*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		go func() {
			_, _ = io.Copy(upstream, conn)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(conn, upstream)
	}()
}

func (r *nw3TestRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.udpFlows.Add(1)
	go func() {
		defer conn.Close()
		upstream, err := net.DialUDP(N.NetworkUDP, nil, r.target.UDPAddr())
		if err != nil {
			return
		}
		defer upstream.Close()
		go func() {
			buffer := buf.New()
			defer buffer.Release()
			for {
				buffer.FullReset()
				_, err := conn.ReadPacket(buffer)
				if err != nil {
					return
				}
				if _, err := upstream.Write(buffer.Bytes()); err != nil {
					return
				}
			}
		}()
		reply := make([]byte, 65535)
		for {
			n, err := upstream.Read(reply)
			if err != nil {
				return
			}
			packet := buf.As(reply[:n])
			if err := conn.WritePacket(packet, M.Socksaddr{}); err != nil {
				return
			}
		}
	}()
}

func (r *nw3TestRouter) RuleSet(tag string) (adapter.RuleSet, bool) { return nil, false }
func (r *nw3TestRouter) Rules() []adapter.Rule                      { return nil }
func (r *nw3TestRouter) NeedFindProcess() bool                      { return false }
func (r *nw3TestRouter) NeedFindNeighbor() bool                     { return false }
func (r *nw3TestRouter) NeighborResolver() adapter.NeighborResolver {
	return nil
}
func (r *nw3TestRouter) AppendTracker(adapter.ConnectionTracker) {}
func (r *nw3TestRouter) ResetNetwork()                           {}
func (r *nw3TestRouter) RuleSets() []adapter.RuleSet             { return nil }
func (r *nw3TestRouter) Rule(string) (adapter.Rule, bool)        { return nil, false }
func (r *nw3TestRouter) Reload()                                 {}
func (r *nw3TestRouter) DefaultDomainMatchStrategy() C.DomainMatchStrategy {
	return C.DomainMatchStrategy(0)
}

var _ adapter.Router = (*nw3TestRouter)(nil)
