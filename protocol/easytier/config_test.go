package easytier

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	corehost "github.com/easytier/easytier/easytier-go"
	etcommon "github.com/easytier/easytier/easytier-go/proto/common"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestParseAddress(t *testing.T) {
	t.Parallel()
	address, err := parseAddress([]netip.Prefix{netip.MustParsePrefix("10.144.0.1/24"), netip.MustParsePrefix("fd00::1/64")})
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("10.144.0.1/24"), address.inet4)
	require.Equal(t, netip.MustParsePrefix("fd00::1/64"), address.inet6)
	_, err = parseAddress([]netip.Prefix{netip.MustParsePrefix("10.144.0.1/32")})
	require.Error(t, err)
	_, err = parseAddress([]netip.Prefix{netip.MustParsePrefix("10.144.0.1/24"), netip.MustParsePrefix("10.144.0.2/24")})
	require.Error(t, err)
}

func mappedCIDR(prefix string) *badoption.Prefix {
	value := badoption.Prefix(netip.MustParsePrefix(prefix))
	return &value
}

func TestBuildConfig(t *testing.T) {
	t.Parallel()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := option.EasyTierEndpointOptions{
		NetworkName:   "office",
		NetworkSecret: `se"cret`,
		Hostname:      "node",
		Peers:         []string{"tcp://198.51.100.10:11010"},
		Listeners:     []string{"udp://0.0.0.0:11010"},
		ProxyNetworks: []option.EasyTierProxyNetworkOptions{
			{CIDR: netip.MustParsePrefix("192.168.1.0/24")},
			{CIDR: netip.MustParsePrefix("192.168.2.1/24"), MappedCIDR: mappedCIDR("10.2.0.0/24")},
		},
		EnableExitNode: true,
		ExitNodes:      []netip.Addr{netip.MustParseAddr("10.144.0.2")},
		PortForwards: []option.EasyTierPortForwardOptions{
			{Listen: netip.MustParseAddrPort("127.0.0.1:5353"), Destination: netip.MustParseAddrPort("10.144.0.3:53")},
			{Network: "tcp", Listen: netip.MustParseAddrPort("0.0.0.0:8080"), Destination: netip.MustParseAddrPort("10.144.0.3:80")},
		},
		EncryptionAlgorithm:   "chacha20",
		SecureMode:            &option.EasyTierSecureModeOptions{Enabled: true, PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Bytes())},
		LazyP2P:               true,
		RelayNetworkWhitelist: []string{"office", "lab*"},
	}
	address, err := parseAddress([]netip.Prefix{netip.MustParsePrefix("10.144.0.1/24")})
	require.NoError(t, err)
	config, err := buildConfig(options, address, 1360)
	require.NoError(t, err)
	require.Equal(t, `hostname = "node"
ipv4 = "10.144.0.1/24"
listeners = ["udp://0.0.0.0:11010"]
exit_nodes = ["10.144.0.2"]

[network_identity]
network_name = "office"
network_secret = "se\"cret"

[[peer]]
uri = "tcp://198.51.100.10:11010"

[[proxy_network]]
cidr = "192.168.1.0/24"

[[proxy_network]]
cidr = "192.168.2.0/24"
mapped_cidr = "10.2.0.0/24"

[[port_forward]]
bind_addr = "127.0.0.1:5353"
dst_addr = "10.144.0.3:53"
proto = "tcp"

[[port_forward]]
bind_addr = "127.0.0.1:5353"
dst_addr = "10.144.0.3:53"
proto = "udp"

[[port_forward]]
bind_addr = "0.0.0.0:8080"
dst_addr = "10.144.0.3:80"
proto = "tcp"

[flags]
mtu = 1360
proxy_forward_by_system = true
enable_exit_node = true
enable_encryption = true
encryption_algorithm = "chacha20"
disable_p2p = false
lazy_p2p = true
need_p2p = false
p2p_only = false
disable_tcp_hole_punching = false
disable_udp_hole_punching = false
disable_sym_hole_punching = false
latency_first = false
private_mode = false
relay_all_peer_rpc = false
relay_network_whitelist = "office lab*"

[secure_mode]
enabled = true
local_private_key = "`+base64.StdEncoding.EncodeToString(privateKey.Bytes())+`"
local_public_key = "`+base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())+`"
`, config)
}

func TestBuildConfigDHCP(t *testing.T) {
	t.Parallel()
	config, err := buildConfig(option.EasyTierEndpointOptions{NetworkName: "office", Hostname: "node"}, addressConfig{}, defaultMTU)
	require.NoError(t, err)
	require.Contains(t, config, "\ndhcp = true\n")
	require.NotContains(t, config, "ipv4 =")
}

func TestBuildConfigInvalid(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]option.EasyTierEndpointOptions{
		"missing network name": {},
		"long hostname":        {NetworkName: "office", Hostname: "0123456789012345678901234567890123"},
		"padded peer":          {NetworkName: "office", Peers: []string{" tcp://198.51.100.10:11010"}},
		"secure mode secret":   {NetworkName: "office", SecureMode: &option.EasyTierSecureModeOptions{Enabled: true}},
		"secure mode key":      {NetworkName: "office", NetworkSecret: "secret", SecureMode: &option.EasyTierSecureModeOptions{Enabled: true, PrivateKey: "AAAA"}},
		"IPv6 proxy network": {NetworkName: "office", ProxyNetworks: []option.EasyTierProxyNetworkOptions{
			{CIDR: netip.MustParsePrefix("fd00::/64")},
		}},
		"mapped size": {NetworkName: "office", ProxyNetworks: []option.EasyTierProxyNetworkOptions{
			{CIDR: netip.MustParsePrefix("192.168.1.0/24"), MappedCIDR: mappedCIDR("10.1.0.0/16")},
		}},
		"duplicate proxy network": {NetworkName: "office", ProxyNetworks: []option.EasyTierProxyNetworkOptions{
			{CIDR: netip.MustParsePrefix("192.168.1.0/24")},
			{CIDR: netip.MustParsePrefix("192.168.2.0/24"), MappedCIDR: mappedCIDR("192.168.1.0/24")},
		}},
		"port forward listen": {NetworkName: "office", PortForwards: []option.EasyTierPortForwardOptions{
			{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Destination: netip.MustParseAddrPort("10.144.0.3:53")},
		}},
		"port forward destination": {NetworkName: "office", PortForwards: []option.EasyTierPortForwardOptions{
			{Listen: netip.MustParseAddrPort("127.0.0.1:53"), Destination: netip.MustParseAddrPort("0.0.0.0:53")},
		}},
		"duplicate port forward": {NetworkName: "office", PortForwards: []option.EasyTierPortForwardOptions{
			{Network: "udp", Listen: netip.MustParseAddrPort("127.0.0.1:53"), Destination: netip.MustParseAddrPort("10.144.0.3:53")},
			{Listen: netip.MustParseAddrPort("127.0.0.1:53"), Destination: netip.MustParseAddrPort("10.144.0.4:53")},
		}},
	} {
		_, err := buildConfig(options, addressConfig{}, defaultMTU)
		require.Error(t, err, name)
	}
}

func TestProxyMapping(t *testing.T) {
	t.Parallel()
	mappings, err := parseProxyNetworks([]option.EasyTierProxyNetworkOptions{
		{CIDR: netip.MustParsePrefix("192.168.16.0/20"), MappedCIDR: mappedCIDR("10.7.32.0/20")},
	})
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	translated, ok := mappings[0].translate(netip.MustParseAddr("10.7.47.200"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("192.168.31.200"), translated)
	_, ok = mappings[0].translate(netip.MustParseAddr("10.7.48.1"))
	require.False(t, ok)

	require.Equal(t, []proxyMapping{{
		realPrefix:   netip.MustParsePrefix("192.168.88.0/24"),
		mappedPrefix: netip.MustParsePrefix("10.88.0.0/24"),
	}, {
		realPrefix:   netip.MustParsePrefix("192.168.88.9/32"),
		mappedPrefix: netip.MustParsePrefix("10.88.0.9/32"),
	}}, parseNodeProxyCIDRs([]string{"192.168.77.0/24", "192.168.88.0/24->10.88.0.0/24", "192.168.88.9->10.88.0.9", "bad->10.0.0.0/8"}))
}

func TestRoutePrefixes(t *testing.T) {
	t.Parallel()
	routes := []*corehost.Route{{
		Ipv4Addr: &etcommon.Ipv4Inet{
			Address:       &etcommon.Ipv4Addr{Addr: 0x0a900002},
			NetworkLength: 24,
		},
		Ipv6Addr: &etcommon.Ipv6Inet{
			Address:       &etcommon.Ipv6Addr{Part1: 0xfd000000, Part4: 2},
			NetworkLength: 64,
		},
		ProxyCidrs: []string{"192.168.1.1/24", "198.51.100.7", "invalid"},
	}}
	prefixes := routePrefixes([]netip.Prefix{netip.MustParsePrefix("10.144.0.1/24")}, routes)
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.144.0.0/24"),
		netip.MustParsePrefix("10.144.0.2/32"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("fd00::2/128"),
	}, prefixes)
}

func testInstance(name string, addresses []string, routes []string, mappings []proxyMapping) *attachedInstance {
	instance := &attachedInstance{name: name}
	state := &instanceState{configured: true, mappings: mappings}
	for _, address := range addresses {
		state.addresses = append(state.addresses, netip.MustParsePrefix(address))
	}
	for _, route := range routes {
		state.routes = append(state.routes, netip.MustParsePrefix(route))
	}
	instance.state.Store(state)
	return instance
}

func TestRoutingSnapshot(t *testing.T) {
	t.Parallel()
	office := testInstance("office", []string{"10.144.0.1/24", "fd00::1/64"}, []string{"10.144.0.0/24", "10.144.0.2/32", "192.168.0.0/16"}, nil)
	lab := testInstance("lab", []string{"10.200.0.5/24"}, []string{"10.200.0.0/24", "192.168.7.0/24"}, []proxyMapping{{
		realPrefix:   netip.MustParsePrefix("172.16.0.0/24"),
		mappedPrefix: netip.MustParsePrefix("10.99.0.0/24"),
	}})
	pending := &attachedInstance{name: "pending"}
	pending.state.Store(&instanceState{})
	snapshot := newRoutingSnapshot([]*attachedInstance{office, pending, lab})

	require.Equal(t, []*attachedInstance{office, lab}, snapshot.instances)
	require.True(t, snapshot.isLocalAddress(netip.MustParseAddr("10.200.0.5")))
	// The longest route wins over the primary instance's wider proxy network.
	require.Equal(t, lab, snapshot.destinationInstance(netip.MustParseAddr("192.168.7.9")))
	require.Equal(t, office, snapshot.destinationInstance(netip.MustParseAddr("192.168.8.9")))
	// Destinations outside every network use the primary instance.
	require.Equal(t, office, snapshot.destinationInstance(netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, netip.MustParseAddr("10.200.0.5"), snapshot.sourceAddress(netip.MustParseAddr("10.200.0.9")))
	require.Equal(t, netip.MustParseAddr("fd00::1"), snapshot.sourceAddress(netip.MustParseAddr("fd00::9")))
	require.False(t, snapshot.sourceAddress(netip.MustParseAddr("fd01::9")).Is4())
	// The source address owns a packet even when another network routes the
	// destination; replies from proxied networks follow the destination.
	require.Equal(t, lab, snapshot.outgoingInstance(netip.MustParseAddr("10.200.0.5"), netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, lab, snapshot.outgoingInstance(netip.MustParseAddr("172.16.0.4"), netip.MustParseAddr("10.200.0.9")))
	translated, mapped := snapshot.translateMapped(netip.MustParseAddr("10.99.0.4"))
	require.True(t, mapped)
	require.Equal(t, netip.MustParseAddr("172.16.0.4"), translated)
	require.True(t, snapshot.preferred(netip.MustParseAddr("192.168.200.1")))
	require.False(t, snapshot.preferred(netip.MustParseAddr("8.8.8.8")))
}

func TestPacketAddresses(t *testing.T) {
	t.Parallel()
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	source, destination, valid := packetAddresses(packet)
	require.True(t, valid)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), source)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), destination)
	_, _, valid = packetAddresses(packet[:19])
	require.False(t, valid)
	packet6 := make([]byte, 40)
	packet6[0] = 0x60
	packet6[39] = 1
	_, destination, valid = packetAddresses(packet6)
	require.True(t, valid)
	require.Equal(t, netip.MustParseAddr("::1"), destination)
}

func TestTOMLString(t *testing.T) {
	t.Parallel()
	document := `hostname = "node"
ipv6 = "fd00::1/64"

[network_identity]
network_name = "office \"main\""

[[peer]]
uri = "tcp://198.51.100.10:11010"
`
	require.Equal(t, "fd00::1/64", tomlString(document, "", "ipv6"))
	require.Equal(t, `office "main"`, tomlString(document, "network_identity", "network_name"))
	require.Equal(t, "", tomlString(document, "", "network_name"))
}

func TestWebClientOptions(t *testing.T) {
	t.Parallel()
	options, err := newWebClientOptions(option.EasyTierEndpointOptions{
		Hostname: "node",
		Web:      &option.EasyTierWebOptions{Server: "udp://127.0.0.1:22020/user"},
	}, "easytier")
	require.NoError(t, err)
	parsed, err := uuid.FromString(options.MachineID)
	require.NoError(t, err)
	require.Equal(t, byte(5), parsed.Version())
	require.Equal(t, defaultMachineID("easytier"), options.MachineID)
	require.NotEqual(t, defaultMachineID("other"), options.MachineID)
	require.Equal(t, "node", options.Hostname)

	options, err = newWebClientOptions(option.EasyTierEndpointOptions{
		Web: &option.EasyTierWebOptions{Server: "tcp://config.example.com:22020/user", MachineID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", Hostname: "web"},
	}, "easytier")
	require.NoError(t, err)
	require.Equal(t, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", options.MachineID)
	require.Equal(t, "web", options.Hostname)

	for _, server := range []string{"", "user", "ws://config.example.com/user", "udp://config.example.com:22020", "udp:///user"} {
		_, err = newWebClientOptions(option.EasyTierEndpointOptions{Web: &option.EasyTierWebOptions{Server: server}}, "easytier")
		require.Error(t, err, server)
	}
	_, err = newWebClientOptions(option.EasyTierEndpointOptions{Web: &option.EasyTierWebOptions{Server: "udp://config.example.com:22020/user", MachineID: "machine"}}, "easytier")
	require.Error(t, err)
}

func TestProxyNATListener(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := &Endpoint{ctx: ctx, proxyNATListeners: make(map[uint16]*proxyNATListener)}
	listener, err := endpoint.newProxyNATListener()
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.Same(t, listener, endpoint.proxyNATListenerFor(port))
	// The port is held on the host loopback.
	_, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	require.Error(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	var closed bool
	conn := &proxyNATConn{
		Conn:       serverConn,
		localAddr:  &net.TCPAddr{IP: net.IPv4(10, 144, 0, 1), Port: int(port)},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(10, 144, 0, 2), Port: 1},
		onClose:    func(error) { closed = true },
	}
	require.True(t, listener.(*proxyNATListener).deliver(conn))
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.Equal(t, "10.144.0.2:1", accepted.RemoteAddr().String())
	require.NoError(t, accepted.Close())
	require.True(t, closed)

	require.NoError(t, listener.Close())
	require.Nil(t, endpoint.proxyNATListenerFor(port))
	_, err = listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestDatagramConnUnmapsPeer(t *testing.T) {
	t.Parallel()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skip("dual-stack UDP is unavailable: ", err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: server.LocalAddr().(*net.UDPAddr).Port})
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)
	conn := newDatagramConn(server)
	buffer := make([]byte, 16)
	_, peer, err := conn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Len(t, peer.(*net.UDPAddr).IP, net.IPv4len)
}
