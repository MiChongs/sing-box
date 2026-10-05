//go:build with_easytier

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// startEasyTierEchoServers starts TCP and UDP echo servers on all IPv4
// addresses.
func startEasyTierEchoServers(t *testing.T) (uint16, uint16) {
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{})
	require.NoError(t, err)
	t.Cleanup(func() { tcpListener.Close() })
	go func() {
		for {
			conn, acceptErr := tcpListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, source, readErr := udpConn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = udpConn.WriteTo(buffer[:n], source)
		}
	}()
	return uint16(tcpListener.Addr().(*net.TCPAddr).Port), uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
}

func easyTierHostIPv4(t *testing.T) netip.Addr {
	addresses, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, address := range addresses {
		prefix, parseErr := netip.ParsePrefix(address.String())
		if parseErr == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() && !prefix.Addr().IsLinkLocalUnicast() {
			return prefix.Addr()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

func easyTierFreePort(t *testing.T) uint16 {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listener.Addr().(*net.TCPAddr).Port})
	if err != nil {
		return easyTierFreePort(t)
	}
	defer udpConn.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// requireEasyTierTCPEcho waits until dial succeeds, then checks that a payload
// larger than one window comes back unchanged.
func requireEasyTierTCPEcho(t *testing.T, dial func(ctx context.Context) (net.Conn, error)) {
	t.Helper()
	var conn net.Conn
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var err error
		conn, err = dial(ctx)
		if err != nil {
			return false
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte("probe"))
		if err == nil {
			response := make([]byte, 5)
			_, err = io.ReadFull(conn, response)
		}
		if err != nil {
			conn.Close()
			return false
		}
		return true
	}, 60*time.Second, 200*time.Millisecond, "TCP echo")
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := bytes.Repeat([]byte("easytier-gateway"), 32768)
	result := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		result <- err
	}()
	received := make([]byte, len(payload))
	_, err := io.ReadFull(conn, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)
	require.NoError(t, <-result)
}

func requireEasyTierUDPEcho(t *testing.T, dial func(ctx context.Context) (net.Conn, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := dial(ctx)
	require.NoError(t, err)
	defer conn.Close()
	response := make([]byte, 2048)
	for _, size := range []int{32, 1200} {
		request := bytes.Repeat([]byte{byte(size)}, size)
		require.Eventually(t, func() bool {
			_, writeErr := conn.Write(request)
			if writeErr != nil {
				return false
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, readErr := conn.Read(response)
			return readErr == nil && bytes.Equal(request, response[:n])
		}, 30*time.Second, 100*time.Millisecond, "UDP echo of %d bytes", size)
	}
}

func easyTierEndpointDialer(endpoint adapter.Endpoint, network string, destination M.Socksaddr) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return endpoint.DialContext(ctx, network, destination)
	}
}

func hostDialer(network string, address string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}

func mappedPrefix(prefix string) *badoption.Prefix {
	value := badoption.Prefix(netip.MustParsePrefix(prefix))
	return &value
}

// TestEasyTierProxyNetworkAndPortForward covers the gateway features of a
// locally configured instance: a peer reaching a plain and a mapped proxy
// network behind the gateway, which sing-box routes, and core-owned port
// forwards from a host port to a peer's virtual address.
func TestEasyTierProxyNetworkAndPortForward(t *testing.T) {
	hostAddress := easyTierHostIPv4(t)
	echoTCPPort, echoUDPPort := startEasyTierEchoServers(t)
	serverPort := reserveEasyTierPort(t, "tcp")
	forwardTCPPort := easyTierFreePort(t)
	forwardUDPPort := easyTierFreePort(t)
	networkName := fmt.Sprintf("sing-box-gateway-%d", time.Now().UnixNano())
	listener := fmt.Sprintf("tcp://127.0.0.1:%d", serverPort)
	instance := startInstance(t, option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeEasyTier,
				Tag:  "gateway",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:   networkName,
					NetworkSecret: "secret",
					Hostname:      "gateway",
					Address:       []netip.Prefix{netip.MustParsePrefix("10.144.78.1/24")},
					Listeners:     []string{listener},
					STUNServers:   []string{"127.0.0.1:1"},
					ProxyNetworks: []option.EasyTierProxyNetworkOptions{
						{CIDR: netip.PrefixFrom(hostAddress, 32)},
						{CIDR: netip.MustParsePrefix("127.0.0.0/24"), MappedCIDR: mappedPrefix("10.99.0.0/24")},
					},
					PortForwards: []option.EasyTierPortForwardOptions{
						{Network: "tcp", Listen: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), forwardTCPPort), Destination: netip.AddrPortFrom(netip.MustParseAddr("10.144.78.2"), echoTCPPort)},
						{Network: "udp", Listen: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), forwardUDPPort), Destination: netip.AddrPortFrom(netip.MustParseAddr("10.144.78.2"), echoUDPPort)},
					},
				},
			},
			{
				Type: C.TypeEasyTier,
				Tag:  "peer",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:   networkName,
					NetworkSecret: "secret",
					Hostname:      "peer",
					Address:       []netip.Prefix{netip.MustParsePrefix("10.144.78.2/24")},
					Peers:         []string{listener},
					STUNServers:   []string{"127.0.0.1:1"},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	peer, loaded := instance.Endpoint().Get("peer")
	require.True(t, loaded)

	t.Run("proxy network", func(t *testing.T) {
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(peer, "tcp", M.SocksaddrFrom(hostAddress, echoTCPPort)))
		requireEasyTierUDPEcho(t, easyTierEndpointDialer(peer, "udp", M.SocksaddrFrom(hostAddress, echoUDPPort)))
	})
	t.Run("mapped proxy network", func(t *testing.T) {
		mapped := netip.MustParseAddr("10.99.0.1")
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(peer, "tcp", M.SocksaddrFrom(mapped, echoTCPPort)))
		requireEasyTierUDPEcho(t, easyTierEndpointDialer(peer, "udp", M.SocksaddrFrom(mapped, echoUDPPort)))
	})
	t.Run("preferred routes", func(t *testing.T) {
		preferred := peer.(adapter.OutboundWithPreferredRoutes)
		require.Eventually(t, func() bool {
			return preferred.PreferredAddress(nil, netip.MustParseAddr("10.99.0.200")) &&
				preferred.PreferredAddress(nil, hostAddress) &&
				preferred.PreferredAddress(nil, netip.MustParseAddr("10.144.78.1"))
		}, 30*time.Second, 200*time.Millisecond)
		require.False(t, preferred.PreferredAddress(nil, netip.MustParseAddr("127.0.0.1")))
	})
	t.Run("port forward", func(t *testing.T) {
		requireEasyTierTCPEcho(t, hostDialer("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(forwardTCPPort)))))
		requireEasyTierUDPEcho(t, hostDialer("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(forwardUDPPort)))))
	})
}

// TestEasyTierExitNode covers a peer sending traffic for a destination
// outside every EasyTier network to an exit node, which sing-box routes.
func TestEasyTierExitNode(t *testing.T) {
	hostAddress := easyTierHostIPv4(t)
	echoTCPPort, echoUDPPort := startEasyTierEchoServers(t)
	serverPort := reserveEasyTierPort(t, "tcp")
	networkName := fmt.Sprintf("sing-box-exit-%d", time.Now().UnixNano())
	listener := fmt.Sprintf("tcp://127.0.0.1:%d", serverPort)
	instance := startInstance(t, option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeEasyTier,
				Tag:  "exit",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:    networkName,
					NetworkSecret:  "secret",
					Address:        []netip.Prefix{netip.MustParsePrefix("10.144.80.1/24")},
					Listeners:      []string{listener},
					STUNServers:    []string{"127.0.0.1:1"},
					EnableExitNode: true,
				},
			},
			{
				Type: C.TypeEasyTier,
				Tag:  "peer",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:   networkName,
					NetworkSecret: "secret",
					Address:       []netip.Prefix{netip.MustParsePrefix("10.144.80.2/24")},
					Peers:         []string{listener},
					ExitNodes:     []netip.Addr{netip.MustParseAddr("10.144.80.1")},
					STUNServers:   []string{"127.0.0.1:1"},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	peer, loaded := instance.Endpoint().Get("peer")
	require.True(t, loaded)
	requireEasyTierTCPEcho(t, easyTierEndpointDialer(peer, "tcp", M.SocksaddrFrom(hostAddress, echoTCPPort)))
	requireEasyTierUDPEcho(t, easyTierEndpointDialer(peer, "udp", M.SocksaddrFrom(hostAddress, echoUDPPort)))
}

const easyTierWebToken = "sing-box-test"

type easyTierWebServer struct {
	apiURL     string
	configPort uint16
}

// startEasyTierWebServer runs the easytier-web binary named by the
// EASYTIER_WEB_BINARY environment variable.
func startEasyTierWebServer(t *testing.T) *easyTierWebServer {
	binary := os.Getenv("EASYTIER_WEB_BINARY")
	if binary == "" {
		t.Skip("EASYTIER_WEB_BINARY is not set")
	}
	directory := t.TempDir()
	configPort := reserveEasyTierPort(t, "udp")
	apiPort := reserveEasyTierPort(t, "tcp")
	command := exec.Command(binary,
		"--db", filepath.Join(directory, "et.db"),
		"--config-server-port", strconv.Itoa(int(configPort)),
		"--config-server-protocol", "udp",
		"--api-server-port", strconv.Itoa(int(apiPort)),
		"--api-server-addr", "127.0.0.1",
		"--allow-auto-create-user",
		"--internal-auth-token", easyTierWebToken,
		"--console-log-level", "warn",
	)
	command.Dir = directory
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	server := &easyTierWebServer{
		apiURL:     fmt.Sprintf("http://127.0.0.1:%d", apiPort),
		configPort: configPort,
	}
	require.Eventually(t, func() bool {
		_, status := server.request(t, http.MethodGet, "/api/internal/sessions", nil)
		return status == http.StatusOK
	}, 30*time.Second, 100*time.Millisecond, "easytier-web API")
	return server
}

func (s *easyTierWebServer) request(t *testing.T, method string, path string, body any) ([]byte, int) {
	var content io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		content = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, s.apiURL+path, content)
	require.NoError(t, err)
	request.Header.Set("X-Internal-Auth", easyTierWebToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, 0
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)
	return responseBody, response.StatusCode
}

// userID waits for machineID to register and returns its owner.
func (s *easyTierWebServer) userID(t *testing.T, machineID string) int {
	var userID int
	require.Eventually(t, func() bool {
		body, status := s.request(t, http.MethodGet, "/api/internal/sessions", nil)
		if status != http.StatusOK {
			return false
		}
		var sessions []struct {
			MachineID string `json:"machine_id"`
			UserID    int    `json:"user_id"`
		}
		if json.Unmarshal(body, &sessions) != nil {
			return false
		}
		for _, session := range sessions {
			if session.MachineID == machineID {
				userID = session.UserID
				return true
			}
		}
		return false
	}, 180*time.Second, 200*time.Millisecond, "Web session of machine %s", machineID)
	return userID
}

// TestEasyTierWeb covers networks assigned by an EasyTier Web configuration
// server: the endpoint attaches the instances the server creates, reaches
// the peers of two networks through one device, serves an instance's subnet
// proxy through the core's own proxy (the Web config leaves
// proxy_forward_by_system disabled) and detaches an instance when the server
// deletes its network.
func TestEasyTierWeb(t *testing.T) {
	webServer := startEasyTierWebServer(t)
	echoTCPPort, echoUDPPort := startEasyTierEchoServers(t)
	serverPort := reserveEasyTierPort(t, "tcp")
	networkName := fmt.Sprintf("sing-box-web-%d", time.Now().UnixNano())
	listener := fmt.Sprintf("tcp://127.0.0.1:%d", serverPort)
	secondServerPort := reserveEasyTierPort(t, "tcp")
	secondNetworkName := networkName + "-second"
	secondListener := fmt.Sprintf("tcp://127.0.0.1:%d", secondServerPort)
	const machineID = "11111111-2222-4333-8444-555555555555"
	instance := startInstance(t, option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeEasyTier,
				Tag:  "local",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:   networkName,
					NetworkSecret: "secret",
					Address:       []netip.Prefix{netip.MustParsePrefix("10.144.79.1/24")},
					Listeners:     []string{listener},
					STUNServers:   []string{"127.0.0.1:1"},
				},
			},
			{
				Type: C.TypeEasyTier,
				Tag:  "second",
				Options: &option.EasyTierEndpointOptions{
					NetworkName:   secondNetworkName,
					NetworkSecret: "secret",
					Address:       []netip.Prefix{netip.MustParsePrefix("10.144.81.1/24")},
					Listeners:     []string{secondListener},
					STUNServers:   []string{"127.0.0.1:1"},
				},
			},
			{
				Type: C.TypeEasyTier,
				Tag:  "web",
				Options: &option.EasyTierEndpointOptions{
					Web: &option.EasyTierWebOptions{
						Server:    fmt.Sprintf("udp://127.0.0.1:%d/sing-box", webServer.configPort),
						MachineID: machineID,
						Hostname:  "sing-box-web",
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	local, loaded := instance.Endpoint().Get("local")
	require.True(t, loaded)
	web, loaded := instance.Endpoint().Get("web")
	require.True(t, loaded)

	networksPath := fmt.Sprintf("/api/internal/users/%d/machines/%s/networks", webServer.userID(t, machineID), machineID)
	const instanceID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	body, status := webServer.request(t, http.MethodPost, networksPath, map[string]any{
		"config": map[string]any{
			"instance_id":       instanceID,
			"network_name":      networkName,
			"network_secret":    "secret",
			"dhcp":              false,
			"virtual_ipv4":      "10.144.79.2",
			"network_length":    24,
			"networking_method": 1,
			"peer_urls":         []string{listener},
			"proxy_cidrs":       []string{"127.0.0.0/24->10.98.0.0/24"},
		},
		"save": false,
	})
	require.Equal(t, http.StatusOK, status, string(body))
	const secondInstanceID = "aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff"
	body, status = webServer.request(t, http.MethodPost, networksPath, map[string]any{
		"config": map[string]any{
			"instance_id":       secondInstanceID,
			"network_name":      secondNetworkName,
			"network_secret":    "secret",
			"dhcp":              false,
			"virtual_ipv4":      "10.144.81.2",
			"network_length":    24,
			"networking_method": 1,
			"peer_urls":         []string{secondListener},
		},
		"save": false,
	})
	require.Equal(t, http.StatusOK, status, string(body))

	t.Run("peer", func(t *testing.T) {
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(web, "tcp", M.SocksaddrFrom(netip.MustParseAddr("10.144.79.1"), echoTCPPort)))
		requireEasyTierUDPEcho(t, easyTierEndpointDialer(web, "udp", M.SocksaddrFrom(netip.MustParseAddr("10.144.79.1"), echoUDPPort)))
	})
	t.Run("second network", func(t *testing.T) {
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(web, "tcp", M.SocksaddrFrom(netip.MustParseAddr("10.144.81.1"), echoTCPPort)))
		requireEasyTierUDPEcho(t, easyTierEndpointDialer(web, "udp", M.SocksaddrFrom(netip.MustParseAddr("10.144.81.1"), echoUDPPort)))
		// Connections into each network start from that network's address.
		var sources [2]string
		for i, peer := range []netip.Addr{netip.MustParseAddr("10.144.79.1"), netip.MustParseAddr("10.144.81.1")} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			conn, err := web.DialContext(ctx, "tcp", M.SocksaddrFrom(peer, echoTCPPort))
			cancel()
			require.NoError(t, err)
			sources[i] = M.SocksaddrFromNet(conn.LocalAddr()).Addr.String()
			conn.Close()
		}
		require.Equal(t, [2]string{"10.144.79.2", "10.144.81.2"}, sources)
		second, loaded := instance.Endpoint().Get("second")
		require.True(t, loaded)
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(second, "tcp", M.SocksaddrFrom(netip.MustParseAddr("10.144.81.2"), echoTCPPort)))
	})
	t.Run("core subnet proxy", func(t *testing.T) {
		mapped := netip.MustParseAddr("10.98.0.1")
		requireEasyTierTCPEcho(t, easyTierEndpointDialer(local, "tcp", M.SocksaddrFrom(mapped, echoTCPPort)))
		requireEasyTierUDPEcho(t, easyTierEndpointDialer(local, "udp", M.SocksaddrFrom(mapped, echoUDPPort)))
	})
	t.Run("delete", func(t *testing.T) {
		body, status := webServer.request(t, http.MethodDelete, networksPath+"/"+instanceID, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		require.Eventually(t, func() bool {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := web.DialContext(ctx, "tcp", M.SocksaddrFrom(netip.MustParseAddr("10.144.79.1"), echoTCPPort))
			if err == nil {
				conn.Close()
				return false
			}
			return true
		}, 30*time.Second, 200*time.Millisecond, "detach deleted Web instance")
	})
}
