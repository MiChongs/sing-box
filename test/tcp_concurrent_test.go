package main

import (
	std_bufio "bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

type tcpConcurrentAPIStatus struct {
	Enabled    bool `json:"enabled"`
	Statistics struct {
		Races    uint64 `json:"races"`
		Attempts uint64 `json:"attempts"`
	} `json:"statistics"`
	Destinations []struct {
		Host    string `json:"host"`
		Port    uint16 `json:"port"`
		Address string `json:"address"`
	} `json:"destinations"`
	Failures []struct {
		Address string `json:"address"`
	} `json:"failures"`
}

func tcpConcurrentHosts(tag string, entries map[string][]string) option.DNSServerOptions {
	hosts := new(badjson.TypedMap[string, option.HostsDNSPredefinedValue])
	for domain, addresses := range entries {
		hosts.Put(domain, option.HostsDNSPredefinedValue{Addresses: common.Map(addresses, netip.MustParseAddr)})
	}
	return option.DNSServerOptions{Type: C.DNSTypeHosts, Tag: tag, Options: &option.HostsDNSServerOptions{Predefined: hosts}}
}

func tcpConcurrentRule(domain string, action option.RuleAction) option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Domain: badoption.Listable[string]{domain}},
			RuleAction:     action,
		},
	}
}

func tcpConcurrentRoute(outbound string) option.RuleAction {
	return option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: outbound}}
}

func tcpConcurrentResolve(server string) option.RuleAction {
	return option.RuleAction{Action: C.RuleActionTypeResolve, ResolveOptions: option.RouteActionResolve{Server: server}}
}

func tcpConcurrentAPI(t *testing.T, apiPort uint16, method string, path string, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(int(apiPort))+path, strings.NewReader(body))
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func tcpConcurrentStatus(t *testing.T, apiPort uint16) tcpConcurrentAPIStatus {
	t.Helper()
	response := tcpConcurrentAPI(t, apiPort, http.MethodGet, "/dns/tcp-concurrent", "")
	require.Equal(t, http.StatusOK, response.StatusCode)
	var status tcpConcurrentAPIStatus
	require.NoError(t, json.NewDecoder(response.Body).Decode(&status))
	return status
}

func tcpConcurrentWinner(status tcpConcurrentAPIStatus, host string, port uint16) string {
	for _, destination := range status.Destinations {
		if destination.Host == host && destination.Port == port {
			return destination.Address
		}
	}
	return ""
}

// serveTCPConcurrentTest accepts on 127.0.0.1 only, so the same port refuses
// connections on 127.0.0.2, and closes every connection when the test ends.
func serveTCPConcurrentTest(t *testing.T, port uint16, handle func(conn net.Conn)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
	require.NoError(t, err)
	var (
		access sync.Mutex
		conns  []net.Conn
		group  sync.WaitGroup
	)
	t.Cleanup(func() {
		listener.Close()
		access.Lock()
		for _, conn := range conns {
			conn.Close()
		}
		access.Unlock()
		group.Wait()
	})
	group.Add(1)
	go func() {
		defer group.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			access.Lock()
			conns = append(conns, conn)
			access.Unlock()
			group.Add(1)
			go func() {
				defer group.Done()
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
}

func startTCPConcurrentEcho(t *testing.T, port uint16) {
	serveTCPConcurrentTest(t, port, func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
}

// startConfirmingHTTPProxy answers CONNECT only after reaching the target, like
// Squid, unlike sing-box's HTTP inbound, which answers at once. Successful
// answers wait a little, so refused targets fail before the race is decided.
func startConfirmingHTTPProxy(t *testing.T, port uint16) {
	serveTCPConcurrentTest(t, port, func(conn net.Conn) {
		request, readErr := http.ReadRequest(std_bufio.NewReader(conn))
		if readErr != nil || request.Method != http.MethodConnect {
			return
		}
		target, dialErr := net.DialTimeout("tcp", request.Host, 5*time.Second)
		if dialErr != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer target.Close()
		time.Sleep(50 * time.Millisecond)
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(target, conn)
			target.Close()
		}()
		_, _ = io.Copy(conn, target)
		conn.Close()
		<-done
	})
}

func tcpConcurrentEcho(t *testing.T, proxyPort uint16, destination M.Socksaddr) time.Duration {
	t.Helper()
	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", proxyPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startedAt := time.Now()
	conn, err := client.DialContext(ctx, N.NetworkTCP, destination)
	require.NoError(t, err, destination.String())
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, destination.String())
	require.Equal(t, "ping", string(reply))
	return time.Since(startedAt)
}

// TestTCPConcurrentSelf races every domain on [127.0.0.2, 127.0.0.1], where
// 127.0.0.2 refuses the echo port, through each dial path that resolves
// addresses: direct outbounds, SOCKS and HTTP proxies for route-resolved
// addresses, the proxy server address itself and a detour.
func TestTCPConcurrentSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("127.0.0.2 is a local address on Linux only")
	}
	entryPort, upstreamPort, apiPort := reserveOpenVPNTCPPort(t), reserveOpenVPNTCPPort(t), reserveOpenVPNTCPPort(t)
	httpProxyPort := reserveOpenVPNTCPPort(t)
	echoPort := reserveOpenVPNEchoPort(t)
	startTCPConcurrentEcho(t, echoPort)
	startConfirmingHTTPProxy(t, httpProxyPort)
	multi := []string{"127.0.0.2", "127.0.0.1"}
	hosts := map[string][]string{"proxy.test": multi, "serial.test": multi, "socks-default.test": multi}
	targets := []string{"direct.test", "socks.test", "socks-resolved.test", "http-resolved.test", "direct-resolved.test", "detour.test"}
	for _, target := range targets {
		hosts[target] = multi
	}
	listen := func(port uint16) option.ListenOptions {
		return option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))), ListenPort: port}
	}
	resolver := &option.DomainResolveOptions{Server: "hosts"}
	enabled := common.Ptr(true)
	startInstance(t, option.Options{
		DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers:       []option.DNSServerOptions{tcpConcurrentHosts("hosts", hosts)},
			Final:         "hosts",
			TCPConcurrent: &option.TCPConcurrentOptions{Enabled: true},
		}},
		Inbounds: []option.Inbound{
			{Type: C.TypeMixed, Tag: "entry", Options: &option.HTTPMixedInboundOptions{ListenOptions: listen(entryPort)}},
			{Type: C.TypeMixed, Tag: "upstream", Options: &option.HTTPMixedInboundOptions{ListenOptions: listen(upstreamPort)}},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{
				DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: resolver}},
			}},
			// sing-box's SOCKS inbound replies once it reached the destination,
			// so destinations may race through it.
			{Type: C.TypeSOCKS, Tag: "via-socks", Options: &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "proxy.test", ServerPort: upstreamPort},
				DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: resolver, TCPConcurrent: enabled}},
			}},
			{Type: C.TypeSOCKS, Tag: "via-socks-default", Options: &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: upstreamPort},
			}},
			{Type: C.TypeHTTP, Tag: "via-http", Options: &option.HTTPOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: httpProxyPort},
				DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPConcurrent: enabled}},
			}},
			{Type: C.TypeSOCKS, Tag: "via-detour", Options: &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "proxy.test", ServerPort: upstreamPort},
				DialerOptions: option.DialerOptions{Detour: "direct", AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver:   resolver,
					ResolverOnDetour: true,
				}},
			}},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{Inbound: badoption.Listable[string]{"upstream"}},
						RuleAction:     tcpConcurrentRoute("direct"),
					},
				},
				tcpConcurrentRule("direct.test", tcpConcurrentRoute("direct")),
				tcpConcurrentRule("socks.test", tcpConcurrentRoute("via-socks")),
				tcpConcurrentRule("socks-resolved.test", tcpConcurrentResolve("hosts")),
				tcpConcurrentRule("socks-resolved.test", tcpConcurrentRoute("via-socks")),
				tcpConcurrentRule("http-resolved.test", tcpConcurrentResolve("hosts")),
				tcpConcurrentRule("http-resolved.test", tcpConcurrentRoute("via-http")),
				tcpConcurrentRule("direct-resolved.test", tcpConcurrentResolve("hosts")),
				tcpConcurrentRule("direct-resolved.test", tcpConcurrentRoute("direct")),
				tcpConcurrentRule("detour.test", tcpConcurrentRoute("via-detour")),
				tcpConcurrentRule("socks-default.test", tcpConcurrentResolve("hosts")),
				tcpConcurrentRule("socks-default.test", tcpConcurrentRoute("via-socks-default")),
			},
			Final:                 "direct",
			DefaultDomainResolver: resolver,
		},
		Experimental: &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{ExternalController: "127.0.0.1:" + strconv.Itoa(int(apiPort))},
		},
	})

	for _, target := range targets {
		tcpConcurrentEcho(t, entryPort, M.ParseSocksaddrHostPort(target, echoPort))
	}
	status := tcpConcurrentStatus(t, apiPort)
	require.True(t, status.Enabled)
	for _, target := range targets {
		require.Equal(t, "127.0.0.1", tcpConcurrentWinner(status, target, echoPort), target)
	}
	require.Equal(t, "127.0.0.1", tcpConcurrentWinner(status, "proxy.test", upstreamPort), "the SOCKS server address races too")
	require.GreaterOrEqual(t, status.Statistics.Races, uint64(len(targets)+1))

	// Without its own tcp_concurrent, a proxy outbound does not race
	// destinations: whether the server confirms them is up to the server.
	races := tcpConcurrentStatus(t, apiPort).Statistics.Races
	tcpConcurrentEcho(t, entryPort, M.ParseSocksaddrHostPort("socks-default.test", echoPort))
	status = tcpConcurrentStatus(t, apiPort)
	require.Equal(t, "", tcpConcurrentWinner(status, "socks-default.test", echoPort))
	require.Equal(t, races, status.Statistics.Races)
	// The HTTP proxy refuses 127.0.0.2 before it confirms 127.0.0.1.
	require.Contains(t, common.Map(status.Failures, func(it struct {
		Address string `json:"address"`
	}) string {
		return it.Address
	}), "127.0.0.2:"+strconv.Itoa(int(echoPort)), "refusals are remembered per address and port")

	// The Clash API switches it off at runtime like mihomo's tcp-concurrent.
	require.Equal(t, http.StatusNoContent, tcpConcurrentAPI(t, apiPort, http.MethodPatch, "/configs", `{"tcp-concurrent": false}`).StatusCode)
	var configs map[string]any
	require.NoError(t, json.NewDecoder(tcpConcurrentAPI(t, apiPort, http.MethodGet, "/configs", "").Body).Decode(&configs))
	require.Equal(t, false, configs["tcp-concurrent"])
	races = tcpConcurrentStatus(t, apiPort).Statistics.Races
	tcpConcurrentEcho(t, entryPort, M.ParseSocksaddrHostPort("serial.test", echoPort))
	status = tcpConcurrentStatus(t, apiPort)
	require.False(t, status.Enabled)
	require.Equal(t, races, status.Statistics.Races, "a disabled switch dials one address after another")
	require.Empty(t, tcpConcurrentWinner(status, "serial.test", echoPort))

	require.Equal(t, http.StatusNoContent, tcpConcurrentAPI(t, apiPort, http.MethodDelete, "/dns/tcp-concurrent", "").StatusCode)
	status = tcpConcurrentStatus(t, apiPort)
	require.Empty(t, status.Destinations)
	require.Empty(t, status.Failures)
}

// TestMASQUETCPConcurrent races addresses inside the tunnel: 10.8.0.99 is in
// the server's prefix but belongs to nobody, so a serial dial would wait on it.
func TestMASQUETCPConcurrent(t *testing.T) {
	apiPort := reserveOpenVPNTCPPort(t)
	tunnel := []string{"10.8.0.99", masqueServerAddress}
	environment := startMASQUEConfigured(t, []int{1}, 1, true, 0, nil, nil, func(server, client *option.Options) {
		client.DNS = &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{
				tcpConcurrentHosts("default", nil),
				tcpConcurrentHosts("inner", map[string][]string{"tunnel.invalid": tunnel, "routed.invalid": tunnel}),
			},
			Final:         "default",
			TCPConcurrent: &option.TCPConcurrentOptions{Enabled: true},
		}}
		client.Endpoints[0].Options.(*option.MASQUEClientEndpointOptions).InnerDomainResolver = &option.DomainResolveOptions{Server: "inner"}
		client.Route.Rules = append([]option.Rule{tcpConcurrentRule("routed.invalid", tcpConcurrentResolve("inner"))}, client.Route.Rules...)
		client.Experimental = &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{ExternalController: "127.0.0.1:" + strconv.Itoa(int(apiPort))},
		}
	})
	for _, target := range []string{"tunnel.invalid", "routed.invalid"} {
		echoPort := reserveOpenVPNEchoPort(t)
		var elapsed time.Duration
		require.NoError(t, testOpenVPNEchoWithConn(echoPort, func() (net.Conn, error) {
			client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", environment.clientProxyPort), socks.Version5, "", "")
			startedAt := time.Now()
			conn, err := client.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort(target, echoPort))
			elapsed = time.Since(startedAt)
			return conn, err
		}), target)
		require.Less(t, elapsed, 3*time.Second, target)
		require.Equal(t, masqueServerAddress, tcpConcurrentWinner(tcpConcurrentStatus(t, apiPort), target, echoPort), target)
	}
}
