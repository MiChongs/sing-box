//go:build with_easytier

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestEasyTierEndpointDataPlane(t *testing.T) {
	for _, tunnel := range []string{"tcp", "udp"} {
		t.Run(tunnel, func(test *testing.T) {
			serverPort := reserveEasyTierPort(test, tunnel)
			serverAddress := netip.MustParsePrefix("10.144.77.1/24")
			listener := fmt.Sprintf("%s://127.0.0.1:%d", tunnel, serverPort)
			// The UDP case leaves the client address empty to cover DHCP.
			var clientAddress badoption.Listable[netip.Prefix]
			if tunnel == "tcp" {
				clientAddress = []netip.Prefix{netip.MustParsePrefix("10.144.77.2/24")}
			}
			networkName := fmt.Sprintf("sing-box-test-%s-%d", tunnel, time.Now().UnixNano())
			instance := startInstance(test, option.Options{
				Endpoints: []option.Endpoint{
					{
						Type: C.TypeEasyTier,
						Tag:  "server",
						Options: &option.EasyTierEndpointOptions{
							NetworkName:   networkName,
							NetworkSecret: "secret",
							Hostname:      "server",
							Address:       []netip.Prefix{serverAddress},
							Listeners:     []string{listener},
							STUNServers:   []string{"127.0.0.1:1"},
						},
					},
					{
						Type: C.TypeEasyTier,
						Tag:  "client",
						Options: &option.EasyTierEndpointOptions{
							NetworkName:   networkName,
							NetworkSecret: "secret",
							Hostname:      "client",
							Address:       clientAddress,
							Peers:         []string{listener},
							STUNServers:   []string{"127.0.0.1:1"},
						},
					},
				},
				Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
				Route:     &option.RouteOptions{Final: "direct"},
			})
			endpoint, loaded := instance.Endpoint().Get("client")
			require.True(test, loaded)

			// Connections to the server's virtual address are delivered to
			// its loopback address.
			tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(test, err)
			defer tcpListener.Close()
			destination := M.SocksaddrFrom(serverAddress.Addr(), uint16(tcpListener.Addr().(*net.TCPAddr).Port))
			var client net.Conn
			require.Eventually(test, func() bool {
				ctx, cancel := context.WithTimeout(test.Context(), 5*time.Second)
				defer cancel()
				client, err = endpoint.DialContext(ctx, "tcp", destination)
				return err == nil
			}, 60*time.Second, 100*time.Millisecond, "dial over EasyTier")
			defer client.Close()
			tcpListener.SetDeadline(time.Now().Add(10 * time.Second))
			server, err := tcpListener.Accept()
			require.NoError(test, err)
			defer server.Close()
			client.SetDeadline(time.Now().Add(10 * time.Second))
			server.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("easytier-overlay-tcp"), 65536)
			for _, pair := range [][2]net.Conn{{client, server}, {server, client}} {
				result := make(chan error, 1)
				go func() {
					_, writeErr := pair[0].Write(payload)
					result <- writeErr
				}()
				received := make([]byte, len(payload))
				_, readErr := io.ReadFull(pair[1], received)
				require.NoError(test, readErr)
				require.Equal(test, payload, received)
				require.NoError(test, <-result)
			}

			udpServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(test, err)
			defer udpServer.Close()
			udpServer.SetDeadline(time.Now().Add(10 * time.Second))
			udpDestination := M.SocksaddrFrom(serverAddress.Addr(), uint16(udpServer.LocalAddr().(*net.UDPAddr).Port))
			ctx, cancel := context.WithTimeout(test.Context(), 10*time.Second)
			defer cancel()
			udpClient, err := endpoint.DialContext(ctx, "udp", udpDestination)
			require.NoError(test, err)
			defer udpClient.Close()
			udpClient.SetDeadline(time.Now().Add(10 * time.Second))
			for _, size := range []int{64, 1200} {
				request := bytes.Repeat([]byte{0x65}, size)
				_, err = udpClient.Write(request)
				require.NoError(test, err)
				received := make([]byte, 65535)
				count, source, readErr := udpServer.ReadFromUDP(received)
				require.NoError(test, readErr)
				require.Equal(test, request, received[:count])
				_, err = udpServer.WriteToUDP(request, source)
				require.NoError(test, err)
				count, err = udpClient.Read(received)
				require.NoError(test, err)
				require.Equal(test, request, received[:count])
			}
		})
	}
}

func reserveEasyTierPort(t *testing.T, network string) uint16 {
	if network == "tcp" {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		defer listener.Close()
		return uint16(listener.Addr().(*net.TCPAddr).Port)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}
