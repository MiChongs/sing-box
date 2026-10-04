//go:build with_quic

package v2rayxhttp

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestE2E_HTTP3(t *testing.T) {
	tlsConfig := newTestTLSServer(t, "h3")
	server, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{Path: "/xhttp"}, tlsConfig, echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	if !common.Contains(server.Network(), N.NetworkUDP) || common.Contains(server.Network(), N.NetworkTCP) {
		t.Fatalf("h3 server should listen on UDP only, got %v", server.Network())
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.ServePacket(packetConn)
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
	})
	serverAddr := M.SocksaddrFromNet(packetConn.LocalAddr())
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			client := newTestClient(t, smallPosts(option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}), serverAddr, newTestTLSClient(t, "example.com", "h3"))
			checkEcho(t, client, 4, 512*1024)
		})
	}
}

// 上行走 HTTP/3 (UDP)，下行走明文 HTTP/1.1 (TCP)，两个入口共用同一个 Server 的 session 表。
func TestE2E_DownloadSettingsAcrossHTTPVersions(t *testing.T) {
	h3TLSConfig := newTestTLSServer(t, "h3")
	serverInstance, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{Path: "/xhttp"}, h3TLSConfig, echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	server := serverInstance.(*Server)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.ServePacket(packetConn)
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
	})

	// 下行入口: 明文 HTTP/1.1，复用同一个 Server 的 ServeHTTP
	downloadAddr := startSharedHTTPEntry(t, server)
	client := newTestClient(t, smallPosts(option.V2RayXHTTPOptions{
		Path: "/xhttp",
		Mode: "packet-up",
		DownloadSettings: &option.V2RayXHTTPDownloadOptions{
			ServerOptions:     option.ServerOptions{Server: downloadAddr.AddrString(), ServerPort: downloadAddr.Port},
			V2RayXHTTPOptions: option.V2RayXHTTPOptions{Path: "/xhttp"},
		},
	}), M.SocksaddrFromNet(packetConn.LocalAddr()), newTestTLSClient(t, "example.com", "h3"))
	checkEcho(t, client, 3, 256*1024)
}
