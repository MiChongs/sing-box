package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	carriermux "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/mux"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type muxEchoUpstream struct {
	got chan []byte
}

func (u *muxEchoUpstream) HandleStream(_ context.Context, conn net.Conn, _ net.Addr, _ wire.Target, readiness FlowReadiness) error {
	if err := readiness.Ready(); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n > 0 {
		select {
		case u.got <- append([]byte(nil), buf[:n]...):
		default:
		}
		_, _ = conn.Write(buf[:n])
	}
	_ = conn.Close()
	return err
}

func (*muxEchoUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, wire.Target, FlowReadiness) error {
	return nil
}

func TestServeTCPAcceptsMarkedMuxLane(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{
		Credentials: credentials,
		Networks:    []Network{NetworkTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream := &muxEchoUpstream{got: make(chan []byte, 1)}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	var exporter wire.TLSExporter
	exporter[0] = 9
	sessionID := wire.SessionID{1}
	auth, err := wire.EncodeAuthFrame(credentials, wire.AuthTransportTLSTCP, exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 7, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
	}
	setup, err := wire.EncodeFlowHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), wire.HandshakedConn{
			Conn: serverConn,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: tls.VersionTLS13, NegotiatedALPN: wire.DefaultALPN, Exporter: exporter,
			},
		}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil)
	}()

	if _, err := clientConn.Write(auth[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write([]byte{wire.MuxMarker}); err != nil {
		t.Fatal(err)
	}
	client, incoming, err := carriermux.Start(clientConn, carriermux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	incoming.Discard()
	defer client.Close()
	stream, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(append(setup, targetBytes...)); err != nil {
		t.Fatal(err)
	}
	result, err := wire.ReadSetupResult(stream)
	if err != nil {
		t.Fatal(err)
	}
	if result != wire.SetupResultReady {
		t.Fatalf("setup result=%v", result)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-upstream.got:
		if string(got) != "hello" {
			t.Fatalf("upstream got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mux flow was not routed")
	}
	echo := make([]byte, 5)
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "hello" {
		t.Fatalf("echo %q", echo)
	}
	_ = stream.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func TestServeTCPStillAcceptsDedicatedLane(t *testing.T) {
	handler, credentials, _ := newLegacyTestHandler(t, nil)
	var exporter wire.TLSExporter
	exporter[0] = 8
	auth := legacyAuthFrame(t, credentials, wire.AuthTransportTLSTCP, exporter)
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 3, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
	}
	setup, err := wire.EncodeFlowHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	input := append(append(auth[:], setup...), targetBytes...)
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), wire.HandshakedConn{
			Conn: serverConn,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: tls.VersionTLS13, NegotiatedALPN: wire.DefaultALPN, Exporter: exporter,
			},
		}, &net.TCPAddr{}, nil)
	}()
	if _, err := clientConn.Write(input); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dedicated lane timed out")
	}
}
