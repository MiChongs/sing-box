package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type loopbackTLSDialer struct{ config *tls.Config }

func (d loopbackTLSDialer) DialTLSConn(ctx context.Context, raw net.Conn) (wire.HandshakedConn, error) {
	conn := tls.Client(raw, d.config.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		return wire.HandshakedConn{}, err
	}
	state := conn.ConnectionState()
	material, err := state.ExportKeyingMaterial(
		wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen,
	)
	if err != nil {
		_ = conn.Close()
		return wire.HandshakedConn{}, err
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: wire.TLSHandshakeInfo{
			TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
		},
	}, nil
}

func TestMuxEnabledBundleOpensTCPThroughPortal(t *testing.T) {
	testMuxEnabledBundleOpensTCPThroughPortal(t, false)
}

func TestMuxEnabledMixedBundleOpensTCPThroughPortal(t *testing.T) {
	testMuxEnabledBundleOpensTCPThroughPortal(t, true)
}

func testMuxEnabledBundleOpensTCPThroughPortal(t *testing.T, mixed bool) {
	t.Helper()
	certificate := muxSelfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	credentials, err := wire.NewCredentials("mux-loopback")
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

	handshake := func(ctx context.Context, raw net.Conn) (wire.HandshakedConn, error) {
		conn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{wire.DefaultALPN},
		})
		if err := conn.HandshakeContext(ctx); err != nil {
			return wire.HandshakedConn{}, err
		}
		state := conn.ConnectionState()
		material, err := state.ExportKeyingMaterial(
			wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen,
		)
		if err != nil {
			_ = conn.Close()
			return wire.HandshakedConn{}, err
		}
		var exporter wire.TLSExporter
		copy(exporter[:], material)
		return wire.HandshakedConn{
			Conn: conn,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
			},
		}, nil
	}

	serveDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serveDone <- err
			return
		}
		serveDone <- handler.ServeTCP(context.Background(), raw, raw.RemoteAddr(), handshake, nil)
	}()

	tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: listener.Addr().String(),
		Dialer:  &net.Dialer{Timeout: 2 * time.Second},
		TLSDialer: loopbackTLSDialer{config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{wire.DefaultALPN},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	options := bundle.BundleOptions{
		TCP: tcp, Credentials: credentials,
		Up: wire.CarrierTLSTCP, Down: wire.CarrierTLSTCP, Mux: bundle.MuxEnabled,
	}
	if mixed {
		options.Up, options.Down = 0, 0
		options.MixUp, options.MixDown = true, true
		options.QUIC = muxUnavailableQUICBackend{}
	}
	client, err := bundle.NewCarrierBundle(options)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.OpenTCP(ctx, target)
	if err != nil {
		t.Fatalf("OpenTCP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-upstream.got:
		if string(got) != "ping" {
			t.Fatalf("upstream %q", got)
		}
	case <-ctx.Done():
		t.Fatal("mux bundle flow was not routed")
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo %q", echo)
	}
	_ = conn.Close()
	_ = client.Close()
	select {
	case err := <-serveDone:
		if err != nil && err != net.ErrClosed {
			t.Logf("ServeTCP: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeTCP still running after client close")
	}
}

type muxUnavailableQUICBackend struct{}

func (muxUnavailableQUICBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test QUIC unavailable")
}
func (muxUnavailableQUICBackend) InvalidateSession(carrier.QuicSession) {}
func (muxUnavailableQUICBackend) Close() error                          { return nil }

func muxSelfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
