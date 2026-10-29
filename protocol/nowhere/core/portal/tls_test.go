package portal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/vector"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestTLSEcho(t *testing.T) {
	for _, morph := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "morph"}[morph], func(t *testing.T) {
			echo := echoServer(t)
			cert := testCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			key := "0123456789abcdef0123456789abcdef"
			srv, err := New(Config{
				SharedKey: key,
				Morph:     morph,
				TLS: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
				Upstream: Direct{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(srv.tls.NextProtos) != 1 || srv.tls.NextProtos[0] != wire.ALPN {
				t.Fatalf("server alpn %v", srv.tls.NextProtos)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx, ln) }()

			client, err := vector.New(vector.Config{
				SharedKey:  key,
				Morph:      morph,
				PortalAddr: ln.Addr().String(),
				TLS: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "nowhere",
				},
				DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", addr)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			host, port, _ := net.SplitHostPort(echo)
			target, err := wire.NewIPTarget(netip.MustParseAddr(host), mustPort(t, port))
			if err != nil {
				t.Fatal(err)
			}
			flowCtx, cancelFlow := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelFlow()
			conn, err := client.OpenTCP(flowCtx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != "ping" {
				t.Fatalf("got %q", buf)
			}

			udpEcho, udpAddr := udpEchoServer(t)
			_ = udpEcho
			uTarget, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), mustPort(t, udpAddr))
			if err != nil {
				t.Fatal(err)
			}
			uc, err := client.OpenUDP(flowCtx, uTarget)
			if err != nil {
				t.Fatal(err)
			}
			defer uc.Close()
			if _, err := uc.Write([]byte("pong")); err != nil {
				t.Fatal(err)
			}
			ubuf := make([]byte, 4)
			_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := uc.Read(ubuf)
			if err != nil {
				t.Fatal(err)
			}
			if string(ubuf[:n]) != "pong" {
				t.Fatalf("udp %q", ubuf[:n])
			}
		})
	}
}

func TestRejectsNW2ALPN(t *testing.T) {
	cert := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := New(Config{
		SharedKey: "0123456789abcdef0123456789abcdef",
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"nw2"},
		ServerName:         "nowhere",
	})
	err = client.HandshakeContext(ctx)
	if err == nil && client.ConnectionState().NegotiatedProtocol == "nw3" {
		t.Fatal("nw2 client completed an nw3 handshake")
	}
	if err == nil && client.ConnectionState().NegotiatedProtocol == "nw2" {
		t.Fatal("server accepted nw2")
	}
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func udpEchoServer(t *testing.T) (net.PacketConn, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(nil), buf[:n]...), addr)
		}
	}()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	return pc, port
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nowhere"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nowhere"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustPort(t *testing.T, s string) uint16 {
	t.Helper()
	var n int
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return uint16(n)
}
