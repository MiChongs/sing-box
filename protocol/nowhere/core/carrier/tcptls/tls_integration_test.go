package tcptls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type standardTLSDialer struct {
	config *tls.Config
}

func (d standardTLSDialer) DialTLSConn(ctx context.Context, raw net.Conn) (wire.HandshakedConn, error) {
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

func TestPrepareAuthenticatesOverRealLocalhostTLS13(t *testing.T) {
	certificate := selfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	credentials, err := wire.NewCredentials("integration-secret")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := wire.SessionID{1, 2, 3}
	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		conn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{wire.DefaultALPN},
		})
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			serverResult <- err
			return
		}
		state := conn.ConnectionState()
		material, err := state.ExportKeyingMaterial(
			wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen,
		)
		if err != nil {
			serverResult <- err
			return
		}
		var exporter wire.TLSExporter
		copy(exporter[:], material)
		got, err := wire.ReadAuthFrame(conn, credentials, wire.AuthTransportTLSTCP, exporter)
		if err == nil && got != sessionID {
			t.Errorf("session ID = %x want %x", got, sessionID)
		}
		serverResult <- err
	}()

	config, err := NewConfig(TCPOptions{
		Address: listener.Addr().String(),
		Dialer:  &net.Dialer{Timeout: time.Second},
		TLSDialer: standardTLSDialer{config: &tls.Config{
			InsecureSkipVerify: true, // test certificate
			MinVersion:         tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{wire.DefaultALPN},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err = config.BindSession(credentials, sessionID, wire.DefaultALPN)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, _, err := prepare(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS server did not receive authentication")
	}
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
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
	certificate, err := tls.X509KeyPair(
		pemCertificate(der),
		pemECPrivateKey(t, key),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
