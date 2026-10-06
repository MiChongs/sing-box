//go:build with_quic

package tls

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const chromeParrotTestALPN = "h3"

// chromeParrotTestServer is a QUIC listener that reports the common name of
// each client certificate it receives, or "" for a client that sent none.
type chromeParrotTestServer struct {
	address      string
	clientNames  chan string
	rootPEM      string
	leafPin      string
	unrelatedPin string
}

func startChromeParrotTestServer(t *testing.T) *chromeParrotTestServer {
	t.Helper()
	serverCertificate, chain := newCertificatePinChain(t)
	_, unrelated := newCertificatePinChain(t)
	unrelatedHash := sha256.Sum256(unrelated[0].Raw)
	listener, err := quic.ListenAddr("127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{serverCertificate},
		NextProtos:   []string{chromeParrotTestALPN},
		ClientAuth:   stdtls.RequestClientCert,
	}, nil)
	require.NoError(t, err)
	server := &chromeParrotTestServer{
		address:      listener.Addr().String(),
		clientNames:  make(chan string, 16),
		rootPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[2].Raw})),
		leafPin:      certificatePin(chain[0]),
		unrelatedPin: hex.EncodeToString(unrelatedHash[:]),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go func() {
		for {
			conn, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			clientName := ""
			if peerCertificates := conn.ConnectionState().TLS.PeerCertificates; len(peerCertificates) > 0 {
				clientName = peerCertificates[0].Subject.CommonName
			}
			server.clientNames <- clientName
			go func() {
				<-ctx.Done()
				_ = conn.CloseWithError(0, "")
			}()
		}
	}()
	return server
}

// dial performs a Chrome-parroting QUIC handshake, hysteria2's default, with
// config and returns the client certificate name the server saw.
func (s *chromeParrotTestServer) dial(t *testing.T, config Config) (string, error) {
	t.Helper()
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)
	stdConfig = stdConfig.Clone()
	stdConfig.NextProtos = []string{chromeParrotTestALPN}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, s.address, stdConfig, &quic.Config{ChromeParrot: true})
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")
	select {
	case clientName := <-s.clientNames:
		return clientName, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func chromeParrotTestCases(server *chromeParrotTestServer) []struct {
	name    string
	options option.OutboundTLSOptions
	client  string
	fails   bool
} {
	clientKey, clientCertificate, _ := GenerateCertificate(nil, nil, time.Now, "client.example", time.Now().Add(time.Hour))
	return []struct {
		name    string
		options option.OutboundTLSOptions
		client  string
		fails   bool
	}{
		{
			name:    "certificate_pin_sha256",
			options: option.OutboundTLSOptions{ServerName: "localhost", CertificatePinSHA256: server.leafPin},
		},
		{
			name:    "certificate_pin_sha256 mismatch",
			options: option.OutboundTLSOptions{ServerName: "localhost", CertificatePinSHA256: server.unrelatedPin},
			fails:   true,
		},
		{
			name: "certificate_server_name",
			options: option.OutboundTLSOptions{
				ServerName:            "sni.example",
				CertificateServerName: "localhost",
				Certificate:           badoption.Listable[string]{server.rootPEM},
			},
		},
		{
			name: "certificate_server_name mismatch",
			options: option.OutboundTLSOptions{
				ServerName:            "sni.example",
				CertificateServerName: "other.example",
				Certificate:           badoption.Listable[string]{server.rootPEM},
			},
			fails: true,
		},
		{
			name: "client certificate",
			options: option.OutboundTLSOptions{
				ServerName:        "localhost",
				Certificate:       badoption.Listable[string]{server.rootPEM},
				ClientCertificate: badoption.Listable[string]{string(clientCertificate)},
				ClientKey:         badoption.Listable[string]{string(clientKey)},
			},
			client: "client.example",
		},
	}
}

// TestSTDClientQUICChromeParrotHandshake covers the client configs whose checks
// replace crypto/tls's built-in verification. quic-go's Chrome-parroting
// handshake translates the config to uTLS and refuses VerifyConnection and
// Certificates, so before these checks moved to VerifyPeerCertificate and
// GetClientCertificate every such hysteria2 outbound failed to connect.
func TestSTDClientQUICChromeParrotHandshake(t *testing.T) {
	server := startChromeParrotTestServer(t)
	for _, testCase := range chromeParrotTestCases(server) {
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			options.Enabled = true
			config, err := NewSTDClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			clientName, err := server.dial(t, config)
			if testCase.fails {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "not supported with ChromeParrot")
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.client, clientName)
		})
	}
}
