//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/stretchr/testify/require"
)

const realityTestServerName = "reality.example.com"

func startRealityTestTarget(t *testing.T) uint16 {
	t.Helper()
	// REALITY pads its own certificate record to the target's, so the target chain must be
	// larger than the ML-DSA-65 certificate (about 3.4 KB), like real-world sites.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	padding := make([]byte, 4096)
	_, err = rand.Read(padding)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: realityTestServerName},
		DNSNames:        []string{realityTestServerName},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 55555, 1}, Value: padding}},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate := stdTLS.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}
	listener, err := stdTLS.Listen("tcp", "127.0.0.1:0", &stdTLS.Config{
		Certificates: []stdTLS.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

type realityHandshakeTestCase struct {
	serverKeyShare string
	clientKeyShare string
	serverMldsa65  bool
	clientMldsa65  bool
	wrongMldsa65   bool
	expectFailure  bool
}

func runRealityHandshakeTest(t *testing.T, testCase realityHandshakeTestCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	targetPort := startRealityTestTarget(t)
	publicKey, privateKey := generateTestX25519Keys(t)

	var seed [mldsa65.SeedSize]byte
	_, err := rand.Read(seed[:])
	require.NoError(t, err)
	verifyKey, _ := mldsa65.NewKeyFromSeed(&seed)
	if testCase.wrongMldsa65 {
		var otherSeed [mldsa65.SeedSize]byte
		otherSeed[0] = seed[0] + 1
		verifyKey, _ = mldsa65.NewKeyFromSeed(&otherSeed)
	}
	verifyKeyBytes, err := verifyKey.MarshalBinary()
	require.NoError(t, err)

	serverRealityOptions := &option.InboundRealityOptions{
		Enabled: true,
		Handshake: option.InboundRealityHandshakeOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: targetPort},
		},
		PrivateKey: privateKey,
		ShortID:    badoption.Listable[string]{"0123456789abcdef"},
		KeyShare:   testCase.serverKeyShare,
	}
	if testCase.serverMldsa65 {
		serverRealityOptions.MLDSA65Seed = base64.RawURLEncoding.EncodeToString(seed[:])
	}
	serverConfig, err := NewRealityServer(ctx, log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: realityTestServerName,
		Reality:    serverRealityOptions,
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	defer serverConfig.Close()

	clientRealityOptions := &option.OutboundRealityOptions{
		Enabled:   true,
		PublicKey: publicKey,
		ShortID:   "0123456789abcdef",
		KeyShare:  testCase.clientKeyShare,
	}
	if testCase.clientMldsa65 {
		clientRealityOptions.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(verifyKeyBytes)
	}
	clientConfig, err := NewRealityClient(ctx, log.NewNOPFactory().Logger(), realityTestServerName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: realityTestServerName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    clientRealityOptions,
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		tlsConn, err := ServerHandshake(ctx, conn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		buffer := make([]byte, 5)
		_, err = io.ReadFull(tlsConn, buffer)
		if err == nil {
			_, err = tlsConn.Write(buffer)
		}
		serverDone <- err
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, err := ClientHandshake(ctx, conn, clientConfig)
	if testCase.expectFailure {
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
	_, err = tlsConn.Write([]byte("hello"))
	require.NoError(t, err)
	response := make([]byte, 5)
	_, err = io.ReadFull(tlsConn, response)
	require.NoError(t, err)
	require.Equal(t, "hello", string(response))
	require.NoError(t, <-serverDone)
}

func TestRealityHandshakeHybrid(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{})
}

func TestRealityHandshakeClassicalClient(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{clientKeyShare: C.RealityKeyShareClassical})
}

func TestRealityHandshakeClassicalServer(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{serverKeyShare: C.RealityKeyShareClassical})
}

func TestRealityHandshakeMldsa65(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{serverMldsa65: true, clientMldsa65: true})
}

func TestRealityHandshakeMldsa65Classical(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{serverKeyShare: C.RealityKeyShareClassical, serverMldsa65: true, clientMldsa65: true})
}

func TestRealityHandshakeMldsa65ServerOnly(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{serverMldsa65: true})
}

func TestRealityHandshakeMldsa65Mismatch(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{serverMldsa65: true, clientMldsa65: true, wrongMldsa65: true, expectFailure: true})
}

func TestRealityHandshakeMldsa65MissingOnServer(t *testing.T) {
	runRealityHandshakeTest(t, realityHandshakeTestCase{clientMldsa65: true, expectFailure: true})
}

func startRealityEchoTLSServer(t *testing.T, network string, address string, serverName string) net.Listener {
	t.Helper()
	privateKeyPEM, certificatePEM, err := GenerateCertificate(nil, nil, time.Now, serverName, time.Now().Add(time.Hour))
	require.NoError(t, err)
	certificate, err := stdTLS.X509KeyPair(certificatePEM, privateKeyPEM)
	require.NoError(t, err)
	listener, err := stdTLS.Listen(network, address, &stdTLS.Config{Certificates: []stdTLS.Certificate{certificate}})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func newRealityFallbackTestServer(t *testing.T, ctx context.Context, fallback *option.InboundRealityFallbackOptions) (ServerConfig, string, string, net.Listener) {
	t.Helper()
	targetPort := startRealityTestTarget(t)
	publicKey, privateKey := generateTestX25519Keys(t)
	serverConfig, err := NewRealityServer(ctx, log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: realityTestServerName,
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: targetPort},
			},
			PrivateKey: privateKey,
			ShortID:    badoption.Listable[string]{"0123456789abcdef"},
			Fallback:   fallback,
		},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	t.Cleanup(func() { serverConfig.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn, err := ServerHandshake(ctx, conn, serverConfig)
				if err != nil {
					return
				}
				io.Copy(tlsConn, tlsConn)
			}()
		}
	}()
	return serverConfig, publicKey, listener.Addr().String(), listener
}

func probeRealityFallback(t *testing.T, address string) (string, error) {
	t.Helper()
	conn, err := stdTLS.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &stdTLS.Config{
		ServerName:         realityTestServerName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	commonName := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	if len(conn.ConnectionState().PeerCertificates[0].DNSNames) > 0 {
		commonName = conn.ConnectionState().PeerCertificates[0].DNSNames[0]
	}
	return commonName, nil
}

func TestRealityFallbackToDest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, publicKey, address, _ := newRealityFallbackTestServer(t, ctx, &option.InboundRealityFallbackOptions{QOS: "1mb/s"})
	serverName, err := probeRealityFallback(t, address)
	require.NoError(t, err)
	require.Equal(t, realityTestServerName, serverName)

	clientConfig, err := NewRealityClient(ctx, log.NewNOPFactory().Logger(), realityTestServerName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: realityTestServerName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: publicKey, ShortID: "0123456789abcdef"},
	})
	require.NoError(t, err)
	conn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, err := ClientHandshake(ctx, conn, clientConfig)
	require.NoError(t, err)
	_, err = tlsConn.Write([]byte("hello"))
	require.NoError(t, err)
	response := make([]byte, 5)
	_, err = io.ReadFull(tlsConn, response)
	require.NoError(t, err)
	require.Equal(t, "hello", string(response))
}

func TestRealityFallbackToUnixSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	socketPath := t.TempDir() + "/fallback.sock"
	startRealityEchoTLSServer(t, "unix", socketPath, "fallback.example.com")
	_, _, address, _ := newRealityFallbackTestServer(t, ctx, &option.InboundRealityFallbackOptions{Server: socketPath})
	serverName, err := probeRealityFallback(t, address)
	require.NoError(t, err)
	require.Equal(t, "fallback.example.com", serverName)

	conn, err := stdTLS.Dial("tcp", address, &stdTLS.Config{ServerName: realityTestServerName, InsecureSkipVerify: true})
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	response := make([]byte, 4)
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, "ping", string(response))
}

func TestRealityFallbackRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, address, _ := newRealityFallbackTestServer(t, ctx, &option.InboundRealityFallbackOptions{MaxConnections: "1/m"})
	_, err := probeRealityFallback(t, address)
	require.NoError(t, err)
	_, err = probeRealityFallback(t, address)
	require.Error(t, err)
}

func TestParseRealityFallbackRate(t *testing.T) {
	for input, expected := range map[string]float64{"10": 10, "10/s": 10, "600/m": 10, "3600/h": 1, "0": 0} {
		rate, err := parseRealityFallbackRate(input)
		require.NoError(t, err, input)
		require.InDelta(t, expected, rate, 1e-9, input)
	}
	_, err := parseRealityFallbackRate("10/d")
	require.Error(t, err)
}
