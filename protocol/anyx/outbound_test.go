package anyx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	anyx "github.com/sagernet/sing-box/common/anyx"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestClientMetadataOrDefault(t *testing.T) {
	require.Equal(t, anyx.DefaultClientMetadata+" sing-box/"+C.Version, clientMetadataOrDefault(nil))
	require.Empty(t, clientMetadataOrDefault(common.Ptr("")))
	require.Equal(t, "custom", clientMetadataOrDefault(common.Ptr("custom")))
	for _, data := range []string{`{}`, `{"client_metadata":""}`, `{"client_metadata":"custom"}`} {
		var options option.AnyXOutboundOptions
		require.NoError(t, json.Unmarshal([]byte(data), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		var roundTrip option.AnyXOutboundOptions
		require.NoError(t, json.Unmarshal(encoded, &roundTrip))
		require.Equal(t, options.ClientMetadata, roundTrip.ClientMetadata)
	}
}

func TestOutboundOptions(t *testing.T) {
	for _, disableReuse := range []bool{false, true} {
		created, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
			DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
			ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			Password:                    "password",
			DisableReuse:                disableReuse,
			ClientMetadata:              common.Ptr(""),
			PaddingSchemeInterval:       badoption.Duration(10 * time.Minute),
			IdleSessionMinTimeout:       badoption.Duration(15 * time.Second),
			IdleSessionTimeout:          badoption.Duration(30 * time.Second),
			MinIdleSession:              2,
		})
		require.NoError(t, err)
		outbound := created.(*Outbound)
		require.Equal(t, disableReuse, outbound.clientOptions.DisableReuse)
		require.Equal(t, !disableReuse, outbound.MultiplexEnabled())
		require.Empty(t, outbound.clientOptions.ClientMetadata)
		require.Equal(t, []byte("auto"), outbound.clientOptions.PaddingScheme)
		require.Equal(t, 10*time.Minute, outbound.clientOptions.PaddingSchemeInterval)
		require.Equal(t, 15*time.Second, outbound.clientOptions.IdleSessionMinTimeout)
		require.Equal(t, 30*time.Second, outbound.clientOptions.IdleSessionTimeout)
		require.Equal(t, 2, outbound.clientOptions.MinIdleSession)
		scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
		t.Cleanup(func() { _ = scope.Close() })
		require.NoError(t, outbound.Start(adapter.StartStateInitialize, scope))
		require.NoError(t, scope.Close())
	}
}

func TestOutboundOptionsJSON(t *testing.T) {
	for _, data := range []string{
		`{}`,
		`{"padding_scheme":["auto"],"padding_scheme_interval":"15m"}`,
		`{"padding_scheme_interval":"45s"}`,
	} {
		var options option.AnyXOutboundOptions
		require.NoError(t, json.Unmarshal([]byte(data), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		var roundTrip option.AnyXOutboundOptions
		require.NoError(t, json.Unmarshal(encoded, &roundTrip))
		require.Equal(t, options.PaddingSchemeInterval, roundTrip.PaddingSchemeInterval)
	}
}

func TestOverrideAnyTLSOptionsJSON(t *testing.T) {
	for _, data := range []string{
		`{}`,
		`{"padding_scheme_interval":"20m"}`,
		`{"padding_scheme_interval":"30s","min_idle_session":1}`,
	} {
		var options option.OverrideAnyTLSOptions
		require.NoError(t, json.Unmarshal([]byte(data), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		var roundTrip option.OverrideAnyTLSOptions
		require.NoError(t, json.Unmarshal(encoded, &roundTrip))
		require.Equal(t, options.PaddingSchemeInterval, roundTrip.PaddingSchemeInterval)
	}
}

func TestClientPaddingSchemeInterval(t *testing.T) {
	testCases := []struct {
		name     string
		interval time.Duration
	}{
		{name: "default_interval", interval: 0},
		{name: "disabled_interval", interval: 30 * time.Second},
		{name: "custom_interval", interval: 10 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := anyx.NewClient(anyx.ClientOptions{
				Password:              "test-password",
				PaddingScheme:         []byte("auto"),
				PaddingSchemeInterval: tc.interval,
			})
			require.NoError(t, err)
			require.NotNil(t, client)
			t.Cleanup(func() { _ = client.Close() })
		})
	}
}

func TestPaddingSchemeModes(t *testing.T) {
	testCases := []struct {
		name   string
		scheme []string
	}{
		{
			name:   "off",
			scheme: []string{"off"},
		},
		{
			name:   "auto",
			scheme: nil,
		},
		{
			name: "manual",
			scheme: []string{
				"stop=4",
				"0=30-30",
				"1=100-200",
				"2=300-400,c,500-600",
				"3=1000-1200",
			},
		},
	}

	for _, tc := range testCases {
		created, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			Password:                    "password",
			PaddingScheme:               tc.scheme,
		})
		require.NoError(t, err)
		outbound := created.(*Outbound)

		scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
		require.NoError(t, outbound.Start(adapter.StartStateInitialize, scope))
		t.Cleanup(func() { _ = scope.Close() })

		schemeStr := string(outbound.clientOptions.PaddingScheme)
		if schemeStr == "auto" {
			generated := string(anyx.GenerateRandomPaddingScheme())
			fmt.Printf("\n=== [Padding Scheme: auto (Configured: auto, Generated Output)] ===\n%s\n===================================================================\n", generated)
			t.Logf("Mode auto generated:\n%s", generated)
			require.Contains(t, generated, "stop=")
		} else {
			fmt.Printf("\n=== [Padding Scheme: %s] ===\n%s\n===============================\n", tc.name, schemeStr)
			t.Logf("Mode %s scheme:\n%s", tc.name, schemeStr)
			if tc.name == "off" {
				require.Equal(t, "off", schemeStr)
			} else {
				require.Contains(t, schemeStr, "stop=4")
			}
		}
	}
}

func TestEncryptionOptions(t *testing.T) {
	created, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
		Password:                    "password",
		Encryption: &option.AnyXEncryptionOptions{
			Method:   "aes-128-gcm",
			Password: "secret-key-123456",
		},
	})
	require.NoError(t, err)
	outbound := created.(*Outbound)
	require.NotNil(t, outbound.ssMethod)

	created2022, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
		Password:                    "password",
		Encryption: &option.AnyXEncryptionOptions{
			Method:   "2022-blake3-aes-128-gcm",
			Password: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		},
	})
	require.NoError(t, err)
	outbound2022 := created2022.(*Outbound)
	require.NotNil(t, outbound2022.ssMethod)

	_, err = NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
		Password:                    "password",
		Encryption: &option.AnyXEncryptionOptions{
			Method:   "invalid-cipher-name",
			Password: "secret-key-123456",
		},
	})
	require.Error(t, err)
}

func TestDirectWithoutTLS(t *testing.T) {
	created, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "password",
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	outbound := created.(*Outbound)
	require.Nil(t, outbound.tlsConfig)
	require.Nil(t, outbound.tlsDialer)
	require.NotNil(t, outbound.dialer)
}

func TestIdleMethodsBeforeStart(t *testing.T) {
	outbound := new(Outbound)
	require.NotPanics(t, func() {
		outbound.InterfaceUpdated(context.Background())
		outbound.SetKeepIdleConnections(false)
		outbound.CloseIdleConnections()
	})
}

func TestALPNFallbackRequiresTLS(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, logger.NOP(), "test", option.AnyXInboundOptions{
		FallbackForALPN: map[string]*option.ServerOptions{"h2": {Server: "127.0.0.1", ServerPort: 80}},
	})
	require.ErrorContains(t, err, "fallback for ALPN is not supported without TLS")
}

func TestOutboundSessionLifecycleAndReplenish(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	inbOpt := option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "test-password"}},
	}
	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-lifecycle", inbOpt)
	require.NoError(t, err)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	outbOpt := option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "127.0.0.1",
				Insecure:   true,
			},
		},
		Password:              "test-password",
		IdleSessionMinTimeout: badoption.Duration(30 * time.Millisecond),
		IdleSessionTimeout:    badoption.Duration(60 * time.Millisecond),
		MinIdleSession:        1,
	}

	outb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-lifecycle", outbOpt)
	require.NoError(t, err)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.(*Outbound).Start(adapter.StartStateInitialize, outbScope))

	conn, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	recv := make([]byte, 4)
	_, err = io.ReadFull(conn, recv)
	require.NoError(t, err)
	require.Equal(t, "ping", string(recv))
	conn.Close()

	time.Sleep(150 * time.Millisecond)

	conn2, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	defer conn2.Close()
	_, err = conn2.Write([]byte("pong"))
	require.NoError(t, err)
	recv2 := make([]byte, 4)
	_, err = io.ReadFull(conn2, recv2)
	require.NoError(t, err)
	require.Equal(t, "pong", string(recv2))
}

func TestClientDiscardUpdatePaddingSchemeFrame(t *testing.T) {
	port := getFreePort(t)

	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	defer l.Close()

	go func() {
		rawConn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer rawConn.Close()

		buf := make([]byte, 512)
		n, _ := rawConn.Read(buf)
		if n <= 34 {
			return
		}

		serverSettings := []byte("version=1")
		h1 := make([]byte, 7+len(serverSettings))
		h1[0] = 0x0A
		binary.BigEndian.PutUint16(h1[5:7], uint16(len(serverSettings)))
		copy(h1[7:], serverSettings)
		_, _ = rawConn.Write(h1)

		fakeScheme := []byte("stop=99\n0=999-999")
		h2 := make([]byte, 7+len(fakeScheme))
		h2[0] = 0x06
		binary.BigEndian.PutUint16(h2[5:7], uint16(len(fakeScheme)))
		copy(h2[7:], fakeScheme)
		_, _ = rawConn.Write(h2)

		time.Sleep(100 * time.Millisecond)
	}()

	fixedScheme := []string{"stop=4", "0=30-30", "1=100-200"}
	outb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-discard-test", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		Password:      "test-password",
		PaddingScheme: fixedScheme,
	})
	require.NoError(t, err)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.(*Outbound).Start(adapter.StartStateInitialize, outbScope))

	conn, dialErr := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	if dialErr == nil {
		conn.Close()
	}

	time.Sleep(50 * time.Millisecond)
	require.Contains(t, string(outb.(*Outbound).clientOptions.PaddingScheme), "stop=4")
	require.NotContains(t, string(outb.(*Outbound).clientOptions.PaddingScheme), "stop=99")
}

// ---------------------------------------------------------------------------
// 连通性测试辅助架构与实装
// ---------------------------------------------------------------------------

type testEchoRouter struct {
	adapter.Router
}

func (r *testEchoRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	defer conn.Close()
	_, err := io.Copy(conn, conn)
	return err
}

func (r *testEchoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	_, _ = io.Copy(conn, conn)
}

func (r *testEchoRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return nil
}

func (r *testEchoRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		onClose(nil)
	}
}

func generateTestCert(t *testing.T) (certPath, keyPath string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AnyX Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	tempDir := t.TempDir()
	certPath = filepath.Join(tempDir, "cert.pem")
	keyPath = filepath.Join(tempDir, "key.pem")

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	defer certOut.Close()
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))

	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	defer keyOut.Close()
	b, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	return certPath, keyPath
}

func getFreePort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port
}

func executeEchoTest(t *testing.T, inbOpt option.AnyXInboundOptions, outbOpt option.AnyXOutboundOptions, testLabel string) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	inbOpt.ListenOptions = option.ListenOptions{
		ListenPort: port,
	}
	inbOpt.InboundTLSOptionsContainer = option.InboundTLSOptionsContainer{
		TLS: &option.InboundTLSOptions{
			Enabled:         true,
			CertificatePath: certPath,
			KeyPath:         keyPath,
		},
	}
	if len(inbOpt.Users) == 0 {
		inbOpt.Users = []option.AnyXUser{{Name: "user", Password: "test-password"}}
	}

	outbOpt.ServerOptions = option.ServerOptions{
		Server:     "127.0.0.1",
		ServerPort: port,
	}
	outbOpt.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "127.0.0.1",
			Insecure:   true,
		},
	}
	if outbOpt.Password == "" {
		outbOpt.Password = "test-password"
	}

	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-"+testLabel, inbOpt)
	require.NoError(t, err)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	outb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-"+testLabel, outbOpt)
	require.NoError(t, err)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.(*Outbound).Start(adapter.StartStateInitialize, outbScope))

	conn, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	defer conn.Close()

	payload := fmt.Sprintf("hello-anyx-data-for-[%s]", testLabel)
	_, err = conn.Write([]byte(payload))
	require.NoError(t, err)

	recv := make([]byte, len(payload))
	_, err = io.ReadFull(conn, recv)
	require.NoError(t, err)
	require.Equal(t, payload, string(recv))
}

func TestEncryptionConnectivityAllMethods(t *testing.T) {
	key16 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key32 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	methods := []struct {
		method string
		pass   string
	}{
		{method: "none", pass: "test"},
		{method: "aes-128-gcm", pass: "secret128"},
		{method: "aes-192-gcm", pass: "secret192"},
		{method: "aes-256-gcm", pass: "secret256"},
		{method: "chacha20-ietf-poly1305", pass: "secretchacha"},
		{method: "xchacha20-ietf-poly1305", pass: "secretxchacha"},
		{method: "2022-blake3-aes-128-gcm", pass: key16},
		{method: "2022-blake3-aes-256-gcm", pass: key32},
		{method: "2022-blake3-chacha20-poly1305", pass: key32},
	}

	for _, m := range methods {
		t.Run(m.method, func(t *testing.T) {
			encOpt := &option.AnyXEncryptionOptions{
				Method:   m.method,
				Password: m.pass,
			}
			executeEchoTest(t,
				option.AnyXInboundOptions{Encryption: encOpt},
				option.AnyXOutboundOptions{Encryption: encOpt},
				"Encryption-"+m.method,
			)
		})
	}
}

func TestTransportConnectivity(t *testing.T) {
	transports := []struct {
		name string
		json string
	}{
		{name: "ws-root", json: `{"type":"ws","path":"/"}`},
		{name: "ws-custom-path", json: `{"type":"ws","path":"/anyx-test-ws"}`},
	}

	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			var transportOpt option.V2RayTransportOptions
			require.NoError(t, json.Unmarshal([]byte(tr.json), &transportOpt))

			executeEchoTest(t,
				option.AnyXInboundOptions{Transport: &transportOpt},
				option.AnyXOutboundOptions{Transport: &transportOpt},
				"Transport-"+tr.name,
			)
		})
	}
}

func TestTransportWithEncryptionConnectivity(t *testing.T) {
	key16 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	var transportOpt option.V2RayTransportOptions
	require.NoError(t, json.Unmarshal([]byte(`{"type":"ws","path":"/testws-enc"}`), &transportOpt))
	encOpt := &option.AnyXEncryptionOptions{
		Method:   "2022-blake3-aes-128-gcm",
		Password: key16,
	}

	executeEchoTest(t,
		option.AnyXInboundOptions{Transport: &transportOpt, Encryption: encOpt},
		option.AnyXOutboundOptions{Transport: &transportOpt, Encryption: encOpt},
		"Composite-ws",
	)
}

func TestDisableReuseConnectivity(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	inbOpt := option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{
			ListenPort: port,
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "test-password"}},
	}

	outbOpt := option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: port,
		},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "127.0.0.1",
				Insecure:   true,
			},
		},
		Password:     "test-password",
		DisableReuse: true,
	}

	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-disable-reuse", inbOpt)
	require.NoError(t, err)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	outb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-disable-reuse", outbOpt)
	require.NoError(t, err)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.(*Outbound).Start(adapter.StartStateInitialize, outbScope))

	conn1, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)

	msg1 := "disable-reuse-message-1"
	_, err = conn1.Write([]byte(msg1))
	require.NoError(t, err)
	recv1 := make([]byte, len(msg1))
	_, err = io.ReadFull(conn1, recv1)
	require.NoError(t, err)
	require.Equal(t, msg1, string(recv1))
	conn1.Close()

	conn2, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)

	msg2 := "disable-reuse-message-2"
	_, err = conn2.Write([]byte(msg2))
	require.NoError(t, err)
	recv2 := make([]byte, len(msg2))
	_, err = io.ReadFull(conn2, recv2)
	require.NoError(t, err)
	require.Equal(t, msg2, string(recv2))
	conn2.Close()
}