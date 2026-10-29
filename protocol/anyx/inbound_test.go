package anyx

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	anyx "github.com/sagernet/sing-box/common/anyx"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type testFallbackServer struct {
	listener net.Listener
	port     uint16
}

func startTestFallbackServer(t *testing.T) *testFallbackServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	srv := &testFallbackServer{listener: l, port: port}

	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, rErr := c.Read(buf)
				if rErr != nil || n == 0 {
					return
				}
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nfallback-echo:%s", n+14, string(buf[:n]))
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return srv
}

// testFallbackProxyRouter 具备向 metadata.Destination 真实转发能力，满足 Fallback 端到端验证
type testFallbackProxyRouter struct {
	adapter.Router
}

func (r *testFallbackProxyRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	targetConn, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		return
	}
	defer targetConn.Close()

	go func() {
		_, _ = io.Copy(targetConn, conn)
	}()
	_, _ = io.Copy(conn, targetConn)
}

func TestInboundOptionsJSON(t *testing.T) {
	for _, data := range []string{
		`{}`,
		`{"padding_scheme":["auto"],"padding_scheme_interval":"10m"}`,
		`{"padding_scheme_interval":"30s"}`,
	} {
		var options option.AnyXInboundOptions
		require.NoError(t, json.Unmarshal([]byte(data), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		var roundTrip option.AnyXInboundOptions
		require.NoError(t, json.Unmarshal(encoded, &roundTrip))
		require.Equal(t, options.PaddingSchemeInterval, roundTrip.PaddingSchemeInterval)
	}
}

func TestInboundShortProbeFastFallback(t *testing.T) {
	fallbackSrv := startTestFallbackServer(t)
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
		Users:    []option.AnyXUser{{Name: "admin", Password: "super-secure-password"}},
		Fallback: &option.ServerOptions{Server: "127.0.0.1", ServerPort: fallbackSrv.port},
	}

	inb, err := NewInbound(t.Context(), &testFallbackProxyRouter{}, logger.NOP(), "inbound-probe-test", inbOpt)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, scope))

	probes := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "HTTP/0.9 (9 Bytes)",
			payload: []byte("GET /\r\n\r\n"),
		},
		{
			name:    "HTTP/1.0 (18 Bytes)",
			payload: []byte("GET / HTTP/1.0\r\n\r\n"),
		},
		{
			name:    "HTTP/2 Client Preface (24 Bytes)",
			payload: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			tlsConn, dErr := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
			require.NoError(t, dErr)
			defer tlsConn.Close()

			start := time.Now()
			_, wErr := tlsConn.Write(p.payload)
			require.NoError(t, wErr)

			respBuf := make([]byte, 512)
			_ = tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, rErr := tlsConn.Read(respBuf)
			elapsed := time.Since(start)

			require.NoError(t, rErr)
			require.True(t, n > 0)
			require.Contains(t, string(respBuf[:n]), "fallback-echo:")
			require.Contains(t, string(respBuf[:n]), string(p.payload))
			// 验证耗时：前缀快速匹配必须在 150ms 内极速返回
			require.Less(t, elapsed, 150*time.Millisecond, "Fast-fail prefix check must return fallback immediately without blocking")
		})
	}
}

func TestInboundFullPasswordMismatchFallback(t *testing.T) {
	fallbackSrv := startTestFallbackServer(t)
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
		Users:    []option.AnyXUser{{Name: "user", Password: "correct-password"}},
		Fallback: &option.ServerOptions{Server: "127.0.0.1", ServerPort: fallbackSrv.port},
	}

	inb, err := NewInbound(t.Context(), &testFallbackProxyRouter{}, logger.NOP(), "inbound-mismatch-test", inbOpt)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, scope))

	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer tlsConn.Close()

	// 发送不匹配的 32 字节 Hash 及附带数据
	wrongAuth := sha256.Sum256([]byte("wrong-password"))
	request := append(wrongAuth[:], []byte("trailing-request-data")...)
	_, err = tlsConn.Write(request)
	require.NoError(t, err)

	respBuf := make([]byte, 512)
	_ = tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := tlsConn.Read(respBuf)
	require.NoError(t, err)
	require.Contains(t, string(respBuf[:n]), "fallback-echo:")
}

func TestInboundMultiUserAuthentication(t *testing.T) {
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
		Users: []option.AnyXUser{
			{Name: "alice", Password: "alice-password"},
			{Name: "bob", Password: "bob-password"},
		},
	}

	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-multiuser", inbOpt)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, scope))

	executeEchoTest(t, inbOpt, option.AnyXOutboundOptions{
		Password: "alice-password",
	}, "MultiUser-Alice")

	executeEchoTest(t, inbOpt, option.AnyXOutboundOptions{
		Password: "bob-password",
	}, "MultiUser-Bob")
}

func TestInboundProloguePaddingLimit(t *testing.T) {
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
		Users:        []option.AnyXUser{{Name: "user", Password: "test-password"}},
		PaddingLimit: 100,
	}

	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-limit-test", inbOpt)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, scope))

	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer tlsConn.Close()

	auth := sha256.Sum256([]byte("test-password"))
	header := make([]byte, 34)
	copy(header[:32], auth[:])
	binary.BigEndian.PutUint16(header[32:34], 500)

	_, err = tlsConn.Write(header)
	require.NoError(t, err)

	buf := make([]byte, 16)
	_ = tlsConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = tlsConn.Read(buf)
	require.Error(t, err)
}

func TestInboundAutoPaddingRotation(t *testing.T) {
	testCases := []struct {
		name     string
		interval badoption.Duration
	}{
		{name: "default_interval", interval: 0},
		{name: "disabled_interval", interval: badoption.Duration(30 * time.Second)},
		{name: "custom_interval", interval: badoption.Duration(15 * time.Minute)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			port := getFreePort(t)
			inbOpt := option.AnyXInboundOptions{
				ListenOptions:         option.ListenOptions{ListenPort: port},
				Users:                 []option.AnyXUser{{Name: "user", Password: "test-password"}},
				PaddingScheme:         []string{"auto"},
				PaddingSchemeInterval: tc.interval,
			}

			inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-auto-"+tc.name, inbOpt)
			require.NoError(t, err)

			scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
			t.Cleanup(func() { _ = scope.Close() })
			require.NoError(t, inb.Start(adapter.StartStateStart, scope))

			service := inb.(*Inbound).service
			require.NotNil(t, service)
		})
	}
}

func TestServicePaddingSchemeInterval(t *testing.T) {
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
			service, err := anyx.NewMultiService[string](anyx.ServiceOptions{
				PaddingScheme:         []byte("auto"),
				PaddingSchemeInterval: tc.interval,
				Logger:                logger.NOP(),
			})
			require.NoError(t, err)
			require.NotNil(t, service)
			t.Cleanup(func() { _ = service.Close() })
		})
	}
}