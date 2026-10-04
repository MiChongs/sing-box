package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// 端到端测试: 真实的 Client ↔ Server 跑在回环地址上，上层用 echo 校验数据完整性。

var (
	testCertOnce sync.Once
	testCertPEM  string
	testKeyPEM   string
)

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	testCertOnce.Do(func() {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "example.com"},
			DNSNames:     []string{"example.com", "cdn.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			panic(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
		testCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		testKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	})
	return testCertPEM, testKeyPEM
}

func newTestTLSServer(t *testing.T, alpn ...string) boxtls.ServerConfig {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
	config, err := boxtls.NewServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		ALPN:        alpn,
		Certificate: []string{certPEM},
		Key:         []string{keyPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = config.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.Close() })
	return config
}

func newTestTLSClient(t *testing.T, serverName string, alpn ...string) boxtls.Config {
	t.Helper()
	config, err := boxtls.NewClient(context.Background(), logger.NOP(), serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ALPN:       alpn,
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// startTestServer 在回环 TCP 端口上启动 XHTTP 入站 (echo)。
func startTestServer(t *testing.T, options *option.V2RayXHTTPOptions, tlsConfig boxtls.ServerConfig) M.Socksaddr {
	t.Helper()
	server, err := NewServer(context.Background(), logger.NOP(), options, tlsConfig, echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	return M.SocksaddrFromNet(listener.Addr())
}

// startSharedHTTPEntry 为已有的 Server 再开一个明文 HTTP 入口，共享同一张 session 表。
func startSharedHTTPEntry(t *testing.T, server *Server) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: server}
	go httpServer.Serve(listener)
	t.Cleanup(func() { _ = httpServer.Close() })
	return M.SocksaddrFromNet(listener.Addr())
}

func newTestClient(t *testing.T, options *option.V2RayXHTTPOptions, serverAddr M.Socksaddr, tlsConfig boxtls.Config) adapter.V2RayClientTransport {
	t.Helper()
	client, err := NewClient(context.Background(), N.SystemDialer, serverAddr, options, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// checkEcho 并发建立若干条逻辑连接，各自写入随机数据并校验 echo 回来的内容。
func checkEcho(t *testing.T, client adapter.V2RayClientTransport, connections int, size int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, connections)
	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- echoOnce(client, size)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func echoOnce(client adapter.V2RayClientTransport, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	writeErr := make(chan error, 1)
	go func() {
		// 分多次写，覆盖 packet-up 的批量合并路径
		for offset := 0; offset < len(data); {
			n := min(len(data)-offset, 1+offset%7919)
			if _, err := conn.Write(data[offset : offset+n]); err != nil {
				writeErr <- err
				// 与代理转发循环一致: 一侧出错即关闭整条连接
				_ = conn.Close()
				return
			}
			offset += n
		}
		writeErr <- nil
	}()
	received := make([]byte, size)
	_, readErr := io.ReadFull(conn, received)
	if err = <-writeErr; err != nil {
		return E.Cause(err, "write")
	}
	if readErr != nil {
		return E.Cause(readErr, "read")
	}
	if !bytes.Equal(data, received) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func smallPosts(options option.V2RayXHTTPOptions) *option.V2RayXHTTPOptions {
	// 强制拆成大量小 POST，覆盖服务端乱序重排与上行并发。
	options.ScMaxEachPostBytes = option.XHTTPRange{From: 16 * 1024, To: 32 * 1024}
	options.ScMinPostsIntervalMs = option.XHTTPRange{From: 1, To: 5}
	return &options
}

func TestE2E_PlainHTTP1(t *testing.T) {
	serverAddr := startTestServer(t, &option.V2RayXHTTPOptions{Path: "/xhttp"}, nil)
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		t.Run(mode, func(t *testing.T) {
			client := newTestClient(t, smallPosts(option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}), serverAddr, nil)
			checkEcho(t, client, 4, 256*1024)
		})
	}
}

// 回归: 服务端曾通过空 TLSNextProto 关闭了 HTTP/2，TLS 上的 h2 客户端全部失败。
func TestE2E_TLS_HTTP2(t *testing.T) {
	serverAddr := startTestServer(t, &option.V2RayXHTTPOptions{Path: "/xhttp"}, newTestTLSServer(t))
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			client := newTestClient(t, smallPosts(option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}), serverAddr, newTestTLSClient(t, "example.com"))
			checkEcho(t, client, 4, 512*1024)
		})
	}
}

func TestE2E_TLS_HTTP1(t *testing.T) {
	serverAddr := startTestServer(t, &option.V2RayXHTTPOptions{Path: "/xhttp"}, newTestTLSServer(t))
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			client := newTestClient(t, smallPosts(option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}), serverAddr, newTestTLSClient(t, "example.com", "http/1.1"))
			checkEcho(t, client, 4, 256*1024)
		})
	}
}

func TestE2E_PacketUpObfuscation(t *testing.T) {
	cases := map[string]option.V2RayXHTTPOptions{
		"header data via GET": {
			UplinkHTTPMethod:    "GET",
			UplinkDataPlacement: "header",
			SessionPlacement:    "header",
			SeqPlacement:        "query",

			// 数据放 header / cookie 时请求头会很大，需同时调大服务端 header 上限 (Xray 同样如此)。
			ServerMaxHeaderBytes: 32 * 1024,
		},
		"cookie data via PUT": {
			UplinkHTTPMethod:    "PUT",
			UplinkDataPlacement: "cookie",
			SessionPlacement:    "cookie",
			SeqPlacement:        "header",
			SeqKey:              "X-Page",

			// 数据放 header / cookie 时请求头会很大，需同时调大服务端 header 上限 (Xray 同样如此)。
			ServerMaxHeaderBytes: 32 * 1024,
		},
		"obfs padding": {
			XPaddingObfsMode:  true,
			XPaddingPlacement: "header",
			XPaddingHeader:    "X-Cache-Key",
			XPaddingMethod:    "tokenish",
			SessionPlacement:  "query",
			SessionKey:        "sid",
			SessionIDTable:    "Base62",
			SessionIDLength:   option.XHTTPRange{From: 16, To: 24},
		},
		"obfs cookie padding": {
			XPaddingObfsMode:  true,
			XPaddingPlacement: "cookie",
			XPaddingKey:       "_ga",
		},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			options.Path = "/xhttp?ed=1"
			options.Mode = "packet-up"
			serverOptions := options
			serverAddr := startTestServer(t, &serverOptions, newTestTLSServer(t))
			clientOptions := options
			clientOptions.ScMaxEachPostBytes = option.XHTTPRange{From: 3000, To: 6000}
			client := newTestClient(t, &clientOptions, serverAddr, newTestTLSClient(t, "example.com"))
			checkEcho(t, client, 2, 64*1024)
		})
	}
}

func TestE2E_ServerModeMismatch(t *testing.T) {
	serverAddr := startTestServer(t, &option.V2RayXHTTPOptions{Path: "/xhttp", Mode: "packet-up"}, newTestTLSServer(t))
	client := newTestClient(t, &option.V2RayXHTTPOptions{Path: "/xhttp", Mode: "stream-one"}, serverAddr, newTestTLSClient(t, "example.com"))
	if err := echoOnce(client, 1024); err == nil {
		t.Fatal("stream-one against a packet-up server should fail")
	}
}

func TestE2E_HostAndPathMismatch(t *testing.T) {
	serverAddr := startTestServer(t, &option.V2RayXHTTPOptions{Path: "/xhttp", Host: []string{"example.com"}}, newTestTLSServer(t))
	for name, options := range map[string]option.V2RayXHTTPOptions{
		"host": {Path: "/xhttp", Host: []string{"other.com"}},
		"path": {Path: "/other", Host: []string{"example.com"}},
	} {
		client := newTestClient(t, &options, serverAddr, newTestTLSClient(t, "example.com"))
		if err := echoOnce(client, 1024); err == nil {
			t.Errorf("%s mismatch should fail", name)
		}
	}
	// 未配置 host 时客户端用 TLS server_name 作为 Host
	client := newTestClient(t, &option.V2RayXHTTPOptions{Path: "/xhttp"}, serverAddr, newTestTLSClient(t, "example.com"))
	checkEcho(t, client, 1, 1024)
}

// countingListener 统计底层连接数。
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

func TestE2E_XmuxRotation(t *testing.T) {
	server, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{Path: "/xhttp"}, newTestTLSServer(t), echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: rawListener}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	client := newTestClient(t, &option.V2RayXHTTPOptions{
		Path: "/xhttp",
		Mode: "packet-up",
		Xmux: &option.V2RayXHTTPXmuxOptions{MaxConnections: option.XHTTPRange{From: 1, To: 1}, HMaxRequestTimes: option.XHTTPRange{From: 4, To: 4}},
	}, M.SocksaddrFromNet(rawListener.Addr()), newTestTLSClient(t, "example.com"))
	for i := 0; i < 6; i++ {
		checkEcho(t, client, 1, 4096)
	}
	if accepted := listener.accepted.Load(); accepted < 2 {
		t.Errorf("h_max_request_times should rotate underlying connections, accepted=%d", accepted)
	}
}

// recordingHandler 记录每个监听端口上收到的请求方法，再交给同一个 XHTTP Server 处理，
// 模拟 CDN / 反代把上下行转发到同一个后端入站。
type recordingHandler struct {
	server  *Server
	access  sync.Mutex
	methods map[string]int
}

func (h *recordingHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.access.Lock()
	h.methods[request.Method]++
	h.access.Unlock()
	h.server.ServeHTTP(writer, request)
}

func (h *recordingHandler) snapshot() map[string]int {
	h.access.Lock()
	defer h.access.Unlock()
	result := make(map[string]int, len(h.methods))
	for method, count := range h.methods {
		result[method] = count
	}
	return result
}

// TestE2E_DownloadSettings 验证上下行分离: 上行走 TLS + HTTP/2 的入口 A，下行走
// 明文 HTTP/1.1 的入口 B (不同端口、不同 Host)，两个入口指向同一个 XHTTP 入站。
func TestE2E_DownloadSettings(t *testing.T) {
	serverInstance, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{Path: "/xhttp"}, nil, echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	server := serverInstance.(*Server)
	t.Cleanup(func() { _ = server.Close() })

	certPEM, keyPEM := testCertificate(t)
	certificate, err := stdtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	uploadHandler := &recordingHandler{server: server, methods: map[string]int{}}
	uploadListener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{certificate}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	uploadServer := &http.Server{Handler: uploadHandler}
	go uploadServer.Serve(uploadListener)
	t.Cleanup(func() { _ = uploadServer.Close() })

	downloadHandler := &recordingHandler{server: server, methods: map[string]int{}}
	downloadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downloadServer := &http.Server{Handler: downloadHandler}
	go downloadServer.Serve(downloadListener)
	t.Cleanup(func() { _ = downloadServer.Close() })

	downloadAddr := M.SocksaddrFromNet(downloadListener.Addr())
	for _, mode := range []string{"packet-up", "stream-up", "auto"} {
		t.Run(mode, func(t *testing.T) {
			options := smallPosts(option.V2RayXHTTPOptions{
				Path: "/xhttp",
				Mode: mode,
				DownloadSettings: &option.V2RayXHTTPDownloadOptions{
					ServerOptions: option.ServerOptions{Server: downloadAddr.AddrString(), ServerPort: downloadAddr.Port},
					V2RayXHTTPOptions: option.V2RayXHTTPOptions{
						Path: "/xhttp",
						Host: []string{"download.example.com"},
					},
				},
			})
			client := newTestClient(t, options, M.SocksaddrFromNet(uploadListener.Addr()), newTestTLSClient(t, "example.com"))
			checkEcho(t, client, 3, 256*1024)
		})
	}
	uploadMethods, downloadMethods := uploadHandler.snapshot(), downloadHandler.snapshot()
	if uploadMethods[http.MethodGet] != 0 || uploadMethods[http.MethodPost] == 0 {
		t.Errorf("upload entry should only see POST, got %v", uploadMethods)
	}
	if downloadMethods[http.MethodPost] != 0 || downloadMethods[http.MethodGet] == 0 {
		t.Errorf("download entry should only see GET, got %v", downloadMethods)
	}
}

func TestE2E_DownloadSettingsValidation(t *testing.T) {
	serverAddr := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	for name, options := range map[string]*option.V2RayXHTTPOptions{
		"stream-one": {Mode: "stream-one", DownloadSettings: &option.V2RayXHTTPDownloadOptions{}},
		"nested": {DownloadSettings: &option.V2RayXHTTPDownloadOptions{V2RayXHTTPOptions: option.V2RayXHTTPOptions{
			DownloadSettings: &option.V2RayXHTTPDownloadOptions{},
		}}},
	} {
		if _, err := NewClient(context.Background(), N.SystemDialer, serverAddr, options, nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{DownloadSettings: &option.V2RayXHTTPDownloadOptions{}}, nil, echoHandler{}); err == nil {
		t.Error("server should reject download_settings")
	}
}
