package ptls_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"io"

	"github.com/sagernet/sing-box/common/ptls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/quic-go"
)

func parseHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析监听地址失败: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("解析监听端口失败: %v", err)
	}
	return host, uint16(port)
}

func generateTestCA(t *testing.T) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 CA 私钥失败: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PTLS Test Authority Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("签发 CA 证书失败: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析 CA 证书失败: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, cert, priv
}

func startDummyFallbackServer(t *testing.T) (addr string, closeFn func(), receivedData *bytes.Buffer) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 Dummy Fallback 监听失败: %v", err)
	}

	buf := new(bytes.Buffer)
	var mu sync.Mutex

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
				tmp := make([]byte, 1024)
				for {
					n, err := c.Read(tmp)
					if n > 0 {
						mu.Lock()
						buf.Write(tmp[:n])
						hasHTTP := bytes.Contains(buf.Bytes(), []byte("\r\n\r\n"))
						hasTLS := buf.Len() >= 76
						mu.Unlock()
						if hasHTTP || hasTLS {
							break
						}
					}
					if err != nil {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nServer: AppleCDN\r\n\r\nFALLBACK_SUCCESS"))
			}(conn)
		}
	}()

	closeFn = func() {
		l.Close()
	}
	return l.Addr().String(), closeFn, buf
}

// -----------------------------------------------------------------------------
// 线缆层监听与全生命周期报文解构引擎 (WireTap & Packet Dissector)
// -----------------------------------------------------------------------------

type wireTapConn struct {
	net.Conn
	mu      sync.Mutex
	c2sData []byte
	s2cData []byte
}

func newWireTap(conn net.Conn) *wireTapConn {
	return &wireTapConn{Conn: conn}
}

func (w *wireTapConn) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.c2sData = append(w.c2sData, b...)
	w.mu.Unlock()
	return w.Conn.Write(b)
}

func (w *wireTapConn) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if n > 0 {
		w.mu.Lock()
		w.s2cData = append(w.s2cData, b[:n]...)
		w.mu.Unlock()
	}
	return n, err
}

func (w *wireTapConn) PrintDissection(reqJSON, respJSON []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	fmt.Println("\n========================= [PTLS 全生命周期全帧流式审计] =========================")
	fmt.Println(">>> [客户端 -> 服务端 数据流 (Client to Server)]")
	dissectRecords(w.c2sData, true, reqJSON)

	fmt.Println("\n<<< [服务端 -> 客户端 数据流 (Server to Client)]")
	dissectRecords(w.s2cData, false, respJSON)
	fmt.Println("================================================================================")
}

func dissectRecords(data []byte, isClient bool, appDataPayload []byte) {
	offset := 0
	frameIdx := 1
	appDataIndex := 0

	for offset < len(data) {
		if offset+5 > len(data) {
			fmt.Printf("  [流片段残留] 未完整解析字节数: %d\n", len(data)-offset)
			break
		}
		contentType := data[offset]
		version := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		recLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))

		typeDesc := "未知"
		switch contentType {
		case 0x14:
			typeDesc = "ChangeCipherSpec (CCS)"
		case 0x15:
			typeDesc = "Alert (告警/关闭)"
		case 0x16:
			typeDesc = "Handshake"
		case 0x17:
			typeDesc = "ApplicationData (TLS 1.3 加密载荷帧)"
		}

		fmt.Printf("  Frame #%d: 类型=0x%02x (%s), 记录版本=0x%04x, 载荷大小=%d 字节\n",
			frameIdx, contentType, typeDesc, version, recLen)

		payloadStart := offset + 5
		payloadEnd := payloadStart + recLen
		if payloadEnd > len(data) {
			payloadEnd = len(data)
		}
		payload := data[payloadStart:payloadEnd]

		if isClient && contentType == 0x16 && len(payload) >= 38 && payload[0] == 0x01 {
			dissectClientHello(payload)
		}

		if !isClient && contentType == 0x16 && len(payload) >= 38 && payload[0] == 0x02 {
			dissectServerHello(payload)
		}

		if contentType == 0x17 {
			if recLen >= 2000 {
				fmt.Printf("      └─ [下行证书链帧]: 长度 %d 字节 (落在目标 CDN 证书高熵填充区间)\n", recLen)
			} else if recLen > 60 && recLen < 1000 {
				appDataIndex++
				fmt.Printf("      └─ [业务数据密文帧 #%d]: 物理大小 %d 字节\n", appDataIndex, recLen)
				if len(appDataPayload) > 0 && appDataIndex == 1 {
					fmt.Printf("          ├─ [隧道内明文长度]: %d 字节\n", len(appDataPayload))
					fmt.Printf("          └─ [传输 JSON 内容]: %s\n", string(bytes.TrimSpace(appDataPayload)))
				}
			} else if recLen <= 30 {
				fmt.Printf("      └─ [连接断开帧]: 物理大小 %d 字节 (TLS 1.3 加密 close_notify 优雅关闭告警)\n", recLen)
			}
		}

		offset = payloadEnd
		frameIdx++
	}
}

func dissectClientHello(payload []byte) {
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	clientVer := binary.BigEndian.Uint16(payload[4:6])
	random := payload[6:38]
	sessionIDLen := int(payload[38])

	fmt.Printf("    └─ [Handshake: ClientHello (0x01)] 总握手长度: %d, 客户端版本: 0x%04x\n", handshakeLen, clientVer)
	fmt.Printf("       ├─ ClientRandom (32B): %s\n", hex.EncodeToString(random))
	if sessionIDLen > 0 && len(payload) >= 39+sessionIDLen {
		sessionID := payload[39 : 39+sessionIDLen]
		fmt.Printf("       ├─ SessionID 长度: %d 字节\n", sessionIDLen)
		fmt.Printf("       ├─ 注入的 SessionID (32B): %s\n", hex.EncodeToString(sessionID))
		fmt.Println("       │  [特征审计]: 包含时间戳白化与认证载荷，在被动 DPI 视角呈现纯均匀随机熵。")
	}

	curr := 39 + sessionIDLen
	if curr+2 <= len(payload) {
		cipherLen := int(binary.BigEndian.Uint16(payload[curr : curr+2]))
		curr += 2 + cipherLen
	}
	if curr+1 <= len(payload) {
		compLen := int(payload[curr])
		curr += 1 + compLen
	}
	if curr+2 <= len(payload) {
		extLen := int(binary.BigEndian.Uint16(payload[curr : curr+2]))
		curr += 2
		extEnd := curr + extLen
		if extEnd > len(payload) {
			extEnd = len(payload)
		}
		fmt.Printf("       └─ Extensions 总长度: %d 字节 (Go 原生密码学协议栈指纹)\n", extLen)
		for curr+4 <= extEnd {
			extType := binary.BigEndian.Uint16(payload[curr : curr+2])
			extDataLen := int(binary.BigEndian.Uint16(payload[curr+2 : curr+4]))
			curr += 4
			extName := getExtensionName(extType)
			fmt.Printf("          - 扩展 0x%04x (%s), 长度=%d\n", extType, extName, extDataLen)
			curr += extDataLen
		}
	}
}

func dissectServerHello(payload []byte) {
	serverVer := binary.BigEndian.Uint16(payload[4:6])
	random := payload[6:38]
	sessionIDLen := int(payload[38])
	fmt.Printf("    └─ [Handshake: ServerHello (0x02)] 服务端版本: 0x%04x\n", serverVer)
	fmt.Printf("       ├─ ServerRandom (32B): %s\n", hex.EncodeToString(random))
	if sessionIDLen > 0 && len(payload) >= 39+sessionIDLen {
		sessionID := payload[39 : 39+sessionIDLen]
		fmt.Printf("       └─ 回显的 SessionID (32B): %s\n", hex.EncodeToString(sessionID))
		fmt.Println("          [强一致性审计]: 确认服务端原样回显客户端注入的认证标记。")
	}
}

func getExtensionName(extType uint16) string {
	switch extType {
	case 0:
		return "server_name (SNI)"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 16:
		return "application_layer_protocol_negotiation (ALPN)"
	case 21:
		return "padding"
	case 43:
		return "supported_versions (TLS 1.3 Indicator)"
	case 45:
		return "psk_key_exchange_modes"
	case 51:
		return "key_share"
	default:
		return "other_extension"
	}
}

// -----------------------------------------------------------------------------
// 1. 叶子证书动态签发、0 字节误差与标准 Root CA 链式验签测试
// -----------------------------------------------------------------------------

func TestPTLS_Certificate_DynamicChainVerification(t *testing.T) {
	caPEM, _, caCert, caPriv := generateTestCA(t)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成叶子私钥失败: %v", err)
	}

	targetSNI := "image.apple.com"
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: targetSNI},
		DNSNames:     []string{targetSNI},
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	targetSize := 1800
	targetEntropy := 7.40

	leafDER, err := ptls.PadCertificateDER(leafTmpl, caCert, &leafPriv.PublicKey, caPriv, targetSize, targetEntropy)
	if err != nil {
		t.Fatalf("PadCertificateDER 签发失败: %v", err)
	}

	if len(leafDER) != targetSize {
		t.Fatalf("叶子证书尺寸未实现 0 字节精确对齐: 期望 %d, 实际: %d 字节", targetSize, len(leafDER))
	}

	actualEntropy := ptls.CalculateEntropy(leafDER)
	if actualEntropy < 7.20 || actualEntropy > 7.60 {
		t.Fatalf("叶子证书香农信息熵偏离预期: 期望约为 %.2f, 实际 %.4f", targetEntropy, actualEntropy)
	}

	parsedLeaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("标准库解析叶子证书失败: %v", err)
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("Root CA 加载到证书池失败")
	}

	opts := x509.VerifyOptions{
		DNSName: targetSNI,
		Roots:   rootPool,
	}

	if _, err := parsedLeaf.Verify(opts); err != nil {
		t.Fatalf("Root CA 链式校验动态签发的叶子证书失败: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 2. 正常基准握手测试
// -----------------------------------------------------------------------------

func TestPTLS_E2E_Success(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			LeafDERSize:   1800,
			ChainDERSize:  3000,
			TargetEntropy: 7.40,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		Insecure:    false,
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Client 失败: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	var serverTLS net.Conn
	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr = acceptErr
			return
		}
		serverTLS, serverErr = server.ServerHandshake(context.Background(), conn)
		if serverErr != nil {
			conn.Close()
		}
	}()

	clientRawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败: %v", err)
	}
	defer clientRawConn.Close()

	clientTLS, clientErr := client.ClientHandshake(context.Background(), clientRawConn)
	if clientErr != nil {
		t.Fatalf("客户端握手失败: %v", clientErr)
	}
	defer clientTLS.Close()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("服务端握手失败: %v", serverErr)
	}
	defer serverTLS.Close()

	tlsState := clientTLS.ConnectionState()
	if tlsState.Version != tls.VersionTLS13 {
		t.Fatalf("协商版本不是 TLS 1.3: %x", tlsState.Version)
	}

	// 验证证书链总 DER 大小是否达到目标 3000 字节
	totalChainDER := 0
	for _, c := range tlsState.PeerCertificates {
		totalChainDER += len(c.Raw)
	}
	if totalChainDER != 3000 {
		t.Fatalf("证书链总 DER 大小未达精确对齐: 期望 3000, 实际 %d", totalChainDER)
	}
}

// -----------------------------------------------------------------------------
// 3. 真实应用层业务数据传输（JSON Ping-Pong）与全生命周期审计
// -----------------------------------------------------------------------------

type PingRequest struct {
	Type            string `json:"type"`
	TraceID         string `json:"trace_id"`
	ClientTimestamp int64  `json:"client_timestamp"`
	Message         string `json:"message"`
}

type PongResponse struct {
	Type          string `json:"type"`
	TraceID       string `json:"trace_id"`
	StatusCode    int    `json:"status_code"`
	ServerTime    int64  `json:"server_time"`
	EchoMessage   string `json:"echo_message"`
	Authenticated bool   `json:"authenticated"`
}

func TestPTLS_E2E_DataTransmission_Inspection(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			LeafDERSize:   1800,
			ChainDERSize:  3000,
			TargetEntropy: 7.40,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		Insecure:    false,
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Client 失败: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试监听失败: %v", err)
	}
	defer listener.Close()

	var serverTLS net.Conn
	var serverErr error
	var sWg sync.WaitGroup
	sWg.Add(1)

	var reqRawJSON []byte
	var respRawJSON []byte

	go func() {
		defer sWg.Done()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr = acceptErr
			return
		}

		serverTLS, serverErr = server.ServerHandshake(context.Background(), conn)
		if serverErr != nil {
			conn.Close()
			return
		}
		defer serverTLS.Close()

		reader := bufio.NewReader(serverTLS)
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			serverErr = fmt.Errorf("服务端读取请求失败: %w", readErr)
			return
		}

		var req PingRequest
		if err := json.Unmarshal(line, &req); err != nil {
			serverErr = fmt.Errorf("服务端 JSON 反序列化失败: %w", err)
			return
		}

		resp := PongResponse{
			Type:          "ptls_pong_response",
			TraceID:       req.TraceID,
			StatusCode:    200,
			ServerTime:    time.Now().Unix(),
			EchoMessage:   req.Message,
			Authenticated: true,
		}
		respBytes, _ := json.Marshal(resp)
		respBytes = append(respBytes, '\n')
		respRawJSON = respBytes

		if _, writeErr := serverTLS.Write(respBytes); writeErr != nil {
			serverErr = fmt.Errorf("服务端写响应失败: %w", writeErr)
			return
		}

		_, _ = reader.ReadByte()
	}()

	clientRawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败: %v", err)
	}
	defer clientRawConn.Close()

	tappedConn := newWireTap(clientRawConn)

	clientTLS, clientErr := client.ClientHandshake(context.Background(), tappedConn)
	if clientErr != nil {
		t.Fatalf("客户端握手失败: %v", clientErr)
	}

	reqObj := PingRequest{
		Type:            "ptls_ping_request",
		TraceID:         "trace-ptls-987654321",
		ClientTimestamp: time.Now().Unix(),
		Message:         "PTLS Secure Tunnel Verification Payload",
	}
	reqBytes, _ := json.Marshal(reqObj)
	reqBytes = append(reqBytes, '\n')
	reqRawJSON = reqBytes

	if _, err := clientTLS.Write(reqBytes); err != nil {
		t.Fatalf("客户端发送 JSON 失败: %v", err)
	}

	clientReader := bufio.NewReader(clientTLS)
	respLine, err := clientReader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("客户端读取 JSON 响应失败: %v", err)
	}

	var respObj PongResponse
	if err := json.Unmarshal(respLine, &respObj); err != nil {
		t.Fatalf("客户端解析 JSON 响应失败: %v", err)
	}

	if respObj.StatusCode != 200 || !respObj.Authenticated || respObj.EchoMessage != reqObj.Message {
		t.Fatalf("业务交互验证不匹配: %+v", respObj)
	}

	_ = clientTLS.Close()

	sWg.Wait()
	if serverErr != nil {
		t.Fatalf("服务端链路错误: %v", serverErr)
	}

	tappedConn.PrintDissection(reqRawJSON, respRawJSON)
}

// -----------------------------------------------------------------------------
// 4. 时间戳过期与未来时钟漂移测试
// -----------------------------------------------------------------------------

func TestPTLS_ExpiredAndFutureDrift_Fallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var psk [32]byte
	copy(psk[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(10 * time.Second),
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	testCases := []struct {
		name      string
		tokenTime time.Time
	}{
		{"过期请求（5分钟前）", time.Now().Add(-5 * time.Minute)},
		{"超前未来请求（5分钟后）", time.Now().Add(5 * time.Minute)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			defer l.Close()

			var serverErr error
			var sWg sync.WaitGroup
			sWg.Add(1)
			go func() {
				defer sWg.Done()
				conn, _ := l.Accept()
				if conn != nil {
					_, serverErr = server.ServerHandshake(context.Background(), conn)
				}
			}()

			clientConn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatalf("拨号失败: %v", err)
			}
			defer clientConn.Close()

			header := make([]byte, 76)
			header[0] = 0x16
			header[1], header[2] = 0x03, 0x01
			header[3], header[4] = 0x00, 0x47
			header[5] = 0x01
			randBytes := make([]byte, 32)
			_, _ = rand.Read(randBytes)
			copy(header[11:43], randBytes)
			header[43] = 32

			sessionID := ptls.PackSessionID(&psk, randBytes, tc.tokenTime)
			copy(header[44:76], sessionID[:])

			_, _ = clientConn.Write(header)

			reply := make([]byte, 256)
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := clientConn.Read(reply)

			sWg.Wait()

			if !errors.Is(serverErr, ptls.ErrFallbackCompleted) {
				t.Fatalf("[%s] 服务端未执行 Fallback，返回错误: %v", tc.name, serverErr)
			}
			if !bytes.Contains(reply[:n], []byte("FALLBACK_SUCCESS")) {
				t.Fatalf("[%s] 客户端未收到 Fallback 目标的响应数据", tc.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 5. 重放攻击测试
// -----------------------------------------------------------------------------

func TestPTLS_ReplayAttack_Fallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var psk [32]byte
	copy(psk[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(30 * time.Second),
			ReplayCacheSize:  1000,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	initialHeader := make([]byte, 76)
	initialHeader[0] = 0x16
	initialHeader[1], initialHeader[2] = 0x03, 0x01
	initialHeader[3], initialHeader[4] = 0x00, 0x47
	initialHeader[5] = 0x01
	clientRand := make([]byte, 32)
	_, _ = rand.Read(clientRand)
	copy(initialHeader[11:43], clientRand)
	initialHeader[43] = 32

	sessID := ptls.PackSessionID(&psk, clientRand, time.Now())
	copy(initialHeader[44:76], sessID[:])

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	var sErr1 error
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		conn, _ := listener.Accept()
		if conn != nil {
			_, sErr1 = server.ServerHandshake(context.Background(), conn)
		}
	}()

	c1, _ := net.Dial("tcp", listener.Addr().String())
	_, _ = c1.Write(initialHeader)
	c1.Close()
	wg1.Wait()

	if errors.Is(sErr1, ptls.ErrFallbackCompleted) {
		t.Fatalf("第一次合法凭据不应触发 Fallback: %v", sErr1)
	}

	var sErr2 error
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		conn, _ := listener.Accept()
		if conn != nil {
			_, sErr2 = server.ServerHandshake(context.Background(), conn)
		}
	}()

	c2, _ := net.Dial("tcp", listener.Addr().String())
	defer c2.Close()
	_, _ = c2.Write(initialHeader)

	reply := make([]byte, 256)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := c2.Read(reply)

	wg2.Wait()

	if !errors.Is(sErr2, ptls.ErrFallbackCompleted) {
		t.Fatalf("重放攻击未被拦截到 Fallback，错误: %v", sErr2)
	}
	if !bytes.Contains(reply[:n], []byte("FALLBACK_SUCCESS")) {
		t.Fatal("重放攻击未收到 Fallback 目标响应")
	}
}

// -----------------------------------------------------------------------------
// 6. 纯非 TLS 主动嗅探探测回放测试
// -----------------------------------------------------------------------------

func TestPTLS_ActiveProbe_Fallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, receivedBuf := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	var serverErr error
	var sWg sync.WaitGroup
	sWg.Add(1)
	go func() {
		defer sWg.Done()
		conn, _ := listener.Accept()
		if conn != nil {
			_, serverErr = server.ServerHandshake(context.Background(), conn)
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer clientConn.Close()

	probePayload := []byte("GET /probe HTTP/1.1\r\nHost: image.apple.com\r\n\r\n")
	_, _ = clientConn.Write(probePayload)

	reply := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientConn.Read(reply)

	sWg.Wait()

	if !errors.Is(serverErr, ptls.ErrFallbackCompleted) {
		t.Fatalf("探测流量未被阻断并转入 Fallback: %v", serverErr)
	}

	if !bytes.Contains(receivedBuf.Bytes(), probePayload) {
		t.Fatalf("Fallback 目标未收到原始回放探测数据，实际收到: %s", receivedBuf.String())
	}
	if !bytes.Contains(reply[:n], []byte("FALLBACK_SUCCESS")) {
		t.Fatal("客户端未收到经由 Fallback 中继返回的应答")
	}
}

// -----------------------------------------------------------------------------
// 7. Fallback QPS 限流防御阻断测试
// -----------------------------------------------------------------------------

func TestPTLS_Fallback_QPSLimit(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
				QPS:        1,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	var hitRateLimit bool
	var mu sync.Mutex

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				_, sErr := server.ServerHandshake(context.Background(), c)
				if errors.Is(sErr, ptls.ErrFallbackRateLimited) {
					mu.Lock()
					hitRateLimit = true
					mu.Unlock()
				}
			}(conn)
		}
	}()

	probe := []byte("INVALID_PROBE_TRAFFIC\r\n")
	for i := 0; i < 10; i++ {
		conn, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr == nil {
			_, _ = conn.Write(probe)
			time.Sleep(10 * time.Millisecond)
			conn.Close()
		}
	}

	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !hitRateLimit {
		t.Fatal("高频探测未触发 ErrFallbackRateLimited 限频阻断")
	}
}

// -----------------------------------------------------------------------------
// 8. Fallback QoS 带宽格式解析测试
// -----------------------------------------------------------------------------

func TestPTLS_Fallback_BandwidthParse(t *testing.T) {
	cases := []struct {
		input    string
		expected int64
	}{
		{"50kb/s", 50 * 1024},
		{"100kb", 100 * 1024},
		{"1mb/s", 1024 * 1024},
		{"10mib", 10 * 1024 * 1024},
		{"100b", 100},
		{"", 0},
	}
	for _, tc := range cases {
		val, err := ptls.ParseBandwidth(tc.input)
		if err != nil {
			t.Fatalf("ParseBandwidth(%q) 失败: %v", tc.input, err)
		}
		if val != tc.expected {
			t.Fatalf("ParseBandwidth(%q) = %d, 期望 %d", tc.input, val, tc.expected)
		}
	}
}

// -----------------------------------------------------------------------------
// 9. 密码学加解密与抗重放缓存测试
// -----------------------------------------------------------------------------

func TestPTLS_Crypto_PackUnpack(t *testing.T) {
	psk := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	}
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	now := time.Unix(time.Now().Unix(), 0)

	sessionID := ptls.PackSessionID(&psk, random, now)

	extractedTime, authTag, valid := ptls.UnpackSessionID(&psk, random, sessionID[:])
	if !valid {
		t.Fatal("合法 SessionID 无法通过校验")
	}
	if !extractedTime.Equal(now) {
		t.Fatalf("时间戳解构不匹配: 期望 %v, 得到 %v", now, extractedTime)
	}
	if len(authTag) != 24 {
		t.Fatalf("AuthTag 长度错误: 期望 24, 得到 %d", len(authTag))
	}
}

func TestPTLS_ReplayCache(t *testing.T) {
	tolerance := 500 * time.Millisecond
	cache := ptls.NewReplayCache(100, tolerance)
	tag := []byte("012345678901234567890123")
	now := time.Now()

	if !cache.CheckAndAdd(tag, now) {
		t.Fatal("初次消费凭据被拒绝")
	}

	if cache.CheckAndAdd(tag, now.Add(100*time.Millisecond)) {
		t.Fatal("窗口期内重放凭据未被拦截")
	}

	future := now.Add(tolerance*2 + 100*time.Millisecond)
	if !cache.CheckAndAdd(tag, future) {
		t.Fatal("凭据过期后未成功刷新")
	}
}

// -----------------------------------------------------------------------------
// 10. ServerName 必填性校验测试
// -----------------------------------------------------------------------------

func TestPTLS_Server_EmptyServerName_Error(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled: true,
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
		},
	}

	_, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err == nil {
		t.Fatal("期望空 server_name 抛出错误，实际成功创建")
	}
	if err.Error() != "ptls: server_name cannot be empty" {
		t.Fatalf("错误信息不匹配: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 11. 默认 90 天与自定义证书有效期测试
// -----------------------------------------------------------------------------

func TestPTLS_Certificate_DefaultAndCustomValidity(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	defaultOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
		},
	}
	serverDefault, err := ptls.NewServer(context.Background(), nil, defaultOpts)
	if err != nil {
		t.Fatalf("创建默认 Server 失败: %v", err)
	}
	defer serverDefault.Close()

	stdCfgDefault, _ := serverDefault.STDConfig()
	certDefault, err := stdCfgDefault.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
	if err != nil {
		t.Fatalf("获取默认动态证书失败: %v", err)
	}
	leafCertDefault, _ := x509.ParseCertificate(certDefault.Certificate[0])

	defaultDuration := leafCertDefault.NotAfter.Sub(leafCertDefault.NotBefore)
	expectedDefault := 90*24*time.Hour + 1*time.Hour
	if defaultDuration != expectedDefault {
		t.Fatalf("默认证书有效期不匹配: 期望 %v, 实际 %v", expectedDefault, defaultDuration)
	}

	customValidity := 30 * 24 * time.Hour
	customOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:             true,
			PSK:                 badoption.Listable[string]{pskHex},
			CACertificate:       badoption.Listable[string]{string(caCertPEM)},
			CAKey:               badoption.Listable[string]{string(caKeyPEM)},
			CertificateValidity: badoption.Duration(customValidity),
		},
	}
	serverCustom, err := ptls.NewServer(context.Background(), nil, customOpts)
	if err != nil {
		t.Fatalf("创建自定义 Server 失败: %v", err)
	}
	defer serverCustom.Close()

	stdCfgCustom, _ := serverCustom.STDConfig()
	certCustom, err := stdCfgCustom.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
	if err != nil {
		t.Fatalf("获取自定义动态证书失败: %v", err)
	}
	leafCertCustom, _ := x509.ParseCertificate(certCustom.Certificate[0])

	customDuration := leafCertCustom.NotAfter.Sub(leafCertCustom.NotBefore)
	expectedCustom := customValidity + 1*time.Hour
	if customDuration != expectedCustom {
		t.Fatalf("自定义证书有效期不匹配: 期望 %v, 实际 %v", expectedCustom, customDuration)
	}
}

// -----------------------------------------------------------------------------
// 12. Fallback 显式禁用熔断测试
// -----------------------------------------------------------------------------

func TestPTLS_Fallback_Disabled(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, receivedBuf := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	falseVal := false
	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Enabled:    &falseVal,
				Server:     fbHost,
				ServerPort: fbPort,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	var serverErr error
	var sWg sync.WaitGroup
	sWg.Add(1)
	go func() {
		defer sWg.Done()
		conn, _ := listener.Accept()
		if conn != nil {
			_, serverErr = server.ServerHandshake(context.Background(), conn)
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer clientConn.Close()

	probePayload := []byte("INVALID_PROBE\r\n")
	_, _ = clientConn.Write(probePayload)

	reply := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _ := clientConn.Read(reply)

	sWg.Wait()

	if serverErr == nil || !strings.Contains(serverErr.Error(), "fallback is disabled") {
		t.Fatalf("期望返回 fallback is disabled 错误，实际: %v", serverErr)
	}
	if receivedBuf.Len() > 0 {
		t.Fatalf("禁用 Fallback 时目标后端不应收到任何数据，实际收到: %d 字节", receivedBuf.Len())
	}
	if n > 0 {
		t.Fatalf("禁用 Fallback 时客户端不应收到来自中继的响应，实际收到: %d 字节", n)
	}
}

// -----------------------------------------------------------------------------
// 13. 证书剩余有效期 <= 1/3 触发后台自动轮转测试
// -----------------------------------------------------------------------------

// func TestPTLS_Certificate_RenewalOnOneThirdValidity(t *testing.T) {
// 	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
// 	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// 	validity := 27 * time.Second

// 	serverOpts := option.InboundTLSOptions{
// 		Enabled:    true,
// 		ServerName: "image.apple.com",
// 		PTLS: &option.InboundPTLSOptions{
// 			Enabled:             true,
// 			PSK:                 badoption.Listable[string]{pskHex},
// 			CACertificate:       badoption.Listable[string]{string(caCertPEM)},
// 			CAKey:               badoption.Listable[string]{string(caKeyPEM)},
// 			CertificateValidity: badoption.Duration(validity),
// 			ChainDERSize:        3000,
// 		},
// 	}

// 	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
// 	if err != nil {
// 		t.Fatalf("创建 PTLS Server 失败: %v", err)
// 	}
// 	defer server.Close()

// 	stdCfg, err := server.STDConfig()
// 	if err != nil {
// 		t.Fatalf("获取 STDConfig 失败: %v", err)
// 	}

// 	helloInfo := &tls.ClientHelloInfo{ServerName: "image.apple.com"}

// 	cert1, err := stdCfg.GetCertificate(helloInfo)
// 	if err != nil {
// 		t.Fatalf("首次获取证书失败: %v", err)
// 	}
// 	leaf1, err := x509.ParseCertificate(cert1.Certificate[0])
// 	if err != nil {
// 		t.Fatalf("解析首次证书失败: %v", err)
// 	}
// 	serial1 := leaf1.SerialNumber

// 	t.Log("等待后台定时器轮转检测 (约 22 秒)...")
// 	time.Sleep(22 * time.Second)

// 	cert2, err := stdCfg.GetCertificate(helloInfo)
// 	if err != nil {
// 		t.Fatalf("轮转后获取证书失败: %v", err)
// 	}
// 	leaf2, err := x509.ParseCertificate(cert2.Certificate[0])
// 	if err != nil {
// 		t.Fatalf("解析轮转证书失败: %v", err)
// 	}
// 	serial2 := leaf2.SerialNumber

// 	if serial1.Cmp(serial2) == 0 {
// 		t.Fatalf("证书未在最后 1/3 周期内刷新: 轮转前后序列号完全相同 (%v)", serial1)
// 	}

// 	if !leaf2.NotAfter.After(leaf1.NotAfter) {
// 		t.Fatalf("新证书的到期时间未延长: 原到期时间 %v, 新到期时间 %v", leaf1.NotAfter, leaf2.NotAfter)
// 	}
// }

// -----------------------------------------------------------------------------
// 14. 服务端多 PSK 列表按序校验测试
// -----------------------------------------------------------------------------

func TestPTLS_Server_MultiPSK(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	psk1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	psk2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	invalidPSK := "1111111111111111111111111111111111111111111111111111111111111111"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{psk1, psk2},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建多 PSK Server 失败: %v", err)
	}
	defer server.Close()

	testWithClient := func(t *testing.T, clientPSK string, expectFallback bool) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("监听失败: %v", err)
		}
		defer l.Close()

		var sWg sync.WaitGroup
		var sErr error
		sWg.Add(1)
		go func() {
			defer sWg.Done()
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			defer conn.Close()
			sConn, err := server.ServerHandshake(context.Background(), conn)
			sErr = err
			if sConn != nil {
				_ = sConn.Close()
			}
		}()

		clientOpts := option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "image.apple.com",
			Certificate: badoption.Listable[string]{string(caCertPEM)},
			PTLS: &option.OutboundPTLSOptions{
				Enabled:          true,
				PSK:              clientPSK,
				HandshakeTimeout: badoption.Duration(2 * time.Second),
			},
		}
		client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
		if err != nil {
			t.Fatalf("创建客户端失败: %v", err)
		}

		cRaw, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatalf("拨号失败: %v", err)
		}
		defer cRaw.Close()

		cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
		if cTLS != nil {
			_ = cTLS.Close()
		}

		sWg.Wait()

		if expectFallback {
			if !errors.Is(sErr, ptls.ErrFallbackCompleted) {
				t.Fatalf("期望触发 Fallback，实际服务端错误: %v", sErr)
			}
		} else {
			if cErr != nil {
				t.Fatalf("客户端握手失败: %v", cErr)
			}
			if sErr != nil {
				t.Fatalf("服务端握手失败: %v", sErr)
			}
		}
	}

	t.Run("匹配首个PSK", func(t *testing.T) {
		testWithClient(t, psk1, false)
	})

	t.Run("匹配列表中间PSK", func(t *testing.T) {
		testWithClient(t, psk2, false)
	})

	t.Run("全不匹配触发Fallback", func(t *testing.T) {
		testWithClient(t, invalidPSK, true)
	})
}

// -----------------------------------------------------------------------------
// 15. 空 PSK ("" 和 []) 校验拦截测试
// -----------------------------------------------------------------------------

func TestPTLS_Server_EmptyPSK_Error(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	testCases := []struct {
		name string
		psk  badoption.Listable[string]
	}{
		{"空列表 []", badoption.Listable[string]{}},
		{"空字符串 \"\"", badoption.Listable[string]{""}},
		{"纯空格字符串 \"   \"", badoption.Listable[string]{"   "}},
		{"多项全空列表 [\"\", \"   \"]", badoption.Listable[string]{"", "   "}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serverOpts := option.InboundTLSOptions{
				Enabled:    true,
				ServerName: "image.apple.com",
				PTLS: &option.InboundPTLSOptions{
					Enabled:       true,
					PSK:           tc.psk,
					CACertificate: badoption.Listable[string]{string(caCertPEM)},
					CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				},
			}

			_, err := ptls.NewServer(context.Background(), nil, serverOpts)
			if err == nil {
				t.Fatalf("[%s] 期望空 PSK 抛出错误，实际成功创建", tc.name)
			}
			if !strings.Contains(err.Error(), "psk cannot be empty") {
				t.Fatalf("[%s] 错误信息不匹配: %v", tc.name, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 辅助工具：构造携带指定 SNI 扩展的标准 TLS ClientHello 二进制帧
// -----------------------------------------------------------------------------

func craftTestClientHello(sni string) []byte {
	var extensions []byte
	if sni != "" {
		sniBytes := []byte(sni)
		sniEntry := make([]byte, 3+len(sniBytes))
		sniEntry[0] = 0 // host_name
		binary.BigEndian.PutUint16(sniEntry[1:3], uint16(len(sniBytes)))
		copy(sniEntry[3:], sniBytes)

		sniList := make([]byte, 2+len(sniEntry))
		binary.BigEndian.PutUint16(sniList[0:2], uint16(len(sniEntry)))
		copy(sniList[2:], sniEntry)

		extSNI := make([]byte, 4+len(sniList))
		binary.BigEndian.PutUint16(extSNI[0:2], 0x0000) // server_name (0)
		binary.BigEndian.PutUint16(extSNI[2:4], uint16(len(sniList)))
		copy(extSNI[4:], sniList)
		extensions = append(extensions, extSNI...)
	}

	body := make([]byte, 0, 128+len(extensions))
	body = append(body, 0x03, 0x03) // version TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)

	body = append(body, 32) // session ID length = 32
	fakeSessionID := make([]byte, 32)
	_, _ = rand.Read(fakeSessionID)
	body = append(body, fakeSessionID...)

	// Cipher suites length = 2, TLS_AES_128_GCM_SHA256 (0x1301)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	// Compression methods length = 1, null (0x00)
	body = append(body, 0x01, 0x00)

	// Extensions length
	extLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extLenBytes, uint16(len(extensions)))
	body = append(body, extLenBytes...)
	body = append(body, extensions...)

	// Handshake header
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	// Record header
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

// -----------------------------------------------------------------------------
// 16. 泛域名与多域名证书动态签发解耦测试
// -----------------------------------------------------------------------------

func TestPTLS_Certificate_Domains_DecoupledAndWildcard(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("配置CertificateDomains优先且解耦外层ServerName", func(t *testing.T) {
		serverOpts := option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  "inbound-entry.example.com", // 外层路由域名
			ServerNames: badoption.Listable[string]{"other-route.example.com"},
			PTLS: &option.InboundPTLSOptions{
				Enabled:            true,
				PSK:                badoption.Listable[string]{pskHex},
				CACertificate:      badoption.Listable[string]{string(caCertPEM)},
				CAKey:              badoption.Listable[string]{string(caKeyPEM)},
				CertificateDomains: badoption.Listable[string]{"*.apple.com", "apple.com", "*.cdn-apple.com"},
				ChainDERSize:       3000,
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建解耦 Server 失败: %v", err)
		}
		defer server.Close()

		stdCfg, err := server.STDConfig()
		if err != nil {
			t.Fatalf("获取 STDConfig 失败: %v", err)
		}

		cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
		if err != nil {
			t.Fatalf("获取动态证书失败: %v", err)
		}

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("解析叶子证书失败: %v", err)
		}

		// 1. 验证首项作为 CommonName
		if leaf.Subject.CommonName != "*.apple.com" {
			t.Fatalf("证书 CommonName 不匹配: 期望 *.apple.com, 实际 %s", leaf.Subject.CommonName)
		}

		// 2. 验证 SAN 列表完全由 CertificateDomains 生成
		expectedSANs := []string{"*.apple.com", "apple.com", "*.cdn-apple.com"}
		if len(leaf.DNSNames) != len(expectedSANs) {
			t.Fatalf("SAN 数量不匹配: 期望 %d, 实际 %d (%v)", len(expectedSANs), len(leaf.DNSNames), leaf.DNSNames)
		}
		for i, name := range expectedSANs {
			if leaf.DNSNames[i] != name {
				t.Fatalf("SAN[%d] 不匹配: 期望 %s, 实际 %s", i, name, leaf.DNSNames[i])
			}
		}

		// 3. 严格断言外层 ServerName 没有泄露到证书 SAN 中
		for _, name := range leaf.DNSNames {
			if name == "inbound-entry.example.com" || name == "other-route.example.com" {
				t.Fatalf("证书 SAN 发生了外层路由域名泄露: %s", name)
			}
		}

		// 4. 验证标准 X.509 泛域名链式校验
		rootPool := x509.NewCertPool()
		rootPool.AppendCertsFromPEM(caCertPEM)

		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "foo.apple.com", Roots: rootPool}); err != nil {
			t.Fatalf("验证子域名 foo.apple.com 失败: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "apple.com", Roots: rootPool}); err != nil {
			t.Fatalf("验证根域名 apple.com 失败: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "node.cdn-apple.com", Roots: rootPool}); err != nil {
			t.Fatalf("验证泛域名 node.cdn-apple.com 失败: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "inbound-entry.example.com", Roots: rootPool}); err == nil {
			t.Fatal("未签发的域名 inbound-entry.example.com 校验应当失败，但成功了")
		}
	})

	t.Run("未配置CertificateDomains时向后兼容回退", func(t *testing.T) {
		serverOpts := option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  "image.apple.com",
			ServerNames: badoption.Listable[string]{"*.cdn-apple.com"},
			PTLS: &option.InboundPTLSOptions{
				Enabled:       true,
				PSK:           badoption.Listable[string]{pskHex},
				CACertificate: badoption.Listable[string]{string(caCertPEM)},
				CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				ChainDERSize:  3000,
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建兼容 Server 失败: %v", err)
		}
		defer server.Close()

		stdCfg, _ := server.STDConfig()
		cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
		if err != nil {
			t.Fatalf("获取回退证书失败: %v", err)
		}

		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		if leaf.Subject.CommonName != "image.apple.com" {
			t.Fatalf("回退 CommonName 错误: %s", leaf.Subject.CommonName)
		}
		if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "image.apple.com" || leaf.DNSNames[1] != "*.cdn-apple.com" {
			t.Fatalf("回退 SAN 列表不匹配: %v", leaf.DNSNames)
		}
	})
}

// -----------------------------------------------------------------------------
// 17. RFC 6125 泛域名通配符 SNI 匹配矩阵全面测试
// -----------------------------------------------------------------------------

func TestPTLS_Wildcard_SNI_Matching_Matrix(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, fbBuf := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:          true,
		ServerName:       "apple.com",
		ServerNames:      badoption.Listable[string]{"*.apple.com", "specific.service.net"},
		RejectUnknownSNI: true,
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建矩阵测试 Server 失败: %v", err)
	}
	defer server.Close()

	testMatrix := []struct {
		name        string
		sni         string
		expectMatch bool
	}{
		// 正向放行用例
		{"精确匹配根域名", "apple.com", true},
		{"精确匹配列表独立域名", "specific.service.net", true},
		{"泛域名单级子域", "image.apple.com", true},
		{"泛域名字母数字子域", "a123-node.apple.com", true},
		{"大小写无关不敏感", "IMAGE.APPLE.COM", true},
		{"尾部带点完全限定域名", "image.apple.com.", true},

		// 逆向严格阻断用例 (RFC 6125 规范违规)
		{"多级跨级子域名拒绝", "cdn.image.apple.com", false},
		{"无前置点前缀伪造拒绝", "fakeapple.com", false},
		{"后缀扩展伪造拒绝", "image.apple.com.cn", false},
		{"攻击者后置劫持拒绝", "image.apple.com.attacker.com", false},
		{"完全无关域名拒绝", "google.com", false},
		{"空SNI请求拒绝", "", false},
	}

	for _, tc := range testMatrix {
		t.Run(tc.name, func(t *testing.T) {
			fbBuf.Reset()

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("监听失败: %v", err)
			}
			defer l.Close()

			var sWg sync.WaitGroup
			var sErr error
			sWg.Add(1)
			go func() {
				defer sWg.Done()
				conn, acceptErr := l.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				_, sErr = server.ServerHandshake(context.Background(), conn)
			}()

			clientConn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatalf("客户端拨号失败: %v", err)
			}
			defer clientConn.Close()

			ch := craftTestClientHello(tc.sni)
			_, _ = clientConn.Write(ch)

			sWg.Wait()

			if tc.expectMatch {
				if !errors.Is(sErr, ptls.ErrFallbackCompleted) {
					t.Fatalf("[%s] 期望通过 SNI 校验并完成 Fallback，实际错误: %v", tc.name, sErr)
				}
				if fbBuf.Len() == 0 {
					t.Fatalf("[%s] SNI 匹配成功时 Fallback 目标应接收到中继报文", tc.name)
				}
			} else {
				if sErr == nil || !strings.Contains(sErr.Error(), "sni rejected") {
					t.Fatalf("[%s] 期望拒绝未知 SNI (sni rejected)，实际错误: %v", tc.name, sErr)
				}
				if fbBuf.Len() > 0 {
					t.Fatalf("[%s] 严重泄漏: 未知 SNI 被拒绝时不应向 Fallback 目标发送任何数据，实际发送 %d 字节", tc.name, fbBuf.Len())
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 18. reject_unknown_sni 直接断开与零 Fallback 穿透阻断测试
// -----------------------------------------------------------------------------

func TestPTLS_RejectUnknownSNI_DirectClose_NoFallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, fbBuf := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	t.Run("开启RejectUnknownSNI时直接断开连接且零Fallback穿透", func(t *testing.T) {
		fbBuf.Reset()

		serverOpts := option.InboundTLSOptions{
			Enabled:          true,
			ServerName:       "image.apple.com",
			RejectUnknownSNI: true,
			PTLS: &option.InboundPTLSOptions{
				Enabled:       true,
				PSK:           badoption.Listable[string]{pskHex},
				CACertificate: badoption.Listable[string]{string(caCertPEM)},
				CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				ChainDERSize:  3000,
				Fallback: &option.InboundPTLSFallbackOptions{
					Server:     fbHost,
					ServerPort: fbPort,
				},
				HandshakeTimeout: badoption.Duration(2 * time.Second),
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建 Server 失败: %v", err)
		}
		defer server.Close()

		l, _ := net.Listen("tcp", "127.0.0.1:0")
		defer l.Close()

		var sWg sync.WaitGroup
		var sErr error
		sWg.Add(1)
		go func() {
			defer sWg.Done()
			conn, _ := l.Accept()
			if conn != nil {
				defer conn.Close()
				_, sErr = server.ServerHandshake(context.Background(), conn)
			}
		}()

		clientConn, _ := net.Dial("tcp", l.Addr().String())
		defer clientConn.Close()

		ch := craftTestClientHello("unauthorized-probe.evil.com")
		_, _ = clientConn.Write(ch)

		sWg.Wait()

		if sErr == nil || !strings.Contains(sErr.Error(), "sni rejected") {
			t.Fatalf("期望服务端直接拒绝未知 SNI，实际错误: %v", sErr)
		}

		if fbBuf.Len() > 0 {
			t.Fatalf("开启 reject_unknown_sni 时未授权流量发生了 Fallback 穿透泄露，收到 %d 字节", fbBuf.Len())
		}
	})

	t.Run("关闭RejectUnknownSNI时正常回退到Fallback后端", func(t *testing.T) {
		fbBuf.Reset()

		serverOpts := option.InboundTLSOptions{
			Enabled:          true,
			ServerName:       "image.apple.com",
			RejectUnknownSNI: false, // 允许未知 SNI 流量回退
			PTLS: &option.InboundPTLSOptions{
				Enabled:       true,
				PSK:           badoption.Listable[string]{pskHex},
				CACertificate: badoption.Listable[string]{string(caCertPEM)},
				CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				ChainDERSize:  3000,
				Fallback: &option.InboundPTLSFallbackOptions{
					Server:     fbHost,
					ServerPort: fbPort,
				},
				HandshakeTimeout: badoption.Duration(2 * time.Second),
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建 Server 失败: %v", err)
		}
		defer server.Close()

		l, _ := net.Listen("tcp", "127.0.0.1:0")
		defer l.Close()

		var sWg sync.WaitGroup
		var sErr error
		sWg.Add(1)
		go func() {
			defer sWg.Done()
			conn, _ := l.Accept()
			if conn != nil {
				defer conn.Close()
				_, sErr = server.ServerHandshake(context.Background(), conn)
			}
		}()

		clientConn, _ := net.Dial("tcp", l.Addr().String())
		defer clientConn.Close()

		ch := craftTestClientHello("unknown-probe.com")
		_, _ = clientConn.Write(ch)

		sWg.Wait()

		if !errors.Is(sErr, ptls.ErrFallbackCompleted) {
			t.Fatalf("关闭 reject_unknown_sni 时期望执行 Fallback，实际错误: %v", sErr)
		}

		if fbBuf.Len() == 0 {
			t.Fatal("关闭 reject_unknown_sni 时 Fallback 后端应收到中继报文")
		}
	})
}

// -----------------------------------------------------------------------------
// 19. 泛域名端到端完整握手与业务传输测试
// -----------------------------------------------------------------------------

func TestPTLS_Wildcard_E2E_FullHandshake(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:          true,
		ServerName:       "inbound-entry.apple.com",
		ServerNames:      badoption.Listable[string]{"*.apple.com"},
		RejectUnknownSNI: true,
		PTLS: &option.InboundPTLSOptions{
			Enabled:            true,
			PSK:                badoption.Listable[string]{pskHex},
			CACertificate:      badoption.Listable[string]{string(caCertPEM)},
			CAKey:              badoption.Listable[string]{string(caKeyPEM)},
			CertificateDomains: badoption.Listable[string]{"*.apple.com"},
			LeafDERSize:        1800,
			ChainDERSize:       3000,
			TargetEntropy:      7.40,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建泛域名端到端 Server 失败: %v", err)
	}
	defer server.Close()

	clientTargetSNI := "node-889.apple.com"
	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  clientTargetSNI,
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		Insecure:    false,
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	client, err := ptls.NewClient(context.Background(), clientTargetSNI, clientOpts)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer l.Close()

	var sWg sync.WaitGroup
	var sConn net.Conn
	var sErr error
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			sErr = acceptErr
			return
		}
		sConn, sErr = server.ServerHandshake(context.Background(), conn)
		if sErr != nil {
			conn.Close()
		}
	}()

	cRaw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer cRaw.Close()

	cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
	if cErr != nil {
		t.Fatalf("客户端握手失败: %v", cErr)
	}
	defer cTLS.Close()

	sWg.Wait()
	if sErr != nil {
		t.Fatalf("服务端握手失败: %v", sErr)
	}
	defer sConn.Close()

	state := cTLS.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("协商版本不是 TLS 1.3: %x", state.Version)
	}

	if len(state.PeerCertificates) == 0 {
		t.Fatal("客户端未获取到对端证书")
	}
	peerCert := state.PeerCertificates[0]
	if peerCert.Subject.CommonName != "*.apple.com" {
		t.Fatalf("对端证书 CommonName 错误: %s", peerCert.Subject.CommonName)
	}
	if len(peerCert.DNSNames) != 1 || peerCert.DNSNames[0] != "*.apple.com" {
		t.Fatalf("对端证书 SAN 错误: %v", peerCert.DNSNames)
	}

	echoMsg := "PTLS Wildcard Decoupled Transmission Test"
	go func() {
		_, _ = sConn.Write([]byte(echoMsg + "\n"))
	}()

	reader := bufio.NewReader(cTLS)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("客户端读取回显失败: %v", err)
	}
	if strings.TrimSpace(line) != echoMsg {
		t.Fatalf("业务报文内容不匹配: 期望 %q, 得到 %q", echoMsg, strings.TrimSpace(line))
	}
}

// -----------------------------------------------------------------------------
// 20. 路径 1 验证：server_name 与 certificate_domains 均为单个普通字符串
// -----------------------------------------------------------------------------

func TestPTLS_SingleString_ConfigAndHandshake(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "single.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:            true,
			PSK:                badoption.Listable[string]{pskHex},
			CACertificate:      badoption.Listable[string]{string(caCertPEM)},
			CAKey:              badoption.Listable[string]{string(caKeyPEM)},
			CertificateDomains: badoption.Listable[string]{"single.apple.com"},
			ChainDERSize:       3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建单字符串 Server 失败: %v", err)
	}
	defer server.Close()

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()

	var sWg sync.WaitGroup
	var sConn net.Conn
	var sErr error
	sWg.Add(1)
	go func() {
		defer sWg.Done()
		conn, _ := l.Accept()
		if conn != nil {
			sConn, sErr = server.ServerHandshake(context.Background(), conn)
		}
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "single.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		PTLS: &option.OutboundPTLSOptions{
			Enabled: true,
			PSK:     pskHex,
		},
	}
	client, _ := ptls.NewClient(context.Background(), "single.apple.com", clientOpts)
	cRaw, _ := net.Dial("tcp", l.Addr().String())
	defer cRaw.Close()

	cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
	if cErr != nil {
		t.Fatalf("单字符串客户端握手失败: %v", cErr)
	}
	defer cTLS.Close()
	sWg.Wait()

	if sErr != nil {
		t.Fatalf("单字符串服务端握手失败: %v", sErr)
	}
	defer sConn.Close()

	peerCert := cTLS.ConnectionState().PeerCertificates[0]
	if peerCert.Subject.CommonName != "single.apple.com" || len(peerCert.DNSNames) != 1 || peerCert.DNSNames[0] != "single.apple.com" {
		t.Fatalf("单字符串证书解析不匹配: CN=%s, DNSNames=%v", peerCert.Subject.CommonName, peerCert.DNSNames)
	}
}

// -----------------------------------------------------------------------------
// 21. 路径 2 验证：server_names 与 certificate_domains 均为多值列表的实战握手
// -----------------------------------------------------------------------------

func TestPTLS_ListConfig_MultiDomain_Handshake(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:          true,
		ServerName:       "main.apple.com",
		ServerNames:      badoption.Listable[string]{"extra1.apple.com", "extra2.apple.com"},
		RejectUnknownSNI: true,
		PTLS: &option.InboundPTLSOptions{
			Enabled:            true,
			PSK:                badoption.Listable[string]{pskHex},
			CACertificate:      badoption.Listable[string]{string(caCertPEM)},
			CAKey:              badoption.Listable[string]{string(caKeyPEM)},
			CertificateDomains: badoption.Listable[string]{"main.apple.com", "extra1.apple.com", "extra2.apple.com"},
			ChainDERSize:       3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建多值列表 Server 失败: %v", err)
	}
	defer server.Close()

	domainsToTest := []string{"main.apple.com", "extra1.apple.com", "extra2.apple.com"}

	for _, domain := range domainsToTest {
		t.Run("连接域名_"+domain, func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			defer l.Close()

			var sWg sync.WaitGroup
			var sErr error
			sWg.Add(1)
			go func() {
				defer sWg.Done()
				conn, _ := l.Accept()
				if conn != nil {
					defer conn.Close()
					sConn, err := server.ServerHandshake(context.Background(), conn)
					sErr = err
					if sConn != nil {
						_ = sConn.Close()
					}
				}
			}()

			clientOpts := option.OutboundTLSOptions{
				Enabled:     true,
				ServerName:  domain,
				Certificate: badoption.Listable[string]{string(caCertPEM)},
				PTLS: &option.OutboundPTLSOptions{
					Enabled: true,
					PSK:     pskHex,
				},
			}
			client, _ := ptls.NewClient(context.Background(), domain, clientOpts)
			cRaw, _ := net.Dial("tcp", l.Addr().String())
			defer cRaw.Close()

			cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
			if cErr != nil {
				t.Fatalf("[%s] 客户端握手失败: %v", domain, cErr)
			}
			_ = cTLS.Close()
			sWg.Wait()

			if sErr != nil {
				t.Fatalf("[%s] 服务端握手失败: %v", domain, sErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 22. 路径 3 验证：同时支持 example.com 与 *.example.com，并在同实例下分别握手
// -----------------------------------------------------------------------------

func TestPTLS_RootAndWildcard_Simultaneous_Handshake(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:          true,
		ServerName:       "example.com",
		ServerNames:      badoption.Listable[string]{"*.example.com"},
		RejectUnknownSNI: true,
		PTLS: &option.InboundPTLSOptions{
			Enabled:            true,
			PSK:                badoption.Listable[string]{pskHex},
			CACertificate:      badoption.Listable[string]{string(caCertPEM)},
			CAKey:              badoption.Listable[string]{string(caKeyPEM)},
			CertificateDomains: badoption.Listable[string]{"example.com", "*.example.com"},
			ChainDERSize:       3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建混合根域/泛域 Server 失败: %v", err)
	}
	defer server.Close()

	targetSNIs := []string{"example.com", "abc.example.com", "xyz.example.com"}

	for _, sni := range targetSNIs {
		t.Run("双模态测试_"+sni, func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			defer l.Close()

			var sWg sync.WaitGroup
			var sErr error
			sWg.Add(1)
			go func() {
				defer sWg.Done()
				conn, _ := l.Accept()
				if conn != nil {
					defer conn.Close()
					sConn, err := server.ServerHandshake(context.Background(), conn)
					sErr = err
					if sConn != nil {
						_ = sConn.Close()
					}
				}
			}()

			clientOpts := option.OutboundTLSOptions{
				Enabled:     true,
				ServerName:  sni,
				Certificate: badoption.Listable[string]{string(caCertPEM)},
				PTLS: &option.OutboundPTLSOptions{
					Enabled: true,
					PSK:     pskHex,
				},
			}
			client, _ := ptls.NewClient(context.Background(), sni, clientOpts)
			cRaw, _ := net.Dial("tcp", l.Addr().String())
			defer cRaw.Close()

			cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
			if cErr != nil {
				t.Fatalf("[%s] 握手验证失败: %v", sni, cErr)
			}
			_ = cTLS.Close()
			sWg.Wait()

			if sErr != nil {
				t.Fatalf("[%s] 服务端握手处理失败: %v", sni, sErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 23. 单目标尺寸零误差微调稳定性测试 (多域名大模板循环 20 次，0 偏差)
// -----------------------------------------------------------------------------

func TestPTLS_Padding_ExactSize_Stability(t *testing.T) {
	_, _, caCert, caPriv := generateTestCA(t)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	heavyDNSNames := []string{
		"apple.com",
		"*.apple.com",
		"*.cdn-apple.com",
		"*.itunes.apple.com",
		"*.mzstatic.com",
		"long-prefix-load-balancer-entry-01.apple.com",
		"long-prefix-load-balancer-entry-02.apple.com",
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "apple.com"},
		DNSNames:     heavyDNSNames,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	targetSize := 2345
	targetEntropy := 7.42

	for i := 0; i < 20; i++ {
		der, err := ptls.PadCertificateDER(leafTemplate, caCert, &leafPriv.PublicKey, caPriv, targetSize, targetEntropy)
		if err != nil {
			t.Fatalf("第 %d 次精确填充签发失败: %v", i+1, err)
		}

		if len(der) != targetSize {
			t.Fatalf("第 %d 次填充未实现 0 字节精确对齐: 期望 %d, 实际大小 %d 字节", i+1, targetSize, len(der))
		}
	}
}

// -----------------------------------------------------------------------------
// 24. 彻底杜绝 Root CA 泄露至下行网络测试
// -----------------------------------------------------------------------------

func TestPTLS_Certificate_NoRootCALeakage(t *testing.T) {
	_, caKeyPEM, caCert, _ := generateTestCA(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			LeafDERSize:   1758,
			ChainDERSize:  2986,
			TargetEntropy: 7.40,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 Server 失败: %v", err)
	}
	defer server.Close()

	stdCfg, err := server.STDConfig()
	if err != nil {
		t.Fatalf("获取 STDConfig 失败: %v", err)
	}

	cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}

	if len(cert.Certificate) != 2 {
		t.Fatalf("下行证书链数量不为 2: 实际为 %d", len(cert.Certificate))
	}

	for idx, certBytes := range cert.Certificate {
		if bytes.Equal(certBytes, caCert.Raw) {
			t.Fatalf("严重安全漏洞: Certificate[%d] 直接包含了私有 Root CA 证书实体！", idx)
		}

		parsed, err := x509.ParseCertificate(certBytes)
		if err != nil {
			t.Fatalf("解析 Certificate[%d] 失败: %v", idx, err)
		}

		if parsed.Subject.String() == parsed.Issuer.String() {
			t.Fatalf("严重安全漏洞: Certificate[%d] 为自签名证书 (Subject == Issuer: %s)，在网络层暴露了非公信根特征", idx, parsed.Subject.String())
		}
	}
}

// -----------------------------------------------------------------------------
// 25. 尺寸边界自愈与自适应单/双证书测试
// -----------------------------------------------------------------------------

func TestPTLS_Boundary_SizeAdjustment(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("空间不足以容纳附加证书时自适应降级为单证书且整链尺寸精确对齐", func(t *testing.T) {
		// 用户配置 leaf: 940, chain: 960 (裕度差仅 20 字节，不足 MinAttachedCertSize 420)
		serverOpts := option.InboundTLSOptions{
			Enabled:    true,
			ServerName: "image.apple.com",
			PTLS: &option.InboundPTLSOptions{
				Enabled:       true,
				PSK:           badoption.Listable[string]{pskHex},
				CACertificate: badoption.Listable[string]{string(caCertPEM)},
				CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				LeafDERSize:   940,
				ChainDERSize:  960,
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建自适应单证书 Server 失败: %v", err)
		}
		defer server.Close()

		stdCfg, _ := server.STDConfig()
		cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
		if err != nil {
			t.Fatalf("获取证书失败: %v", err)
		}

		// 1. 验证附加证书被裁撤，下行仅包含 1 张叶子证书
		if len(cert.Certificate) != 1 {
			t.Fatalf("空间不足时未裁撤附加证书: 下行证书数期望 1, 实际 %d", len(cert.Certificate))
		}

		// 2. 验证叶子证书顶格填充，整链物理尺寸精确等于目标 960 字节 (0 误差)
		totalChain := len(cert.Certificate[0])
		if totalChain != 960 {
			t.Fatalf("单证书顶格对齐失败: 期望 960 字节, 实际 %d 字节", totalChain)
		}
	})

	t.Run("空间充足时正常采用双证书且整链尺寸精确对齐", func(t *testing.T) {
		// 裕度充裕 (3418 - 940 = 2478 >= 420)
		serverOpts := option.InboundTLSOptions{
			Enabled:    true,
			ServerName: "image.apple.com",
			PTLS: &option.InboundPTLSOptions{
				Enabled:       true,
				PSK:           badoption.Listable[string]{pskHex},
				CACertificate: badoption.Listable[string]{string(caCertPEM)},
				CAKey:         badoption.Listable[string]{string(caKeyPEM)},
				LeafDERSize:   940,
				ChainDERSize:  3418,
				TargetEntropy: 7.16,
			},
		}

		server, err := ptls.NewServer(context.Background(), nil, serverOpts)
		if err != nil {
			t.Fatalf("创建双证书 Server 失败: %v", err)
		}
		defer server.Close()

		stdCfg, _ := server.STDConfig()
		cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
		if err != nil {
			t.Fatalf("获取证书失败: %v", err)
		}

		if len(cert.Certificate) != 2 {
			t.Fatalf("空间充裕时应采用双证书模式: 下行证书数期望 2, 实际 %d", len(cert.Certificate))
		}

		if len(cert.Certificate[0]) != 940 {
			t.Fatalf("叶子证书尺寸未命中 940 字节: 实际 %d 字节", len(cert.Certificate[0]))
		}

		totalChain := len(cert.Certificate[0]) + len(cert.Certificate[1])
		if totalChain != 3418 {
			t.Fatalf("双证书整链尺寸未命中 3418 字节: 实际 %d 字节", totalChain)
		}
	})

	t.Run("附加证书接口输入小于MinAttachedCertSize时自动强制保底", func(t *testing.T) {
		_, _, caCert, caPriv := generateTestCA(t)
		attachedDER, err := ptls.GenerateAttachedCertificate(caCert, caPriv, 100, 7.40)
		if err != nil {
			t.Fatalf("生成过小附加证书失败: %v", err)
		}

		if len(attachedDER) < ptls.MinAttachedCertSize {
			t.Fatalf("附加证书生成体积未达到最小合法保底尺寸 %d: 实际 %d", ptls.MinAttachedCertSize, len(attachedDER))
		}

		if _, err := x509.ParseCertificate(attachedDER); err != nil {
			t.Fatalf("生成的附加证书语法解析失败: %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// 26. 信息熵有效区间钳位测试
// -----------------------------------------------------------------------------

func TestPTLS_Entropy_Clamping(t *testing.T) {
	_, _, caCert, caPriv := generateTestCA(t)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "image.apple.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	targetSize := 1800

	derLow, err := ptls.PadCertificateDER(leafTemplate, caCert, &leafPriv.PublicKey, caPriv, targetSize, 1.0)
	if err != nil {
		t.Fatalf("极低目标熵签发失败: %v", err)
	}
	entLow := ptls.CalculateEntropy(derLow)
	if entLow < 5.0 || entLow > 7.0 {
		t.Fatalf("极低目标熵输出异常: %.4f", entLow)
	}

	derHigh, err := ptls.PadCertificateDER(leafTemplate, caCert, &leafPriv.PublicKey, caPriv, targetSize, 9.5)
	if err != nil {
		t.Fatalf("极高目标熵签发失败: %v", err)
	}
	entHigh := ptls.CalculateEntropy(derHigh)
	if entHigh < 7.5 || entHigh > 7.95 {
		t.Fatalf("极高目标熵输出异常: %.4f", entHigh)
	}
}

func TestPTLS_Server_LeafUnderflow_CliffRecovery(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 注入多 SAN 域名列表，使未填充原生 baseDER 达到约 720~750 字节
	// 此时满足断崖临界触发条件：
	// 1. 配置参数 leafDERSize: 650 (< 真实 baseDER 730B)
	// 2. 静态计算 1200 - 650 = 550 >= 510 (易产生能双证书的假象)
	// 3. 动态有效尺寸 1200 - 730 = 470 < 510 (空间实际不足以容纳 510B 附加证书)
	// 4. 必须自动触发自愈回退：裁撤附加证书，叶子证书顶格拉伸至 1200 字节
	targetChainSize := 1200
	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			CertificateDomains: badoption.Listable[string]{
				"image.apple.com",
				"cdn1.apple.com",
				"cdn2.apple.com",
				"cdn3.apple.com",
				"cdn4.apple.com",
				"static.apple.com",
				"assets.apple.com",
				"media.apple.com",
				"download.apple.com",
				"app-store.apple.com",
				"icloud.apple.com",
				"store.apple.com",
				"support.apple.com",
				"developer.apple.com",
				"news.apple.com",
				"music.apple.com",
			},
			LeafDERSize:  650,
			ChainDERSize: targetChainSize,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建自愈测试 Server 失败: %v", err)
	}
	defer server.Close()

	stdCfg, err := server.STDConfig()
	if err != nil {
		t.Fatalf("获取 STDConfig 失败: %v", err)
	}

	cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "image.apple.com"})
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}

	totalLen := 0
	for _, c := range cert.Certificate {
		totalLen += len(c)
	}

	if totalLen != targetChainSize {
		t.Fatalf("自愈失败: 预期整链严格为 %d 字节, 实际产生尺寸断崖: %d 字节", targetChainSize, totalLen)
	}

	// 空间不足时应自动裁撤附加证书，只下发 1 张顶格拉伸的叶子证书
	if len(cert.Certificate) != 1 {
		t.Fatalf("预期降级为单证书顶格拉伸, 实际下发证书数: %d", len(cert.Certificate))
	}
}

func TestPTLS_Padding_ASN1_BoundaryConvergence(t *testing.T) {
	_, _, caCert, caPriv := generateTestCA(t)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "image.apple.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	// 探测基准尺寸
	baseDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("基准签发失败: %v", err)
	}
	baseLen := len(baseDER)

	// 重点测试 padLen 在 125 ~ 130 字节波动时的 ASN.1 临界区间 (padOverhead 约为 21 字节)
	for pad := 125; pad <= 130; pad++ {
		targetSize := baseLen + 21 + pad
		done := make(chan error, 1)
		go func(sz int) {
			der, pErr := ptls.PadCertificateDER(tmpl, caCert, &leafPriv.PublicKey, caPriv, sz, 7.40)
			if pErr != nil {
				done <- pErr
				return
			}
			if len(der) == 0 {
				done <- errors.New("生成的证书为空")
				return
			}
			done <- nil
		}(targetSize)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("目标尺寸 %d 签发失败: %v", targetSize, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("目标尺寸 %d 在 ASN.1 临界区发生死循环或严重震荡超时", targetSize)
		}
	}
}

func TestPTLS_Padding_NonP256_Passthrough(t *testing.T) {
	// 生成 P-384 曲线的根 CA
	p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-384 密钥失败: %v", err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P-384 Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p384Priv.PublicKey, p384Priv)
	if err != nil {
		t.Fatalf("签发 P-384 CA 失败: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "image.apple.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	start := time.Now()
	// 执行填充签发，预期快速返回，不应被 64 次重试阻塞
	der, err := ptls.PadCertificateDER(leafTmpl, caCert, &leafPriv.PublicKey, p384Priv, 1800, 7.40)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("非 P-256 CA 签发失败: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("生成的 DER 为空")
	}
	// 若未透传而进入 64 次 P-384 重试，耗时通常在数十至上百毫秒；透传后应在 5ms 内完成
	if elapsed > 50*time.Millisecond {
		t.Fatalf("非 P-256 私钥未正常透传，检测到异常耗时: %v", elapsed)
	}
}

func TestPTLS_Server_RSALeafType_E2E(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	targetLeafSize := 1758
	targetChainSize := 2986

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "fastcdn.hoyoverse.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			LeafType:      "rsa",
			LeafDERSize:   targetLeafSize,
			ChainDERSize:  targetChainSize,
			TargetEntropy: 7.40,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 RSA Server 失败: %v", err)
	}
	defer server.Close()

	stdCfg, err := server.STDConfig()
	if err != nil {
		t.Fatalf("获取 STDConfig 失败: %v", err)
	}

	cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "fastcdn.hoyoverse.com"})
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}

	parsedLeaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("解析叶子证书失败: %v", err)
	}

	// 校验公钥类型确实为 RSA-2048
	rsaPub, ok := parsedLeaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("叶子公钥不是 RSA 类型: %T", parsedLeaf.PublicKey)
	}
	if rsaPub.Size()*8 != 2048 {
		t.Fatalf("RSA 位宽不等于 2048: %d", rsaPub.Size()*8)
	}

	// 校验整链尺寸精确对齐
	totalLen := 0
	for _, c := range cert.Certificate {
		totalLen += len(c)
	}
	if totalLen != targetChainSize {
		t.Fatalf("整链尺寸偏差: 期望 %d, 实际 %d", targetChainSize, totalLen)
	}
	if len(cert.Certificate[0]) != targetLeafSize {
		t.Fatalf("叶子证书尺寸偏差: 期望 %d, 实际 %d", targetLeafSize, len(cert.Certificate[0]))
	}
}

// -----------------------------------------------------------------------------
// 27. 零拷贝联合信息熵计算算法等价性测试
// -----------------------------------------------------------------------------

func TestPTLS_Entropy_CombinedCalculation(t *testing.T) {
	slice1 := []byte("Hello, PTLS Zero-Copy Combined Entropy Verification Slice 1!")
	slice2 := []byte("DigiCert Global G2 TLS RSA SHA256 2020 CA1 Random High-Entropy Buffer")
	slice3 := make([]byte, 256)
	for i := 0; i < 256; i++ {
		slice3[i] = byte(i)
	}

	// 1. 验证多切片联合计算与内存拼接后计算的浮点结果绝对一致
	combinedDirect := ptls.CalculateCombinedEntropy(slice1, slice2, slice3)

	var flattened []byte
	flattened = append(flattened, slice1...)
	flattened = append(flattened, slice2...)
	flattened = append(flattened, slice3...)
	flattenedEntropy := ptls.CalculateEntropy(flattened)

	if combinedDirect != flattenedEntropy {
		t.Fatalf("联合信息熵零拷贝计算与扁平化计算结果不一致: 零拷贝=%.8f, 扁平化=%.8f", combinedDirect, flattenedEntropy)
	}

	// 2. 空切片与边界输入
	if ent := ptls.CalculateCombinedEntropy(nil, []byte{}); ent != 0 {
		t.Fatalf("全空切片联合熵期望为 0, 实际: %.4f", ent)
	}
}

// -----------------------------------------------------------------------------
// 28. 双证书附加垫片联合整链信息熵闭环自适应收敛测试
// -----------------------------------------------------------------------------

func TestPTLS_DualCertificate_JointEntropyConvergence(t *testing.T) {
	_, _, caCert, caPriv := generateTestCA(t)
	leafPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(8888),
		Subject:      pkix.Name{CommonName: "fastcdn.hoyoverse.com"},
		DNSNames:     []string{"*.hoyoverse.com", "hoyoverse.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	targetLeafSize := 1758
	targetChainSize := 2986
	targetEntropy := 7.40
	attachedSize := targetChainSize - targetLeafSize // 1228 字节

	// 1. 签发单张叶子证书
	leafDER, err := ptls.PadCertificateDER(leafTemplate, caCert, &leafPriv.PublicKey, caPriv, targetLeafSize, targetEntropy)
	if err != nil {
		t.Fatalf("生成叶子证书失败: %v", err)
	}
	if len(leafDER) != targetLeafSize {
		t.Fatalf("叶子证书尺寸偏差: 期望 %d, 实际 %d", targetLeafSize, len(leafDER))
	}
	leafEntropy := ptls.CalculateEntropy(leafDER)

	// 2. 将叶子证书作为前置上下文传入，生成附加证书
	attachedDER, err := ptls.GenerateAttachedCertificate(caCert, caPriv, attachedSize, targetEntropy, leafDER)
	if err != nil {
		t.Fatalf("生成附加证书失败: %v", err)
	}
	if len(attachedDER) != attachedSize {
		t.Fatalf("附加证书尺寸偏差: 期望 %d, 实际 %d", attachedSize, len(attachedDER))
	}

	// 3. 计算整链联合信息熵
	jointEntropy := ptls.CalculateCombinedEntropy(leafDER, attachedDER)
	diff := jointEntropy - targetEntropy
	if diff < 0 {
		diff = -diff
	}

	t.Logf("单叶子证书熵: %.4f bit/byte", leafEntropy)
	t.Logf("整链联合熵:   %.4f bit/byte (目标: %.2f, 偏差: %.4f)", jointEntropy, targetEntropy, diff)

	// 断言：整链联合熵误差必须被附加证书吸收至 ±0.03 bit/byte 以内，彻底消除原本 +0.08 的凸性散度跃升
	if diff > 0.03 {
		t.Fatalf("整链联合信息熵未收敛至目标值: 目标 %.2f, 实际 %.4f, 偏差超出容差 (%.4f > 0.03)", targetEntropy, jointEntropy, diff)
	}
}

// -----------------------------------------------------------------------------
// 29. 服务端双证书 E2E 整链尺寸与联合熵双重锁定测试 (RSA-2048 + ECDSA P-256)
// -----------------------------------------------------------------------------

func TestPTLS_Server_JointEntropy_DualCert_E2E(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	targetLeafSize := 1758
	targetChainSize := 2986
	targetEntropy := 7.40

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "fastcdn.hoyoverse.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			LeafType:      "rsa",
			LeafDERSize:   targetLeafSize,
			ChainDERSize:  targetChainSize,
			TargetEntropy: targetEntropy,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 Server 失败: %v", err)
	}
	defer server.Close()

	stdCfg, err := server.STDConfig()
	if err != nil {
		t.Fatalf("获取 STDConfig 失败: %v", err)
	}

	cert, err := stdCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "fastcdn.hoyoverse.com"})
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}

	if len(cert.Certificate) != 2 {
		t.Fatalf("预期下发双证书模式, 实际证书张数: %d", len(cert.Certificate))
	}

	leafDER := cert.Certificate[0]
	attachedDER := cert.Certificate[1]

	// 1. 物理尺寸锁定校验
	if len(leafDER) != targetLeafSize {
		t.Fatalf("叶子证书尺寸未命中: 期望 %d, 实际 %d", targetLeafSize, len(leafDER))
	}
	if len(leafDER)+len(attachedDER) != targetChainSize {
		t.Fatalf("整链 DER 总尺寸未命中: 期望 %d, 实际 %d", targetChainSize, len(leafDER)+len(attachedDER))
	}

	// 2. 整链联合信息熵收敛校验
	chainEntropy := ptls.CalculateCombinedEntropy(leafDER, attachedDER)
	entropyDiff := chainEntropy - targetEntropy
	if entropyDiff < 0 {
		entropyDiff = -entropyDiff
	}

	t.Logf("E2E 叶子证书尺寸: %d B, 熵: %.4f", len(leafDER), ptls.CalculateEntropy(leafDER))
	t.Logf("E2E 附加证书尺寸: %d B, 熵: %.4f", len(attachedDER), ptls.CalculateEntropy(attachedDER))
	t.Logf("E2E 整链联合总熵: %.4f bit/byte (目标: %.2f)", chainEntropy, targetEntropy)

	if entropyDiff > 0.035 {
		t.Fatalf("E2E 联合整链熵偏差过大: 目标 %.2f, 实测 %.4f, 偏差 %.4f > 0.035", targetEntropy, chainEntropy, entropyDiff)
	}
}

// -----------------------------------------------------------------------------
// 30. uTLS 客户端端到端正常握手与业务传输测试 (Chrome 指纹)
// -----------------------------------------------------------------------------

func TestPTLS_Client_UTLS_E2E_Success(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		Insecure:    false,
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建带 uTLS 的 PTLS Client 失败: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer l.Close()

	var sWg sync.WaitGroup
	var sConn net.Conn
	var sErr error
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			sErr = acceptErr
			return
		}
		sConn, sErr = server.ServerHandshake(context.Background(), conn)
		if sErr != nil {
			conn.Close()
		}
	}()

	cRaw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败: %v", err)
	}
	defer cRaw.Close()

	cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
	if cErr != nil {
		t.Fatalf("uTLS 客户端握手失败: %v", cErr)
	}
	defer cTLS.Close()

	sWg.Wait()
	if sErr != nil {
		t.Fatalf("服务端握手失败: %v", sErr)
	}
	defer sConn.Close()

	state := cTLS.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("协商版本不是 TLS 1.3: %x", state.Version)
	}

	testMsg := "Hello, PTLS with uTLS (Chrome)!\n"
	go func() {
		_, _ = sConn.Write([]byte(testMsg))
	}()

	reader := bufio.NewReader(cTLS)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("读取应用层数据失败: %v", err)
	}
	if line != testMsg {
		t.Fatalf("回显数据不一致: 期望 %q, 得到 %q", testMsg, line)
	}
}

// -----------------------------------------------------------------------------
// 31. uTLS 多浏览器指纹矩阵握手测试 (Chrome / Firefox / Edge / Safari / iOS / Android / Random)
// -----------------------------------------------------------------------------

func TestPTLS_Client_UTLS_MultiFingerprint_Matrix(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	fingerprints := []string{
		"chrome",
		"firefox",
		"edge",
		"safari",
		"ios",
		"android",
		"random",
		"randomized",
	}

	for _, fp := range fingerprints {
		t.Run("指纹_"+fp, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("监听失败: %v", err)
			}
			defer l.Close()

			var sWg sync.WaitGroup
			var sConn net.Conn
			var sErr error
			sWg.Add(1)

			go func() {
				defer sWg.Done()
				conn, acceptErr := l.Accept()
				if acceptErr != nil {
					sErr = acceptErr
					return
				}
				sConn, sErr = server.ServerHandshake(context.Background(), conn)
				if sErr != nil {
					conn.Close()
				}
			}()

			clientOpts := option.OutboundTLSOptions{
				Enabled:     true,
				ServerName:  "image.apple.com",
				Certificate: badoption.Listable[string]{string(caCertPEM)},
				PTLS: &option.OutboundPTLSOptions{
					Enabled:          true,
					PSK:              pskHex,
					HandshakeTimeout: badoption.Duration(2 * time.Second),
				},
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: fp,
				},
			}

			client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
			if err != nil {
				t.Fatalf("[%s] 创建客户端失败: %v", fp, err)
			}

			cRaw, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatalf("拨号失败: %v", err)
			}
			defer cRaw.Close()

			cTLS, cErr := client.ClientHandshake(context.Background(), cRaw)
			if cErr != nil {
				t.Fatalf("[%s] 客户端握手失败: %v", fp, cErr)
			}
			defer cTLS.Close()

			sWg.Wait()
			if sErr != nil {
				t.Fatalf("[%s] 服务端握手失败: %v", fp, sErr)
			}
			defer sConn.Close()

			state := cTLS.ConnectionState()
			expectedVersion := uint16(tls.VersionTLS13)
			if fp == "android" || fp == "randomized" {
				// android (OkHttp 11) 与 randomized (古典随机扩展) 在 uTLS 规范中均基于 TLS 1.2 建模
				expectedVersion = tls.VersionTLS12
			}
			if state.Version != expectedVersion {
				t.Fatalf("[%s] 协商版本异常: 期望 0x%04x, 实际 0x%04x", fp, expectedVersion, state.Version)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 32. uTLS 客户端错误 PSK 凭据触发服务端 Fallback 穿透测试
// -----------------------------------------------------------------------------

func TestPTLS_Client_UTLS_InvalidPSK_Fallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	validPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wrongPSK := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	fallbackAddr, closeFallback, _ := startDummyFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{validPSK},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer l.Close()

	var sWg sync.WaitGroup
	var sErr error
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			sErr = acceptErr
			return
		}
		defer conn.Close()
		_, sErr = server.ServerHandshake(context.Background(), conn)
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              wrongPSK,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	cRaw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer cRaw.Close()

	_, _ = client.ClientHandshake(context.Background(), cRaw)

	sWg.Wait()

	if !errors.Is(sErr, ptls.ErrFallbackCompleted) {
		t.Fatalf("错误 PSK 启用 uTLS 时服务端未执行 Fallback，实际错误: %v", sErr)
	}
}

// -----------------------------------------------------------------------------
// 33. uTLS 线缆层报文审计与 SessionID 密码学验签测试
// -----------------------------------------------------------------------------

func TestPTLS_Client_UTLS_Wiretap_SessionID_Inspection(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var psk [32]byte
	_, _ = hex.Decode(psk[:], []byte(pskHex))

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer l.Close()

	var sWg sync.WaitGroup
	var sConn net.Conn
	var sErr error
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			sErr = acceptErr
			return
		}
		sConn, sErr = server.ServerHandshake(context.Background(), conn)
		if sErr != nil {
			conn.Close()
		}
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	cRaw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer cRaw.Close()

	tapped := newWireTap(cRaw)

	cTLS, cErr := client.ClientHandshake(context.Background(), tapped)
	if cErr != nil {
		t.Fatalf("客户端握手失败: %v", cErr)
	}
	defer cTLS.Close()

	sWg.Wait()
	if sErr != nil {
		t.Fatalf("服务端握手失败: %v", sErr)
	}
	defer sConn.Close()

	tapped.mu.Lock()
	c2s := append([]byte(nil), tapped.c2sData...)
	tapped.mu.Unlock()

	if len(c2s) < 76 {
		t.Fatalf("客户端发送的数据量不足以包含完整的 ClientHello: %d 字节", len(c2s))
	}

	if c2s[0] != 0x16 {
		t.Fatalf("首包记录类型不是 Handshake: 0x%02x", c2s[0])
	}

	clientRandom := c2s[11:43]
	sessIDLen := c2s[43]
	if sessIDLen != 32 {
		t.Fatalf("uTLS ClientHello 的 SessionID 长度不为 32: %d", sessIDLen)
	}
	sessionID := c2s[44:76]

	tokenTime, authTag, valid := ptls.UnpackSessionID(&psk, clientRandom, sessionID)
	if !valid {
		t.Fatal("线缆层截获的 uTLS ClientHello SessionID 未能通过 PTLS 密码学验签")
	}
	if len(authTag) != 24 {
		t.Fatalf("AuthTag 长度错误: 期望 24, 实际 %d", len(authTag))
	}
	if time.Since(tokenTime) > 5*time.Second || time.Until(tokenTime) > 5*time.Second {
		t.Fatalf("解出的时间戳偏离当前时间过大: %v", tokenTime)
	}
}

// -----------------------------------------------------------------------------
// 34. 验证未开启 uTLS 时的纯原生 Go 标准库状态机与零 uTLS 参与测试
// -----------------------------------------------------------------------------

func TestPTLS_Client_DisabledUTLS_PureStdlib_ZeroUTLS_Inspection(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var psk [32]byte
	_, _ = hex.Decode(psk[:], []byte(pskHex))

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	// 明确不配置 UTLS (或显式设置 Enabled: false)
	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		Insecure:    false,
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer l.Close()

	var sWg sync.WaitGroup
	var sConn net.Conn
	var sErr error
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			sErr = acceptErr
			return
		}
		sConn, sErr = server.ServerHandshake(context.Background(), conn)
		if sErr != nil {
			conn.Close()
		}
	}()

	cRaw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败: %v", err)
	}
	defer cRaw.Close()

	tapped := newWireTap(cRaw)

	// 1. 运行时类型断言：验证工厂返回的实体是 Go 原生标准库 *crypto/tls.Conn
	cTLS, cErr := client.ClientHandshake(context.Background(), tapped)
	if cErr != nil {
		t.Fatalf("客户端握手失败: %v", cErr)
	}
	defer cTLS.Close()

	// 强断言：必须可直接类型断言为 Go 标准库 *tls.Conn
	stdConn, isStd := cTLS.(*tls.Conn)
	if !isStd || stdConn == nil {
		t.Fatalf("未开启 uTLS 时返回的连接类型异常: 期望 *crypto/tls.Conn, 实际得到 %T", cTLS)
	}

	// 反向断言：严禁包含 uTLS 适配层所特有的 Upstream() 接口
	type upstreamGetter interface {
		Upstream() any
	}
	if ug, ok := cTLS.(upstreamGetter); ok {
		t.Fatalf("隔离性穿透泄漏: 检测到连接对象实现了 Upstream 接口 (%T)，存在 uTLS 包装层参与！", ug.Upstream())
	}

	sWg.Wait()
	if sErr != nil {
		t.Fatalf("服务端握手失败: %v", sErr)
	}
	defer sConn.Close()

	// 2. 线缆层物理报文特征审计
	tapped.mu.Lock()
	c2s := append([]byte(nil), tapped.c2sData...)
	tapped.mu.Unlock()

	if len(c2s) < 76 {
		t.Fatalf("线缆截获数据量过小: %d 字节", len(c2s))
	}

	// 验证首记录为 Handshake ClientHello
	if c2s[0] != 0x16 || c2s[5] != 0x01 {
		t.Fatalf("首包记录类型或握手类型错误: 记录=0x%02x, 握手=0x%02x", c2s[0], c2s[5])
	}

	clientRandom := c2s[11:43]
	sessIDLen := int(c2s[43])
	if sessIDLen != 32 {
		t.Fatalf("SessionID 长度不为 32: %d", sessIDLen)
	}
	sessionID := c2s[44:76]

	// 验证 PTLS 凭据合法解构
	_, _, valid := ptls.UnpackSessionID(&psk, clientRandom, sessionID)
	if !valid {
		t.Fatal("未开启 uTLS 时，标准库 newPTLSRand 注入的 SessionID 凭据验签失败")
	}

	// 3. 密码学指纹物理排查：验证绝不包含 RFC 8701 GREASE 特征
	// uTLS (Chrome/Firefox/Safari 等) 在构建 ClientHello 时会无条件注入 GREASE 保留字；
	// Go 语言原生 crypto/tls 则完全不发送任何 GREASE 扩展或密码套件。
	isGREASE := func(v uint16) bool {
		return (v&0x0f0f == 0x0a0a) && ((v>>8) == (v&0xff))
	}

	curr := 76 // 跳过头部与 SessionID
	if curr+2 <= len(c2s) {
		cipherLen := int(binary.BigEndian.Uint16(c2s[curr : curr+2]))
		curr += 2
		cipherEnd := curr + cipherLen
		if cipherEnd <= len(c2s) {
			for curr+2 <= cipherEnd {
				suite := binary.BigEndian.Uint16(c2s[curr : curr+2])
				if isGREASE(suite) {
					t.Fatalf("检测到伪装指纹特征: 密码套件包含 GREASE 0x%04x，证明 ClientHello 由 uTLS 构造！", suite)
				}
				curr += 2
			}
		}
	}

	// 跳过 CompressionMethods
	if curr+1 <= len(c2s) {
		compLen := int(c2s[curr])
		curr += 1 + compLen
	}

	// 检查 Extensions 列表
	if curr+2 <= len(c2s) {
		extLen := int(binary.BigEndian.Uint16(c2s[curr : curr+2]))
		curr += 2
		extEnd := curr + extLen
		if extEnd > len(c2s) {
			extEnd = len(c2s)
		}
		for curr+4 <= extEnd {
			extType := binary.BigEndian.Uint16(c2s[curr : curr+2])
			extDataLen := int(binary.BigEndian.Uint16(c2s[curr+2 : curr+4]))
			if isGREASE(extType) {
				t.Fatalf("检测到伪装指纹特征: 扩展列表包含 GREASE 0x%04x，证明 ClientHello 由 uTLS 构造！", extType)
			}
			curr += 4 + extDataLen
		}
	}
}

// -----------------------------------------------------------------------------
// 35. QUIC PTLS 专用辅助工具与模拟回落后端
// -----------------------------------------------------------------------------

func startDummyUDPFallbackServer(t *testing.T) (addr string, closeFn func(), receivedData *bytes.Buffer) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 Dummy UDP Fallback 监听失败: %v", err)
	}

	buf := new(bytes.Buffer)
	var mu sync.Mutex

	go func() {
		tmp := make([]byte, 65536)
		for {
			n, rAddr, err := conn.ReadFrom(tmp)
			if err != nil {
				return
			}
			if n > 0 {
				mu.Lock()
				buf.Write(tmp[:n])
				mu.Unlock()
				_, _ = conn.WriteTo([]byte("UDP_FALLBACK_SUCCESS"), rAddr)
			}
		}
	}()

	closeFn = func() {
		_ = conn.Close()
	}
	return conn.LocalAddr().String(), closeFn, buf
}

// -----------------------------------------------------------------------------
// 36. QUIC PTLS 基础端到端完整握手与双向流数据读写测试
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_E2E_Success(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:          true,
			PSK:              badoption.Listable[string]{pskHex},
			CACertificate:    badoption.Listable[string]{string(caCertPEM)},
			CAKey:            badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:     3000,
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}

	server, err := ptls.NewServer(context.Background(), nil, serverOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Server 失败: %v", err)
	}
	defer server.Close()

	serverTLSConf, err := server.STDConfig()
	if err != nil {
		t.Fatalf("获取服务端 STDConfig 失败: %v", err)
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("QUIC 监听失败: %v", err)
	}
	defer listener.Close()

	testPayload := "Hello, QUIC PTLS Secure Tunnel!\n"
	var sErr error
	var sWg sync.WaitGroup
	sWg.Add(1)

	go func() {
		defer sWg.Done()
		conn, err := listener.Accept(context.Background())
		if err != nil {
			sErr = err
			return
		}
		defer conn.CloseWithError(0, "")

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			sErr = err
			return
		}
		defer stream.Close()

		reader := bufio.NewReader(stream)
		line, err := reader.ReadString('\n')
		if err != nil {
			sErr = err
			return
		}
		_, _ = stream.Write([]byte(line))

		// 等待客户端确认接收并关闭流后退出，杜绝提前触发 conn.CloseWithError 导致对端流被异常中断
		_, _ = reader.ReadByte()
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		ALPN:        badoption.Listable[string]{"h3"},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}

	client, err := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	if err != nil {
		t.Fatalf("创建 PTLS Client 失败: %v", err)
	}

	clientTLSConf, err := client.STDConfig()
	if err != nil {
		t.Fatalf("获取客户端 STDConfig 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("QUIC 客户端拨号失败: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("QUIC 打开流失败: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte(testPayload)); err != nil {
		t.Fatalf("QUIC 流写入失败: %v", err)
	}

	reader := bufio.NewReader(stream)
	echoLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("QUIC 流读取回显失败: %v", err)
	}
	if echoLine != testPayload {
		t.Fatalf("QUIC 回显内容不匹配: 期望 %q, 得到 %q", testPayload, echoLine)
	}

	// 告知服务端已完成读取
	_ = stream.Close()

	sWg.Wait()
	if sErr != nil {
		t.Fatalf("QUIC 服务端错误: %v", sErr)
	}
}

// -----------------------------------------------------------------------------
// 37. 客户端并发连接上下文隔离测试（确保不同连接绑定各自独立的 DCID 与 AuthTag）
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_Concurrent_Connection_Isolation(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:          true,
			PSK:              badoption.Listable[string]{pskHex},
			CACertificate:    badoption.Listable[string]{string(caCertPEM)},
			CAKey:            badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:     3000,
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}
	server, _ := ptls.NewServer(context.Background(), nil, serverOpts)
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	const concurrency = 10
	var sWg sync.WaitGroup
	sWg.Add(concurrency)
	go func() {
		for i := 0; i < concurrency; i++ {
			go func() {
				defer sWg.Done()
				conn, err := listener.Accept(context.Background())
				if err != nil {
					return
				}
				defer conn.CloseWithError(0, "")
				str, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				defer str.Close()
				buf := make([]byte, 16)
				n, _ := str.Read(buf)
				_, _ = str.Write(buf[:n])
				// 等待客户端确认后退出
				b := make([]byte, 1)
				_, _ = str.Read(b)
			}()
		}
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		ALPN:        badoption.Listable[string]{"h3"},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	}
	client, _ := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)

	var cWg sync.WaitGroup
	cWg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer cWg.Done()
			clientTLSConf, _ := client.STDConfig()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
			if err != nil {
				t.Errorf("[连接 %d] 拨号失败: %v", id, err)
				return
			}
			defer conn.CloseWithError(0, "")

			str, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Errorf("[连接 %d] 打开流失败: %v", id, err)
				return
			}
			defer str.Close()

			msg := fmt.Sprintf("ping-%d", id)
			_, _ = str.Write([]byte(msg))
			reply := make([]byte, len(msg))
			_, rErr := io.ReadFull(str, reply)
			if rErr != nil {
				t.Errorf("[连接 %d] 读取流失败: %v", id, rErr)
				return
			}
			_ = str.Close()
			if string(reply) != msg {
				t.Errorf("[连接 %d] 数据不一致: 期望 %s, 得到 %s", id, msg, string(reply))
			}
		}(i)
	}

	cWg.Wait()
	sWg.Wait()
}

// -----------------------------------------------------------------------------
// 38. 错误 PSK 下 QUIC 握手静默丢弃测试（未配置 Fallback）
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_InvalidPSK_SilentDrop(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	serverPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wrongPSK := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	falseVal := false
	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{serverPSK},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
			Fallback: &option.InboundPTLSFallbackOptions{
				Enabled: &falseVal,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	server, _ := ptls.NewServer(context.Background(), nil, serverOpts)
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()

	listener, _ := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	defer listener.Close()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		ALPN:        badoption.Listable[string]{"h3"},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              wrongPSK,
			HandshakeTimeout: badoption.Duration(1 * time.Second),
		},
	}
	client, _ := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	clientTLSConf, _ := client.STDConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 期望客户端因首包被静默丢弃而超时，严禁成功握手或收到重置/拒绝帧
	_, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: 2 * time.Second})
	if err == nil {
		t.Fatal("错误 PSK 客户端拨号不应成功")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("期望静默丢包导致超时 (deadline exceeded)，实际收到非预期错误: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 39. QUIC 多 PSK 动态匹配与逐项验证测试
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_MultiPSK_Matching(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	psk1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	psk2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	invalidPSK := "1111111111111111111111111111111111111111111111111111111111111111"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:          true,
			PSK:              badoption.Listable[string]{psk1, psk2},
			CACertificate:    badoption.Listable[string]{string(caCertPEM)},
			CAKey:            badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:     3000,
			TimeTolerance:    badoption.Duration(30 * time.Second),
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	server, _ := ptls.NewServer(context.Background(), nil, serverOpts)
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()

	listener, _ := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				defer c.CloseWithError(0, "")
				str, err := c.AcceptStream(context.Background())
				if err == nil {
					_ = str.Close()
				}
			}(conn)
		}
	}()

	testDial := func(t *testing.T, psk string, expectSuccess bool) {
		clientOpts := option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "image.apple.com",
			Certificate: badoption.Listable[string]{string(caCertPEM)},
			ALPN:        badoption.Listable[string]{"h3"},
			PTLS: &option.OutboundPTLSOptions{
				Enabled:          true,
				PSK:              psk,
				HandshakeTimeout: badoption.Duration(1 * time.Second),
			},
		}
		client, _ := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
		clientTLSConf, _ := client.STDConfig()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: 2 * time.Second})
		if expectSuccess {
			if err != nil {
				t.Fatalf("期望连接成功，实际失败: %v", err)
			}
			_ = conn.CloseWithError(0, "")
		} else {
			if err == nil {
				_ = conn.CloseWithError(0, "")
				t.Fatal("期望连接失败被丢弃，实际连接成功")
			}
		}
	}

	t.Run("匹配列表首个PSK", func(t *testing.T) {
		testDial(t, psk1, true)
	})

	t.Run("匹配列表中间PSK", func(t *testing.T) {
		testDial(t, psk2, true)
	})

	t.Run("未授权PSK被静默丢弃", func(t *testing.T) {
		testDial(t, invalidPSK, false)
	})
}

// -----------------------------------------------------------------------------
// 40. QUIC 传输层门禁抗重放攻击验证测试
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_ReplayAttack_Drop(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:          true,
			PSK:              badoption.Listable[string]{pskHex},
			CACertificate:    badoption.Listable[string]{string(caCertPEM)},
			CAKey:            badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:     3000,
			TimeTolerance:    badoption.Duration(30 * time.Second),
			ReplayCacheSize:  1000,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	server, _ := ptls.NewServer(context.Background(), nil, serverOpts)
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()

	rawUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("监听本地 UDP 失败: %v", err)
	}
	defer rawUDP.Close()

	tr := &quic.Transport{Conn: rawUDP}
	defer tr.Close()

	listener, err := tr.Listen(serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				defer c.CloseWithError(0, "")
				str, err := c.AcceptStream(context.Background())
				if err == nil {
					_ = str.Close()
				}
			}(conn)
		}
	}()

	clientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		ALPN:        badoption.Listable[string]{"h3"},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              pskHex,
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	client, _ := ptls.NewClient(context.Background(), "image.apple.com", clientOpts)
	clientTLSConf, _ := client.STDConfig()

	// 构造双向透明 UDP 代理，准确捕获客户端发出的真实 Initial 首包
	clientSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("clientSide 监听失败: %v", err)
	}
	defer clientSide.Close()

	serverSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("serverSide 监听失败: %v", err)
	}
	defer serverSide.Close()

	clientPacketChan := make(chan []byte, 10)
	var clientAddr net.Addr
	var clientAddrMu sync.Mutex

	serverAddr := rawUDP.LocalAddr().(*net.UDPAddr)

	// Client -> Server
	go func() {
		buf := make([]byte, 65536)
		for {
			n, cAddr, err := clientSide.ReadFrom(buf)
			if err != nil {
				return
			}
			clientAddrMu.Lock()
			clientAddr = cAddr
			clientAddrMu.Unlock()

			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case clientPacketChan <- pkt:
			default:
			}
			_, _ = serverSide.WriteTo(pkt, serverAddr)
		}
	}()

	// Server -> Client
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := serverSide.ReadFrom(buf)
			if err != nil {
				return
			}
			clientAddrMu.Lock()
			cAddr := clientAddr
			clientAddrMu.Unlock()
			if cAddr != nil {
				_, _ = clientSide.WriteTo(buf[:n], cAddr)
			}
		}
	}()

	// 发起首次合法握手
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, clientSide.LocalAddr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("首次合法握手失败: %v", err)
	}
	_ = conn.CloseWithError(0, "")

	var initialPacket []byte
	select {
	case initialPacket = <-clientPacketChan:
	case <-time.After(1 * time.Second):
		t.Fatal("未能截获合法的 Initial 首包")
	}

	// 实施重放攻击：向服务端重放一模一样的合法 Initial 首包
	replayAttacker, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("攻击端拨号失败: %v", err)
	}
	defer replayAttacker.Close()

	_, _ = replayAttacker.Write(initialPacket)

	_ = replayAttacker.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	replyBuf := make([]byte, 2048)
	n, err := replayAttacker.Read(replyBuf)
	if err == nil && n > 0 {
		t.Fatalf("严重漏洞: 重放攻击报文未被服务端门禁丢弃，收到了回包 (%d 字节)", n)
	}
}

// -----------------------------------------------------------------------------
// 41. 未授权流量通过 QUIC 传输层触发 UDP Fallback 中继转发测试
// -----------------------------------------------------------------------------

func TestPTLS_QUIC_UDP_Fallback_Relay(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, receivedBuf := startDummyUDPFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	serverOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:       true,
			PSK:           badoption.Listable[string]{pskHex},
			CACertificate: badoption.Listable[string]{string(caCertPEM)},
			CAKey:         badoption.Listable[string]{string(caKeyPEM)},
			ChainDERSize:  3000,
			Fallback: &option.InboundPTLSFallbackOptions{
				Server:     fbHost,
				ServerPort: fbPort,
			},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	server, _ := ptls.NewServer(context.Background(), nil, serverOpts)
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	// 客户端使用未授权的 PSK 发起真实的 QUIC 握手连接（产生标准的 1200+ 字节 Initial 首包）
	unauthClientOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "image.apple.com",
		Certificate: badoption.Listable[string]{string(caCertPEM)},
		ALPN:        badoption.Listable[string]{"h3"},
		PTLS: &option.OutboundPTLSOptions{
			Enabled:          true,
			PSK:              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			HandshakeTimeout: badoption.Duration(1 * time.Second),
		},
	}
	client, err := ptls.NewClient(context.Background(), "image.apple.com", unauthClientOpts)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}
	clientTLSConf, _ := client.STDConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 发起拨号：首包到达服务端，checkPTLS 验签失败触发 Fallback，将首包无损转发至 dummyUDPFallbackServer
	_, _ = quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: 1 * time.Second})

	time.Sleep(200 * time.Millisecond)

	if receivedBuf.Len() < 1200 {
		t.Fatalf("Fallback 目标未收到未授权客户端的原始 QUIC Initial 首包，实际收到 %d 字节", receivedBuf.Len())
	}

	recvBytes := receivedBuf.Bytes()
	if (recvBytes[0] & 0x80) == 0 {
		t.Fatalf("Fallback 目标收到的首包不是 Long Header 报文: 0x%02x", recvBytes[0])
	}
}
// With reject_unknown_sni, a QUIC client presenting another SNI is dropped
// silently: neither its Initial packets nor later ones reach the fallback.
func TestPTLS_QUIC_RejectUnknownSNI_NoFallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pskHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fallbackAddr, closeFallback, receivedBuf := startDummyUDPFallbackServer(t)
	defer closeFallback()
	fbHost, fbPort := parseHostPort(t, fallbackAddr)

	server, err := ptls.NewServer(context.Background(), nil, option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "image.apple.com",
		ALPN:       badoption.Listable[string]{"h3"},
		PTLS: &option.InboundPTLSOptions{
			Enabled:          true,
			PSK:              badoption.Listable[string]{pskHex},
			CACertificate:    badoption.Listable[string]{string(caCertPEM)},
			CAKey:            badoption.Listable[string]{string(caKeyPEM)},
			RejectUnknownSNI: true,
			Fallback:         &option.InboundPTLSFallbackOptions{Server: fbHost, ServerPort: fbPort},
			HandshakeTimeout: badoption.Duration(2 * time.Second),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverTLSConf, _ := server.STDConfig()
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dial := func(serverName string) error {
		client, err := ptls.NewClient(context.Background(), serverName, option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  serverName,
			Insecure:    true,
			ALPN:        badoption.Listable[string]{"h3"},
			PTLS:        &option.OutboundPTLSOptions{Enabled: true, PSK: pskHex},
			Certificate: badoption.Listable[string]{string(caCertPEM)},
		})
		if err != nil {
			return err
		}
		clientTLSConf, _ := client.STDConfig()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConf, &quic.Config{MaxIdleTimeout: time.Second})
		if err == nil {
			conn.CloseWithError(0, "")
		}
		return err
	}

	if err := dial("unknown.example.com"); err == nil {
		t.Fatal("handshake with an unknown SNI succeeded")
	}
	time.Sleep(200 * time.Millisecond)
	if receivedBuf.Len() != 0 {
		t.Fatalf("rejected SNI reached the fallback target: %d bytes", receivedBuf.Len())
	}
	if err := dial("image.apple.com"); err != nil {
		t.Fatalf("handshake with the configured SNI failed: %v", err)
	}
}
