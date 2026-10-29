package ptls

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
)

var _ aTLS.Config = (*ClientConfig)(nil)

type quicDCIDEntry struct {
	dcid      []byte
	createdAt time.Time
}

// quicClientRand 专为 QUIC 客户端设计的确定性随机数注入器
type quicClientRand struct {
	psk     [32]byte
	mu      sync.Mutex
	entries []quicDCIDEntry
}

func (r *quicClientRand) SetDestinationConnectionID(dcid []byte) {
	if len(dcid) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	valid := r.entries[:0]
	for _, entry := range r.entries {
		if now.Sub(entry.createdAt) <= 10*time.Second {
			valid = append(valid, entry)
		}
	}
	r.entries = append(valid, quicDCIDEntry{
		dcid:      append([]byte(nil), dcid...),
		createdAt: now,
	})
}

func (r *quicClientRand) Read(p []byte) (int, error) {
	if len(p) == 32 {
		r.mu.Lock()
		now := time.Now()
		for len(r.entries) > 0 {
			entry := r.entries[0]
			r.entries = r.entries[1:]
			if now.Sub(entry.createdAt) <= 10*time.Second {
				r.mu.Unlock()
				sessID := PackSessionID(&r.psk, entry.dcid, now)
				copy(p, sessID[:])
				return 32, nil
			}
		}
		r.mu.Unlock()
	}
	return crand.Reader.Read(p)
}

// UTLSClientConfig 封装独立的 uTLS 引擎专属状态
type UTLSClientConfig struct {
	config *utls.Config
	id     utls.ClientHelloID
}

func (u *UTLSClientConfig) Clone() *UTLSClientConfig {
	if u == nil {
		return nil
	}
	return &UTLSClientConfig{
		config: u.config.Clone(),
		id:     u.id,
	}
}

// ClientConfig 为 PTLS 统一出站配置实体
type ClientConfig struct {
	access           sync.RWMutex
	tlsConfig        *tls.Config
	psk              [32]byte
	serverName       string
	handshakeTimeout time.Duration

	// utls 为独立的子引擎配置，未启用时为 nil
	utls *UTLSClientConfig
}

var outboundAllowlist = map[string]struct{}{
	"enabled":                 {},
	"phantom":                 {},
	"server_name":             {},
	"certificate_server_name": {},
	"disable_sni":             {},
	"insecure":                {},
	"alpn":                    {},
	"min_version":             {},
	"max_version":             {},
	"cipher_suites":           {},
	"curve_preferences":       {},
	"certificate":             {},
	"certificate_path":        {},
	"client_certificate":      {},
	"client_certificate_path": {},
	"client_key":              {},
	"client_key_path":         {},
	"handshake_timeout":       {},
	"utls":                    {},
}

func validateOutboundOptions(options option.OutboundTLSOptions) error {
	if options.Engine != "" && options.Engine != C.TLSEngineGo {
		return E.New("ptls: unsupported tls option: engine=", options.Engine)
	}

	v := reflect.ValueOf(options)
	t := reflect.TypeOf(options)
	for i := 0; i < v.NumField(); i++ {
		fieldVal := v.Field(i)
		if fieldVal.IsZero() {
			continue
		}
		jsonTag := t.Field(i).Tag.Get("json")
		name := strings.Split(jsonTag, ",")[0]
		if name == "" || name == "-" || name == "engine" {
			continue
		}
		if _, ok := outboundAllowlist[name]; !ok {
			return E.New("ptls: unsupported outbound tls option: ", name)
		}
	}
	return nil
}

func NewClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions) (*ClientConfig, error) {
	opts := options.PTLS
	if opts == nil {
		return nil, errors.New("ptls: options not configured")
	}

	if err := validateOutboundOptions(options); err != nil {
		return nil, err
	}

	psk, err := opts.ParsePSK()
	if err != nil {
		return nil, err
	}

	serverName := options.ServerName
	if serverName == "" {
		serverName = serverAddress
	}

	minVersion := uint16(tls.VersionTLS12)
	if options.MinVersion != "" {
		parsed, err := parseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, err
		}
		minVersion = parsed
	}

	maxVersion := uint16(tls.VersionTLS13)
	if options.MaxVersion != "" {
		parsed, err := parseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, err
		}
		maxVersion = parsed
	}

	tlsConfig := &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     options.Insecure,
		MinVersion:             minVersion,
		MaxVersion:             maxVersion,
		SessionTicketsDisabled: true, // 强制关闭 Session Tickets，杜绝复用跳过认证
		ClientSessionCache:     nil,  // 显式禁用客户端会话缓存
	}

	if options.DisableSNI {
		tlsConfig.ServerName = ""
	}

	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}

	cipherSuites, err := parseCipherSuites([]string(options.CipherSuites))
	if err != nil {
		return nil, err
	}
	if len(cipherSuites) > 0 {
		tlsConfig.CipherSuites = cipherSuites
	}

	if len(options.CurvePreferences) > 0 {
		curves := make([]tls.CurveID, len(options.CurvePreferences))
		for i, curve := range options.CurvePreferences {
			curves[i] = tls.CurveID(curve)
		}
		tlsConfig.CurvePreferences = curves
	}

	// 根证书池配置
	if len(options.Certificate) > 0 || options.CertificatePath != "" {
		certPool := x509.NewCertPool()
		data, err := readCertPEM(options.Certificate, options.CertificatePath)
		if err != nil {
			return nil, err
		}
		if !certPool.AppendCertsFromPEM(data) {
			return nil, E.New("ptls: failed to append root certificates")
		}
		tlsConfig.RootCAs = certPool
	}

	// mTLS 客户端证书与私钥
	if (len(options.ClientCertificate) > 0 || options.ClientCertificatePath != "") &&
		(len(options.ClientKey) > 0 || options.ClientKeyPath != "") {
		certData, err := readCertPEM(options.ClientCertificate, options.ClientCertificatePath)
		if err != nil {
			return nil, err
		}
		keyData, err := readCertPEM(options.ClientKey, options.ClientKeyPath)
		if err != nil {
			return nil, err
		}
		keyPair, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, E.Cause(err, "ptls: parse client key pair")
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
	}

	timeout := opts.HandshakeTimeout.Build()
	if timeout <= 0 {
		timeout = options.HandshakeTimeout.Build()
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// 独立初始化 uTLS 状态机
	var utlsClient *UTLSClientConfig
	if options.UTLS != nil && options.UTLS.Enabled {
		id, err := parseUTLSFingerprint(options.UTLS.Fingerprint)
		if err != nil {
			return nil, err
		}

		uConfig := &utls.Config{
			ServerName:             tlsConfig.ServerName,
			InsecureSkipVerify:     tlsConfig.InsecureSkipVerify,
			MinVersion:             tlsConfig.MinVersion,
			MaxVersion:             tlsConfig.MaxVersion,
			SessionTicketsDisabled: true,
			ClientSessionCache:     nil,
			NextProtos:             tlsConfig.NextProtos,
			CipherSuites:           tlsConfig.CipherSuites,
			RootCAs:                tlsConfig.RootCAs,
		}
		if len(tlsConfig.CurvePreferences) > 0 {
			uConfig.CurvePreferences = make([]utls.CurveID, len(tlsConfig.CurvePreferences))
			for i, curve := range tlsConfig.CurvePreferences {
				uConfig.CurvePreferences[i] = utls.CurveID(curve)
			}
		}
		if len(tlsConfig.Certificates) > 0 {
			uConfig.Certificates = make([]utls.Certificate, len(tlsConfig.Certificates))
			for i, cert := range tlsConfig.Certificates {
				uConfig.Certificates[i] = utls.Certificate{
					Certificate: cert.Certificate,
					PrivateKey:  cert.PrivateKey,
					Leaf:        cert.Leaf,
				}
			}
		}

		utlsClient = &UTLSClientConfig{
			config: uConfig,
			id:     id,
		}
	}

	return &ClientConfig{
		tlsConfig:        tlsConfig,
		psk:              psk,
		serverName:       serverName,
		handshakeTimeout: timeout,
		utls:             utlsClient,
	}, nil
}

func (c *ClientConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	c.access.RLock()
	utlsClient := c.utls.Clone()
	cloned := c.tlsConfig.Clone()
	psk := c.psk
	c.access.RUnlock()

	// 优先判定是否激活独立的 uTLS 客户端分支
	if utlsClient != nil {
		uConn := utls.UClient(conn, utlsClient.config, utlsClient.id)
		return &utlsClientConn{
			utlsConnWrapper: utlsConnWrapper{uConn},
			uConfig:         utlsClient.config,
			psk:             psk,
		}, nil
	}

	cloned.Rand = newPTLSRand(psk)
	return tls.Client(conn, cloned), nil
}

func (c *ClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	c.access.RLock()
	timeout := c.handshakeTimeout
	c.access.RUnlock()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	tlsConn, err := c.Client(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (c *ClientConfig) STDConfig() (*tls.Config, error) {
	c.access.RLock()
	defer c.access.RUnlock()
	cloned := c.tlsConfig.Clone()
	cloned.Rand = &quicClientRand{psk: c.psk}
	return cloned, nil
}

func (c *ClientConfig) Clone() aTLS.Config {
	c.access.RLock()
	defer c.access.RUnlock()
	return &ClientConfig{
		tlsConfig:        c.tlsConfig.Clone(),
		psk:              c.psk,
		serverName:       c.serverName,
		handshakeTimeout: c.handshakeTimeout,
		utls:             c.utls.Clone(),
	}
}

func (c *ClientConfig) ServerName() string {
	c.access.RLock()
	defer c.access.RUnlock()
	return c.serverName
}

func (c *ClientConfig) SetServerName(serverName string) {
	c.access.Lock()
	defer c.access.Unlock()
	c.serverName = serverName
	c.tlsConfig.ServerName = serverName
	if c.utls != nil && c.utls.config != nil {
		c.utls.config.ServerName = serverName
	}
}

func (c *ClientConfig) NextProtos() []string {
	c.access.RLock()
	defer c.access.RUnlock()
	return c.tlsConfig.NextProtos
}

func (c *ClientConfig) SetNextProtos(nextProto []string) {
	c.access.Lock()
	defer c.access.Unlock()
	c.tlsConfig.NextProtos = nextProto
	if c.utls != nil && c.utls.config != nil {
		c.utls.config.NextProtos = nextProto
	}
}

func (c *ClientConfig) HandshakeTimeout() time.Duration {
	c.access.RLock()
	defer c.access.RUnlock()
	return c.handshakeTimeout
}

func (c *ClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.access.Lock()
	defer c.access.Unlock()
	c.handshakeTimeout = timeout
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

func (c *utlsConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *utlsConnWrapper) WriterReplaceable() bool {
	return true
}

type utlsClientConn struct {
	utlsConnWrapper
	uConfig *utls.Config
	psk     [32]byte
}

func (c *utlsClientConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *utlsClientConn) HandshakeContext(ctx context.Context) error {
	if len(c.uConfig.NextProtos) > 0 {
		for _, extension := range c.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = c.uConfig.NextProtos
				break
			}
		}
	}

	if err := c.BuildHandshakeState(); err != nil {
		return err
	}

	hello := c.HandshakeState.Hello
	if len(hello.SessionId) != 32 {
		hello.SessionId = make([]byte, 32)
	}

	sessID := PackSessionID(&c.psk, hello.Random, time.Now())
	copy(hello.SessionId, sessID[:])
	if len(hello.Raw) >= 39+32 {
		copy(hello.Raw[39:39+32], sessID[:])
	}

	return c.UConn.HandshakeContext(ctx)
}

func parseUTLSFingerprint(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		fallthrough
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random":
		modern := []utls.ClientHelloID{
			utls.HelloChrome_Auto,
			utls.HelloFirefox_Auto,
			utls.HelloEdge_Auto,
			utls.HelloSafari_Auto,
			utls.HelloIOS_Auto,
		}
		return modern[rand.Intn(len(modern))], nil
	case "randomized":
		return utls.HelloRandomized, nil
	default:
		return utls.ClientHelloID{}, E.New("ptls: unknown utls fingerprint: ", name)
	}
}

func parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.0", "1.0.0", "tls1.0", "TLS1.0":
		return tls.VersionTLS10, nil
	case "1.1", "1.1.0", "tls1.1", "TLS1.1":
		return tls.VersionTLS11, nil
	case "1.2", "1.2.0", "tls1.2", "TLS1.2":
		return tls.VersionTLS12, nil
	case "1.3", "1.3.0", "tls1.3", "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, E.New("ptls: unknown tls version: ", version)
	}
}

func parseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	var suiteIDs []uint16
	for _, name := range names {
		var found bool
		cleanName := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
		for _, s := range allSuites {
			sNameUpper := strings.ToUpper(s.Name)
			if sNameUpper == cleanName || strings.TrimPrefix(sNameUpper, "TLS_") == strings.TrimPrefix(cleanName, "TLS_") {
				suiteIDs = append(suiteIDs, s.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, E.New("ptls: unknown cipher suite: ", name)
		}
	}
	return suiteIDs, nil
}

func readCertPEM(list []string, path string) ([]byte, error) {
	if len(list) > 0 {
		return []byte(strings.Join(list, "\n")), nil
	}
	if path != "" {
		return os.ReadFile(path)
	}
	return nil, errors.New("ptls: no certificate data")
}