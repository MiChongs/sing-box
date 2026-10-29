package ptls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
)

var _ aTLS.ServerConfig = (*ServerConfig)(nil)
var (
	_ quic.PTLSInitialGatekeeper = (*ServerConfig)(nil)
	_ quic.PTLSSNIChecker        = (*ServerConfig)(nil)
)

type quicTagRecord struct {
	remoteAddr string
	expireAt   time.Time
	count      uint8
}

type ServerConfig struct {
	access           sync.RWMutex
	tlsConfig        *tls.Config
	pskList          [][32]byte
	relayer          *FallbackRelayer
	fallbackConfig   quic.PTLSFallbackConfig
	timeTolerance    time.Duration
	replayCache      *ReplayCache
	quicTagMu        sync.Mutex
	quicTags         map[[24]byte]quicTagRecord
	rejectUnknownSNI bool
	serverNames      []string
	handshakeTimeout time.Duration
	logger           log.ContextLogger

	// 动态证书签发与轮转字段
	currentCert   atomic.Pointer[tls.Certificate]
	isDynamicCA   bool
	caCert        *x509.Certificate
	caKeyPair     *tls.Certificate
	leafPriv      crypto.Signer
	targetDomain  string
	dnsNames      []string
	validity      time.Duration
	leafDERSize   int
	chainDERSize  int
	targetEntropy float64
	checkInterval time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
}

var inboundAllowlist = map[string]struct{}{
	"enabled":                 {},
	"phantom":                 {},
	"server_name":             {},
	"server_names":            {},
	"insecure":                {},
	"alpn":                    {},
	"min_version":             {},
	"max_version":             {},
	"cipher_suites":           {},
	"curve_preferences":       {},
	"certificate":             {},
	"certificate_path":        {},
	"key":                     {},
	"key_path":                {},
	"client_authentication":   {},
	"client_certificate":      {},
	"client_certificate_path": {},
	"handshake_timeout":       {},
	"reject_unknown_sni":      {},
}

func validateInboundOptions(options option.InboundTLSOptions) error {
	v := reflect.ValueOf(options)
	t := reflect.TypeOf(options)
	for i := 0; i < v.NumField(); i++ {
		fieldVal := v.Field(i)
		if fieldVal.IsZero() {
			continue
		}
		jsonTag := t.Field(i).Tag.Get("json")
		name := strings.Split(jsonTag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, ok := inboundAllowlist[name]; !ok {
			return E.New("ptls: unsupported inbound tls option: ", name)
		}
	}
	return nil
}

func NewServer(ctx context.Context, logger log.ContextLogger, options option.InboundTLSOptions) (*ServerConfig, error) {
	opts := options.PTLS
	if opts == nil {
		return nil, errors.New("ptls: options not configured")
	}

	if err := validateInboundOptions(options); err != nil {
		return nil, err
	}

	pskList, err := opts.ParsePSKList()
	if err != nil {
		return nil, err
	}

	// 强制校验 server_name，杜绝隐式默认值
	targetDomain := options.ServerName
	if targetDomain == "" && len(options.ServerNames) > 0 {
		targetDomain = options.ServerNames[0]
	}
	if targetDomain == "" {
		return nil, errors.New("ptls: server_name cannot be empty")
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
		MinVersion:             minVersion,
		MaxVersion:             maxVersion,
		SessionTicketsDisabled: true, // 强制关闭 Session Tickets，杜绝复用跳过认证
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

	var serverNames []string
	serverNameMap := make(map[string]bool)
	if options.ServerName != "" {
		serverNameMap[options.ServerName] = true
		serverNames = append(serverNames, options.ServerName)
	}
	for _, name := range options.ServerNames {
		if name != "" && !serverNameMap[name] {
			serverNameMap[name] = true
			serverNames = append(serverNames, name)
		}
	}

	timeTolerance := opts.TimeTolerance.Build()
	if timeTolerance <= 0 {
		timeTolerance = 30 * time.Second
	}

	hsTimeout := opts.HandshakeTimeout.Build()
	if hsTimeout <= 0 {
		hsTimeout = options.HandshakeTimeout.Build()
	}
	if hsTimeout <= 0 {
		hsTimeout = 15 * time.Second
	}

	cacheSize := opts.ReplayCacheSize
	if cacheSize <= 0 {
		cacheSize = 65536
	}

	// 构造具有 QPS、QoS、硬超时的 Fallback 转发器 (默认开启)
	var relayer *FallbackRelayer
	var fallbackConfig quic.PTLSFallbackConfig
	if opts.Fallback.IsEnabled() {
		fbServer := ""
		var fbPort uint16
		var fbQPS int
		var fbQoS string
		var fbTimeout time.Duration

		if opts.Fallback != nil {
			fbServer = opts.Fallback.Server
			fbPort = opts.Fallback.ServerPort
			fbQPS = opts.Fallback.QPS
			fbQoS = opts.Fallback.QoS
			fbTimeout = opts.Fallback.Timeout.Build()
		}
		if fbServer == "" {
			fbServer = targetDomain // 默认联动 server_name
		}
		if fbPort == 0 && !strings.HasPrefix(fbServer, "unix:") && !strings.HasPrefix(fbServer, "/") {
			fbPort = 443
		}
		if fbTimeout <= 0 {
			fbTimeout = 10 * time.Second
		}
		relayer = NewFallbackRelayer(fbServer, fbPort, fbQPS, fbQoS, fbTimeout)

		fallbackConfig = quic.PTLSFallbackConfig{
			Enabled: true,
			Server:  fbServer,
			Port:    fbPort,
			QPS:     fbQPS,
			QoS:     fbQoS,
			Timeout: fbTimeout,
		}
	}

	serverConfig := &ServerConfig{
		tlsConfig:        tlsConfig,
		pskList:          pskList,
		relayer:          relayer,
		fallbackConfig:   fallbackConfig,
		timeTolerance:    timeTolerance,
		replayCache:      NewReplayCache(cacheSize, timeTolerance),
		quicTags:         make(map[[24]byte]quicTagRecord),
		rejectUnknownSNI: opts.RejectUnknownSNI || options.RejectUnknownSNI,
		serverNames:      serverNames,
		handshakeTimeout: hsTimeout,
		logger:           logger,
	}

	// 动态 CA 证书链填充签发模式 (优先级最高)
	if opts.IsDynamicCAMode() {
		caCertPEM, err := readCertPEM(opts.CACertificate, opts.CACertificatePath)
		if err != nil {
			return nil, E.Cause(err, "ptls: read ca_certificate")
		}
		caKeyPEM, err := readCertPEM(opts.CAKey, opts.CAKeyPath)
		if err != nil {
			return nil, E.Cause(err, "ptls: read ca_key")
		}

		caKeyPair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
		if err != nil {
			return nil, E.Cause(err, "ptls: parse ca key pair")
		}
		caCert, err := x509.ParseCertificate(caKeyPair.Certificate[0])
		if err != nil {
			return nil, E.Cause(err, "ptls: parse ca certificate")
		}

		var leafPriv crypto.Signer
		switch strings.ToLower(opts.LeafType) {
		case "rsa":
			leafPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		default:
			leafPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			return nil, err
		}

		validity := opts.CertificateValidity.Build()
		if validity <= 0 {
			validity = 90 * 24 * time.Hour // 默认 90 天
		}

		leafDERSize := opts.LeafDERSize
		chainDERSize := opts.ChainDERSize
		const minLeafCertSize = 600

		// 以 chainDERSize 为第一基准，仅保留基础物理底线约束，不强制附加证书的留白空间
		if chainDERSize <= 0 {
			if leafDERSize > 0 {
				chainDERSize = leafDERSize + 1024
			} else {
				chainDERSize = 3000
			}
		} else if chainDERSize < minLeafCertSize {
			chainDERSize = minLeafCertSize
		}

		if leafDERSize > 0 && leafDERSize < minLeafCertSize {
			leafDERSize = minLeafCertSize
		}

		targetEntropy := opts.TargetEntropy
		if targetEntropy <= 0 {
			targetEntropy = 7.40
		} else if targetEntropy < 5.50 {
			targetEntropy = 5.50
		} else if targetEntropy > 7.85 {
			targetEntropy = 7.85
		}

		var dnsNames []string
		dnsMap := make(map[string]bool)
		certCommonName := targetDomain

		// 1. 优先采用 CertificateDomains 签发证书 (支持泛域名，解耦 server_name)
		if len(opts.CertificateDomains) > 0 {
			for _, name := range opts.CertificateDomains {
				name = strings.TrimSpace(name)
				if name != "" && !dnsMap[name] {
					dnsMap[name] = true
					dnsNames = append(dnsNames, name)
				}
			}
			if len(dnsNames) > 0 {
				certCommonName = dnsNames[0]
			}
		}

		// 2. 回退兜底：未配置 CertificateDomains 时沿用外层 server_name / server_names
		if len(dnsNames) == 0 {
			if options.ServerName != "" {
				dnsMap[options.ServerName] = true
				dnsNames = append(dnsNames, options.ServerName)
			}
			for _, name := range options.ServerNames {
				if name != "" && !dnsMap[name] {
					dnsMap[name] = true
					dnsNames = append(dnsNames, name)
				}
			}
			if len(dnsNames) == 0 {
				dnsNames = []string{targetDomain}
			}
		}

		serverConfig.isDynamicCA = true
		serverConfig.caCert = caCert
		serverConfig.caKeyPair = &caKeyPair
		serverConfig.leafPriv = leafPriv
		serverConfig.targetDomain = certCommonName
		serverConfig.dnsNames = dnsNames
		serverConfig.validity = validity
		serverConfig.leafDERSize = leafDERSize
		serverConfig.chainDERSize = chainDERSize
		serverConfig.targetEntropy = targetEntropy

		checkInterval := validity / 6
		if checkInterval > 12*time.Hour {
			checkInterval = 12 * time.Hour
		}
		if checkInterval < 10*time.Second {
			checkInterval = 10 * time.Second
		}
		serverConfig.checkInterval = checkInterval

		initialCert, err := serverConfig.issueCertificate()
		if err != nil {
			return nil, E.Cause(err, "ptls: issue initial certificate")
		}
		serverConfig.currentCert.Store(initialCert)

		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if serverConfig.rejectUnknownSNI && len(serverConfig.serverNames) > 0 {
				if hello.ServerName == "" || !matchAnySNI(serverConfig.serverNames, hello.ServerName) {
					return nil, errors.New("ptls: unrecognized name (sni rejected)")
				}
			}
			if cert := serverConfig.currentCert.Load(); cert != nil {
				return cert, nil
			}
			return nil, errors.New("ptls: no certificate available")
		}

		serverConfig.ctx, serverConfig.cancel = context.WithCancel(context.Background())
		go serverConfig.certRenewalLoop()
	} else if len(options.Certificate) > 0 || options.CertificatePath != "" {
		// 静态证书模式 (次优先级)
		certPEM, err := readCertPEM(options.Certificate, options.CertificatePath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := readCertPEM(options.Key, options.KeyPath)
		if err != nil {
			return nil, err
		}
		keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, E.Cause(err, "ptls: parse key pair")
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if serverConfig.rejectUnknownSNI && len(serverConfig.serverNames) > 0 {
				if hello.ServerName == "" || !matchAnySNI(serverConfig.serverNames, hello.ServerName) {
					return nil, errors.New("ptls: unrecognized name (sni rejected)")
				}
			}
			return &keyPair, nil
		}
	} else {
		return nil, errors.New("ptls: either CA or certificate/key must be provided")
	}

	// 客户端认证 (mTLS)
	tlsConfig.ClientAuth = tls.ClientAuthType(options.ClientAuthentication)
	if len(options.ClientCertificate) > 0 || len(options.ClientCertificatePath) > 0 {
		clientCAPool := x509.NewCertPool()
		if len(options.ClientCertificate) > 0 {
			data := []byte(strings.Join(options.ClientCertificate, "\n"))
			if !clientCAPool.AppendCertsFromPEM(data) {
				return nil, errors.New("ptls: failed to append client certificate strings")
			}
		}
		for _, path := range options.ClientCertificatePath {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, E.Cause(err, "ptls: read client certificate from ", path)
			}
			if !clientCAPool.AppendCertsFromPEM(data) {
				return nil, E.New("ptls: failed to append client certificate file: ", path)
			}
		}
		tlsConfig.ClientCAs = clientCAPool
	}

	return serverConfig, nil
}

func (s *ServerConfig) issueCertificate() (*tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: s.targetDomain},
		DNSNames:     s.dnsNames,
		NotBefore:    time.Now().Add(-1 * time.Hour), // 回拨 1 小时防客户端时钟轻微偏移
		NotAfter:     time.Now().Add(s.validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 先生成未填充的基准叶子证书 (既用于探测实际原生体积，也可在无需填充时直接复用，消除重复签名)
	baseDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, s.caCert, s.leafPriv.Public(), s.caKeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}

	// 计算叶子证书的实际有效尺寸占用 (不可低于原生未填充物理下限)
	effectiveLeafSize := len(baseDER)
	if s.leafDERSize > effectiveLeafSize {
		effectiveLeafSize = s.leafDERSize
	}

	// 预判断是否满足双证书填充要求 (附加证书至少需要 MinAttachedCertSize 物理字节)
	isDualCert := s.chainDERSize-effectiveLeafSize >= MinAttachedCertSize

	var leafDER []byte
	if isDualCert {
		if s.leafDERSize > len(baseDER) {
			leafDER, err = PadCertificateDER(leafTemplate, s.caCert, s.leafPriv.Public(), s.caKeyPair.PrivateKey, s.leafDERSize, s.targetEntropy)
			if err != nil {
				return nil, err
			}
		} else {
			leafDER = baseDER // 直接复用已签发的基准证书，消除重复密码学开销
		}
	} else {
		// 空间不足以容纳合规附加证书，裁撤附加证书，叶子证书顶格填充至目标整链尺寸
		if s.chainDERSize > len(baseDER) {
			leafDER, err = PadCertificateDER(leafTemplate, s.caCert, s.leafPriv.Public(), s.caKeyPair.PrivateKey, s.chainDERSize, s.targetEntropy)
			if err != nil {
				return nil, err
			}
		} else {
			leafDER = baseDER
		}
	}

	certs := [][]byte{leafDER}
	if isDualCert {
		attachedSize := s.chainDERSize - len(leafDER)
		if attachedSize >= MinAttachedCertSize {
			attachedDER, err := GenerateAttachedCertificate(s.caCert, s.caKeyPair.PrivateKey, attachedSize, s.targetEntropy, leafDER)
			if err != nil {
				return nil, err
			}
			certs = append(certs, attachedDER)
		} else {
			// 防御性兜底：若由于未知极端边界导致剩余空间不足以容纳附加证书，
			// 回退将叶子证书顶格拉伸至目标整链尺寸，确保整链尺寸不产生断崖失真
			leafDER, err = PadCertificateDER(leafTemplate, s.caCert, s.leafPriv.Public(), s.caKeyPair.PrivateKey, s.chainDERSize, s.targetEntropy)
			if err != nil {
				return nil, err
			}
			certs = [][]byte{leafDER}
		}
	}

	return &tls.Certificate{
		Certificate: certs,
		PrivateKey:  s.leafPriv,
	}, nil
}

func (s *ServerConfig) certRenewalLoop() {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkAndRenewCertificate()
		}
	}
}

func (s *ServerConfig) checkAndRenewCertificate() {
	cert := s.currentCert.Load()
	if cert == nil || len(cert.Certificate) == 0 {
		if newCert, err := s.issueCertificate(); err == nil {
			s.currentCert.Store(newCert)
		}
		return
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf != nil {
		if time.Until(leaf.NotAfter) <= s.validity/3 {
			if newCert, err := s.issueCertificate(); err == nil {
				s.currentCert.Store(newCert)
			}
		}
	}
}

func (s *ServerConfig) Server(conn net.Conn) (aTLS.Conn, error) {
	return s.ServerHandshake(context.Background(), conn)
}

func (s *ServerConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return nil, errors.New("ptls: server config does not support client handshake")
}

func (s *ServerConfig) STDConfig() (*tls.Config, error) {
	s.access.RLock()
	defer s.access.RUnlock()
	cloned := s.tlsConfig.Clone()
	cloned.Rand = s
	return cloned, nil
}

func (s *ServerConfig) Clone() aTLS.Config {
	s.access.RLock()
	defer s.access.RUnlock()
	cloned := &ServerConfig{
		tlsConfig:        s.tlsConfig.Clone(),
		pskList:          append([][32]byte(nil), s.pskList...),
		relayer:          s.relayer,
		fallbackConfig:   s.fallbackConfig,
		timeTolerance:    s.timeTolerance,
		replayCache:      s.replayCache,
		quicTags:         make(map[[24]byte]quicTagRecord),
		rejectUnknownSNI: s.rejectUnknownSNI,
		serverNames:      append([]string(nil), s.serverNames...),
		handshakeTimeout: s.handshakeTimeout,
		logger:           s.logger,
		isDynamicCA:      s.isDynamicCA,
		caCert:           s.caCert,
		caKeyPair:        s.caKeyPair,
		leafPriv:         s.leafPriv,
		targetDomain:     s.targetDomain,
		dnsNames:         append([]string(nil), s.dnsNames...),
		validity:         s.validity,
		leafDERSize:      s.leafDERSize,
		chainDERSize:     s.chainDERSize,
		targetEntropy:    s.targetEntropy,
		checkInterval:    s.checkInterval,
		ctx:              s.ctx,
		cancel:           s.cancel,
	}
	if cert := s.currentCert.Load(); cert != nil {
		cloned.currentCert.Store(cert)
	}
	if s.isDynamicCA {
		cloned.tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cloned.rejectUnknownSNI && len(cloned.serverNames) > 0 {
				if hello.ServerName == "" || !matchAnySNI(cloned.serverNames, hello.ServerName) {
					return nil, errors.New("ptls: unrecognized name (sni rejected)")
				}
			}
			if c := cloned.currentCert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("ptls: no certificate available")
		}
	} else if len(cloned.tlsConfig.Certificates) > 0 {
		cert := &cloned.tlsConfig.Certificates[0]
		cloned.tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cloned.rejectUnknownSNI && len(cloned.serverNames) > 0 {
				if hello.ServerName == "" || !matchAnySNI(cloned.serverNames, hello.ServerName) {
					return nil, errors.New("ptls: unrecognized name (sni rejected)")
				}
			}
			return cert, nil
		}
	}
	return cloned
}

func (s *ServerConfig) ServerHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	s.access.RLock()
	relayer := s.relayer
	tolerance := s.timeTolerance
	hsTimeout := s.handshakeTimeout
	rejectSNI := s.rejectUnknownSNI
	sniList := s.serverNames
	clonedTLS := s.tlsConfig.Clone()
	pskList := s.pskList
	s.access.RUnlock()

	fallback := func(initial []byte) (aTLS.Conn, error) {
		if relayer != nil {
			return nil, relayer.Relay(ctx, conn, initial)
		}
		_ = conn.Close()
		return nil, errors.New("ptls: handshake verification failed and fallback is disabled")
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	recordHeader := make([]byte, 5)
	n, err := io.ReadFull(conn, recordHeader)
	if err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return fallback(recordHeader[:n])
	}

	if recordHeader[0] != 0x16 {
		_ = conn.SetReadDeadline(time.Time{})
		return fallback(recordHeader[:n])
	}

	recLen := binary.BigEndian.Uint16(recordHeader[3:5])
	if recLen < 71 {
		extra := make([]byte, recLen)
		n, _ := io.ReadFull(conn, extra)
		_ = conn.SetReadDeadline(time.Time{})
		return fallback(append(recordHeader, extra[:n]...))
	}

	payload := make([]byte, recLen)
	n, err = io.ReadFull(conn, payload)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fallback(append(recordHeader, payload[:n]...))
	}

	fullHead := append(recordHeader, payload...)

	// SNI 门禁检查：若开启 reject_unknown_sni 且域名不匹配准入列表，直接断开连接且不进入 Fallback
	if rejectSNI && payload[0] == 0x01 {
		sni := extractSNI(payload)
		if len(sniList) > 0 && (sni == "" || !matchAnySNI(sniList, sni)) {
			_ = conn.Close()
			return nil, errors.New("ptls: unrecognized name (sni rejected)")
		}
	}

	if payload[0] != 0x01 || fullHead[43] != 32 {
		return fallback(fullHead)
	}

	clientRandom := fullHead[11:43]
	sessionID := fullHead[44:76]

	var (
		matchedTime time.Time
		matchedTag  []byte
		matched     bool
	)
	for i := range pskList {
		clientTime, authTag, valid := UnpackSessionID(&pskList[i], clientRandom, sessionID)
		if valid {
			matchedTime = clientTime
			matchedTag = authTag
			matched = true
			break
		}
	}
	if !matched {
		return fallback(fullHead)
	}

	now := time.Now()
	diff := now.Sub(matchedTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		return fallback(fullHead)
	}

	if !s.replayCache.CheckAndAdd(matchedTag, now) {
		return fallback(fullHead)
	}

	syntheticConn := &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(fullHead), conn),
	}

	if hsTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hsTimeout)
		defer cancel()
	}

	tlsServer := tls.Server(syntheticConn, clonedTLS)
	if err := tlsServer.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return tlsServer, nil
}

func matchSNI(pattern, sni string) bool {
	pattern = strings.TrimSuffix(pattern, ".")
	sni = strings.TrimSuffix(sni, ".")
	if strings.EqualFold(pattern, sni) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".example.com"
		if len(sni) > len(suffix) && strings.EqualFold(sni[len(sni)-len(suffix):], suffix) {
			prefix := sni[:len(sni)-len(suffix)]
			return !strings.Contains(prefix, ".")
		}
	}
	return false
}

func matchAnySNI(patterns []string, sni string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if matchSNI(pattern, sni) {
			return true
		}
	}
	return false
}

func extractSNI(payload []byte) string {
	if len(payload) < 44 || payload[0] != 0x01 {
		return ""
	}
	offset := 38
	if offset >= len(payload) {
		return ""
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(payload) {
		return ""
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen
	if offset+2 > len(payload) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(payload) {
		extensionsLen = len(payload) - offset
	}
	extensionsEnd := offset + extensionsLen

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extensionsEnd {
			break
		}
		if extType == 0 { // server_name (SNI)
			sniData := payload[offset : offset+extLen]
			if len(sniData) < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(sniData[:2]))
			sniOffset := 2
			for sniOffset+3 <= 2+listLen && sniOffset+3 <= len(sniData) {
				nameType := sniData[sniOffset]
				nameLen := int(binary.BigEndian.Uint16(sniData[sniOffset+1 : sniOffset+3]))
				sniOffset += 3
				if nameType == 0 && sniOffset+nameLen <= len(sniData) {
					return string(sniData[sniOffset : sniOffset+nameLen])
				}
				sniOffset += nameLen
			}
			return ""
		}
		offset += extLen
	}
	return ""
}

func (s *ServerConfig) ServerName() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.tlsConfig.ServerName
}

func (s *ServerConfig) SetServerName(serverName string) {
	s.access.Lock()
	defer s.access.Unlock()
	s.tlsConfig.ServerName = serverName
}

func (s *ServerConfig) NextProtos() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.tlsConfig.NextProtos
}

func (s *ServerConfig) SetNextProtos(nextProto []string) {
	s.access.Lock()
	defer s.access.Unlock()
	s.tlsConfig.NextProtos = nextProto
}

func (s *ServerConfig) HandshakeTimeout() time.Duration {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.handshakeTimeout
}

func (s *ServerConfig) SetHandshakeTimeout(timeout time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	s.handshakeTimeout = timeout
}

func (s *ServerConfig) Start() error {
	return nil
}

func (s *ServerConfig) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// Read 实现 io.Reader 接口以合法赋值给 tls.Config.Rand
func (s *ServerConfig) Read(p []byte) (int, error) {
	return rand.Reader.Read(p)
}

// GetFallbackConfig 暴露声明式回落配置给 quic-go 传输层
func (s *ServerConfig) GetFallbackConfig() quic.PTLSFallbackConfig {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.fallbackConfig
}

// CheckSNI 供 quic-go 在 Initial 阶段静默丢弃未知 SNI（不进入回落）。
// 首个 Initial 包中取不到 SNI 时放行，由 TLS 握手阶段的 reject_unknown_sni 处理。
func (s *ServerConfig) CheckSNI(serverName string) bool {
	if serverName == "" {
		return true
	}
	s.access.RLock()
	rejectUnknownSNI := s.rejectUnknownSNI
	serverNames := s.serverNames
	s.access.RUnlock()
	if !rejectUnknownSNI || len(serverNames) == 0 {
		return true
	}
	return matchAnySNI(serverNames, serverName)
}

// VerifyInitial 执行纯计算型无状态首包验签
func (s *ServerConfig) VerifyInitial(dcid []byte, clientHelloRandom []byte, rawPacket []byte, remoteAddr net.Addr) (bool, error) {
	if len(clientHelloRandom) != 32 || remoteAddr == nil {
		return false, nil
	}

	s.access.RLock()
	pskList := s.pskList
	tolerance := s.timeTolerance
	replayCache := s.replayCache
	s.access.RUnlock()

	var (
		matchedTime time.Time
		matchedTag  []byte
		matched     bool
	)
	for i := range pskList {
		clientTime, authTag, valid := UnpackSessionID(&pskList[i], dcid, clientHelloRandom)
		if valid {
			matchedTime = clientTime
			matchedTag = authTag
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	now := time.Now()
	diff := now.Sub(matchedTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		return false, nil
	}

	var tagKey [24]byte
	copy(tagKey[:], matchedTag)
	addrStr := remoteAddr.String()

	s.quicTagMu.Lock()
	if len(s.quicTags) > 2048 {
		for k, v := range s.quicTags {
			if now.After(v.expireAt) {
				delete(s.quicTags, k)
			}
		}
	}

	rec, exists := s.quicTags[tagKey]
	if exists {
		if now.After(rec.expireAt) || rec.remoteAddr != addrStr || rec.count >= 3 {
			s.quicTagMu.Unlock()
			return false, nil
		}
		rec.count++
		s.quicTags[tagKey] = rec
		s.quicTagMu.Unlock()
		return true, nil
	}

	if replayCache != nil && !replayCache.CheckAndAdd(matchedTag, now) {
		s.quicTagMu.Unlock()
		return false, nil
	}

	s.quicTags[tagKey] = quicTagRecord{
		remoteAddr: addrStr,
		expireAt:   now.Add(tolerance),
		count:      1,
	}
	s.quicTagMu.Unlock()

	return true, nil
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *bufferedConn) Upstream() any {
	return c.Conn
}