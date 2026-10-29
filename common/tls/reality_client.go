//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	ctx        context.Context
	uClient    *UTLSClientConfig
	publicKey  []byte
	shortID    [8]byte
	keyShare   string
	mldsa65Pub *mldsa65.PublicKey
	clientVer  [3]byte
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}
	switch options.Reality.KeyShare {
	case C.RealityKeyShareDefault, C.RealityKeyShareHybrid, C.RealityKeyShareClassical:
	default:
		return nil, E.New("unknown reality key_share: ", options.Reality.KeyShare, " (expected \"hybrid\" or \"classical\")")
	}

	var mldsa65Pub *mldsa65.PublicKey
	if options.Reality.MLDSA65Verify != "" {
		keyStr := strings.TrimSpace(options.Reality.MLDSA65Verify)
		unpadded := strings.TrimRight(keyStr, "=")
		rawKey, err := base64.RawURLEncoding.DecodeString(unpadded)
		if err != nil {
			rawKey, err = base64.RawStdEncoding.DecodeString(unpadded)
			if err != nil {
				rawKey, err = hex.DecodeString(keyStr)
				if err != nil {
					return nil, E.Cause(err, "decode mldsa65 verify key")
				}
			}
		}
		if len(rawKey) != mldsa65.PublicKeySize {
			return nil, E.New("invalid mldsa65_verify: expected ", mldsa65.PublicKeySize, " bytes, got ", len(rawKey))
		}
		mldsa65Pub = new(mldsa65.PublicKey)
		err = mldsa65Pub.UnmarshalBinary(rawKey)
		if err != nil {
			return nil, E.Cause(err, "parse mldsa65 verify key")
		}
	}

	clientVer := [3]byte{26, 3, 27}
	if options.Reality.Version != "" {
		parts := strings.Split(options.Reality.Version, ".")
		if len(parts) != 3 {
			return nil, E.New("invalid reality version: expected X.Y.Z, got ", options.Reality.Version)
		}
		for i, part := range parts {
			v, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, E.Cause(err, "parse reality version[", i, "]")
			}
			clientVer[i] = byte(v)
		}
	}

	var config Config = &RealityClientConfig{
		ctx:        ctx,
		uClient:    uClient.(*UTLSClientConfig),
		publicKey:  publicKey,
		shortID:    shortID,
		keyShare:   options.Reality.KeyShare,
		mldsa65Pub: mldsa65Pub,
		clientVer:  clientVer,
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	uConn, verifier, err := e.prepareClientHello(conn)
	if err != nil {
		return nil, err
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

func (e *RealityClientConfig) prepareClientHello(conn net.Conn) (*utls.UConn, *realityVerifier, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.verificationServerName(),
		mldsa65Pub: e.mldsa65Pub,
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate

	uConn := utls.UClient(conn, uConfig, e.uClient.id)
	verifier.UConn = uConn

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	err := uConn.BuildHandshakeState()
	if err != nil {
		return nil, nil, err
	}
	switch e.keyShare {
	case C.RealityKeyShareClassical:
		for _, extension := range uConn.Extensions {
			if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
				curves.Curves = common.Filter(curves.Curves, func(curveID utls.CurveID) bool {
					return curveID != utls.X25519MLKEM768
				})
				if !common.Contains(curves.Curves, utls.X25519) {
					curves.Curves = append(curves.Curves, utls.X25519)
				}
			}
			if keyShares, isKeyShares := extension.(*utls.KeyShareExtension); isKeyShares {
				keyShares.KeyShares = common.Filter(keyShares.KeyShares, func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768
				})
				hasX25519 := false
				for _, share := range keyShares.KeyShares {
					if share.Group == utls.X25519 {
						hasX25519 = true
						break
					}
				}
				if !hasX25519 {
					keyShares.KeyShares = append(keyShares.KeyShares, utls.KeyShare{Group: utls.X25519})
				}
			}
		}
		err = uConn.BuildHandshakeState()
		if err != nil {
			return nil, nil, err
		}
	case C.RealityKeyShareHybrid:
		if !realityHelloCarriesHybridShare(uConn) {
			return nil, nil, E.New("reality key_share \"hybrid\": fingerprint ", e.uClient.id.Client, " ", e.uClient.id.Version, " carries no X25519MLKEM768 key share")
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}

	hello.SessionId[0] = e.clientVer[0]
	hello.SessionId[1] = e.clientVer[1]
	hello.SessionId[2] = e.clientVer[2]
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(nowTime.Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, nil, E.New("nil KeyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, nil, err
	}
	if authKey == nil {
		return nil, nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}
	return uConn, verifier, nil
}

func realityHelloCarriesHybridShare(uConn *utls.UConn) bool {
	for _, extension := range uConn.Extensions {
		if keyShares, isKeyShares := extension.(*utls.KeyShareExtension); isKeyShares {
			for _, share := range keyShares.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					return true
				}
			}
		}
	}
	return false
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	serverAddress := M.ParseSocksaddrHostPort(serverName, 0)
	host := serverAddress.AddrString()
	if serverAddress.IsIPv6() {
		host = "[" + host + "]"
	}
	request, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		ctx:        e.ctx,
		uClient:    e.uClient.Clone().(*UTLSClientConfig),
		publicKey:  e.publicKey,
		shortID:    e.shortID,
		keyShare:   e.keyShare,
		mldsa65Pub: e.mldsa65Pub,
		clientVer:  e.clientVer,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	mldsa65Pub *mldsa65.PublicKey
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return E.New("no certificates presented")
	}
	var serverHelloRaw []byte
	if c.UConn.HandshakeState.ServerHello != nil {
		serverHelloRaw = c.UConn.HandshakeState.ServerHello.Raw
	}
	err := verifyRealityCertificate(rawCerts[0], c.authKey, c.UConn.HandshakeState.Hello.Raw, serverHelloRaw, c.mldsa65Pub)
	if err == nil {
		c.verified = true
		return nil
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// verifyRealityCertificate 校验 REALITY 服务端临时证书：签名是以 auth key 为密钥对证书公钥的
// HMAC-SHA512；配置了 mldsa65_verify 时，证书首个扩展还须是对同一 HMAC 继续写入
// ClientHello 与 ServerHello 后摘要的 ML-DSA-65 签名（与 Xray 一致）。
func verifyRealityCertificate(rawCert []byte, authKey []byte, clientHelloRaw []byte, serverHelloRaw []byte, mldsa65Pub *mldsa65.PublicKey) error {
	certificate, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return err
	}
	publicKey, isEd25519 := certificate.PublicKey.(ed25519.PublicKey)
	if !isEd25519 {
		return E.New("reality: unexpected certificate public key type")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(publicKey)
	if !hmac.Equal(h.Sum(nil), certificate.Signature) {
		return E.New("reality: certificate signature mismatch")
	}
	if mldsa65Pub == nil {
		return nil
	}
	if len(certificate.Extensions) == 0 || len(clientHelloRaw) == 0 || len(serverHelloRaw) == 0 {
		return E.New("reality: missing ML-DSA-65 signature")
	}
	h.Write(clientHelloRaw)
	h.Write(serverHelloRaw)
	if !mldsa65.Verify(mldsa65Pub, h.Sum(nil), nil, certificate.Extensions[0].Value) {
		return E.New("reality: ML-DSA-65 signature mismatch")
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
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

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}
