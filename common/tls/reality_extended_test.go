//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
)

func generateTestX25519Keys(t *testing.T) (pubKeyStr string, privKeyStr string) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate X25519 key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(privKey.Bytes())
}

// 1. 测试 Version 伪装解析与 ClientHello SessionID 明文注入并校验解密结果
func TestRealityClient_VersionSpoofing(t *testing.T) {
	pubKey, _ := generateTestX25519Keys(t)
	ctx := context.Background()

	opts := option.OutboundTLSOptions{
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		Reality: &option.OutboundRealityOptions{
			PublicKey: pubKey,
			ShortID:   "0123456789abcdef",
			Version:   "28.5.12",
		},
	}

	clientCfg, err := newRealityClient(ctx, nil, "example.com:443", opts, true)
	if err != nil {
		t.Fatalf("newRealityClient failed: %v", err)
	}

	cfg, ok := clientCfg.(*RealityClientConfig)
	if !ok {
		t.Fatalf("expected *RealityClientConfig")
	}

	if cfg.clientVer != [3]byte{28, 5, 12} {
		t.Fatalf("expected clientVer [28 5 12], got %v", cfg.clientVer)
	}

	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	uConn, verifier, err := cfg.prepareClientHello(conn1)
	if err != nil {
		t.Fatalf("prepareClientHello failed: %v", err)
	}

	hello := uConn.HandshakeState.Hello

	aesBlock, err := aes.NewCipher(verifier.authKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	aesGcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	rawAAD := make([]byte, len(hello.Raw))
	copy(rawAAD, hello.Raw)
	for i := 39; i < 71; i++ {
		rawAAD[i] = 0
	}

	plaintext, err := aesGcm.Open(nil, hello.Random[20:], hello.SessionId, rawAAD)
	if err != nil {
		t.Fatalf("decrypt SessionId failed: %v", err)
	}

	if plaintext[0] != 28 || plaintext[1] != 5 || plaintext[2] != 12 {
		t.Errorf("expected decrypted SessionId[:3] == [28 5 12], got %v", plaintext[:3])
	}
	if plaintext[3] != 0 {
		t.Errorf("expected decrypted SessionId[3] == 0, got %d", plaintext[3])
	}
}

// 2. 测试 KeyShare 控制分支 (classical / hybrid / 非法枚举)
func TestRealityClient_KeyShare(t *testing.T) {
	pubKey, _ := generateTestX25519Keys(t)
	ctx := context.Background()

	// 2.1 Classical 模式：确保剥离 X25519MLKEM768 并注入 X25519
	optsClassical := option.OutboundTLSOptions{
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		Reality: &option.OutboundRealityOptions{
			PublicKey: pubKey,
			ShortID:   "0123456789abcdef",
			KeyShare:  C.RealityKeyShareClassical,
		},
	}

	clientCfgClassical, err := newRealityClient(ctx, nil, "example.com:443", optsClassical, true)
	if err != nil {
		t.Fatalf("newRealityClient classical failed: %v", err)
	}

	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	uConn, _, err := clientCfgClassical.(*RealityClientConfig).prepareClientHello(conn1)
	if err != nil {
		t.Fatalf("prepareClientHello failed: %v", err)
	}

	for _, ext := range uConn.Extensions {
		if curves, ok := ext.(*utls.SupportedCurvesExtension); ok {
			for _, c := range curves.Curves {
				if c == utls.X25519MLKEM768 {
					t.Errorf("classical mode must not contain X25519MLKEM768 in SupportedCurves")
				}
			}
		}
		if keyShares, ok := ext.(*utls.KeyShareExtension); ok {
			hasX25519 := false
			for _, ks := range keyShares.KeyShares {
				if ks.Group == utls.X25519MLKEM768 {
					t.Errorf("classical mode must not contain X25519MLKEM768 KeyShare")
				}
				if ks.Group == utls.X25519 {
					hasX25519 = true
				}
			}
			if !hasX25519 {
				t.Errorf("classical mode must explicitly contain X25519 KeyShare")
			}
		}
	}

	// 2.2 非法 KeyShare 枚举必须被拒
	optsInvalid := optsClassical
	optsInvalid.Reality = &option.OutboundRealityOptions{
		PublicKey: pubKey,
		KeyShare:  "unknown-curve",
	}
	_, err = newRealityClient(ctx, nil, "example.com:443", optsInvalid, true)
	if err == nil {
		t.Errorf("expected error on invalid key_share, got nil")
	}
}

// 3. 测试 MLDSA65 签名公钥解析与配置注入
func TestRealityClient_MLDSA65(t *testing.T) {
	pubKey, _ := generateTestX25519Keys(t)
	ctx := context.Background()

	// 1952 字节标准 ML-DSA-65 公钥材料
	rawMldsaPub := make([]byte, 1952)
	for i := range rawMldsaPub {
		rawMldsaPub[i] = byte(i % 256)
	}

	// 3.1 Base64 RawURL 格式
	optsURL := option.OutboundTLSOptions{
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		Reality: &option.OutboundRealityOptions{
			PublicKey:     pubKey,
			ShortID:       "0123456789abcdef",
			MLDSA65Verify: base64.RawURLEncoding.EncodeToString(rawMldsaPub),
		},
	}
	clientCfgURL, err := newRealityClient(ctx, nil, "example.com:443", optsURL, true)
	if err != nil {
		t.Fatalf("newRealityClient Base64URL failed: %v", err)
	}
	if clientCfgURL.(*RealityClientConfig).mldsa65Pub == nil {
		t.Errorf("mldsa65Pub not parsed")
	}

	// 3.2 长度不匹配拦截
	optsBadLen := optsURL
	optsBadLen.Reality = &option.OutboundRealityOptions{
		PublicKey:     pubKey,
		ShortID:       "0123456789abcdef",
		MLDSA65Verify: base64.RawURLEncoding.EncodeToString(make([]byte, 100)),
	}
	_, err = newRealityClient(ctx, nil, "example.com:443", optsBadLen, true)
	if err == nil {
		t.Errorf("expected error on invalid mldsa65_verify length, got nil")
	}
}

// 4. 测试 Server 端 KeyShare (ClassicalKeyShare) 与 MLDSA65Seed
func TestRealityServer_KeyShareAndMLDSA65(t *testing.T) {
	_, privKey := generateTestX25519Keys(t)
	ctx := context.Background()

	// 4.1 Hybrid 曲线模式
	inboundOpts := option.InboundTLSOptions{
		Reality: &option.InboundRealityOptions{
			PrivateKey: privKey,
			KeyShare:   C.RealityKeyShareHybrid,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: 443,
				},
			},
		},
	}
	serverCfg, err := NewRealityServer(ctx, nil, inboundOpts)
	if err != nil {
		t.Fatalf("NewRealityServer hybrid failed: %v", err)
	}
	cfg := serverCfg.(*RealityServerConfig)
	if cfg.config.ClassicalKeyShare {
		t.Errorf("expected ClassicalKeyShare=false for hybrid mode")
	}

	// 4.2 Classical 曲线模式
	inboundOpts.Reality.KeyShare = C.RealityKeyShareClassical
	serverCfgClassical, err := NewRealityServer(ctx, nil, inboundOpts)
	if err != nil {
		t.Fatalf("NewRealityServer classical failed: %v", err)
	}
	if !serverCfgClassical.(*RealityServerConfig).config.ClassicalKeyShare {
		t.Errorf("expected ClassicalKeyShare=true for classical mode")
	}

	// 4.3 MLDSA65 32 字节 Seed 解析
	seed := make([]byte, 32)
	inboundOpts.Reality.MLDSA65Seed = hex.EncodeToString(seed)
	serverCfgSeed, err := NewRealityServer(ctx, nil, inboundOpts)
	if err != nil {
		t.Fatalf("NewRealityServer MLDSA65Seed failed: %v", err)
	}
	if serverCfgSeed.(*RealityServerConfig).config.Mldsa65Key == nil {
		t.Errorf("expected Mldsa65Key to be parsed from seed")
	}
}
