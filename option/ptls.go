package option

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/crypto/pbkdf2"
)

var ptlsKDFSalt = []byte("sing-box/ptls:v1:psk-kdf-salt")

const ptlsKDFIterations = 30000

// InboundPTLSOptions 服务端 PTLS 入站专属配置
type InboundPTLSOptions struct {
	Enabled bool                       `json:"enabled,omitempty"`
	PSK     badoption.Listable[string] `json:"password,omitempty"` // 32 字节对称预共享密钥 (Hex/Base64/Raw/任意口令，支持单字符串或字符串列表)

	// 动态 CA 签发模式 (优先级高于标准证书)
	CACertificate       badoption.Listable[string] `json:"ca_certificate,omitempty"`
	CACertificatePath   string                     `json:"ca_certificate_path,omitempty"`
	CAKey               badoption.Listable[string] `json:"ca_key,omitempty"`
	CAKeyPath           string                     `json:"ca_key_path,omitempty"`
	CertificateDomains  badoption.Listable[string] `json:"certificate_domains,omitempty"`  // 动态证书签发专属域名列表 (支持泛域名，解耦外层 server_name)
	CertificateValidity badoption.Duration         `json:"certificate_validity,omitempty"` // 证书有效期 (默认 90 天)
	LeafType            string                     `json:"leaf_type,omitempty"`            // 目标叶子证书算法类型 ("ecdsa" / "rsa"，默认 "ecdsa")
	LeafDERSize         int                        `json:"leaf_der_size,omitempty"`        // 目标叶子证书物理 DER 字节尺寸
	ChainDERSize        int                        `json:"chain_der_size,omitempty"`       // 目标整链总计物理 DER 字节尺寸
	TargetEntropy       float64                    `json:"target_entropy,omitempty"`       // 目标证书明文香农信息熵 (bit/byte)

	// Fallback 专属配置对象
	Fallback *InboundPTLSFallbackOptions `json:"fallback,omitempty"`

	// 门禁控制与抗重放
	RejectUnknownSNI bool               `json:"reject_unknown_sni,omitempty"`
	TimeTolerance    badoption.Duration `json:"time_tolerance,omitempty"`
	ReplayCacheSize  int                `json:"replay_cache_size,omitempty"`

	HandshakeTimeout badoption.Duration `json:"handshake_timeout,omitempty"`
}

type InboundPTLSFallbackOptions struct {
	Enabled    *bool              `json:"enabled,omitempty"`
	Server     string             `json:"server,omitempty"`
	ServerPort uint16             `json:"server_port,omitempty"`
	QoS        string             `json:"qos,omitempty"`
	QPS        int                `json:"qps,omitempty"`
	Timeout    badoption.Duration `json:"timeout,omitempty"`
}

func (o *InboundPTLSFallbackOptions) IsEnabled() bool {
	if o == nil {
		return true
	}
	if o.Enabled == nil {
		return true
	}
	return *o.Enabled
}

func (o *InboundPTLSOptions) IsDynamicCAMode() bool {
	return len(o.CACertificate) > 0 || o.CACertificatePath != "" || len(o.CAKey) > 0 || o.CAKeyPath != ""
}

func (o *InboundPTLSOptions) ParsePSK() ([32]byte, error) {
	if len(o.PSK) == 0 {
		return [32]byte{}, E.New("ptls: psk cannot be empty")
	}
	return parsePTLSPSK(o.PSK[0])
}

func (o *InboundPTLSOptions) ParsePSKList() ([][32]byte, error) {
	if len(o.PSK) == 0 {
		return nil, E.New("ptls: psk cannot be empty")
	}
	var pskList [][32]byte
	seen := make(map[[32]byte]bool)
	for _, rawPSK := range o.PSK {
		str := strings.TrimSpace(rawPSK)
		if str == "" {
			continue
		}
		key, err := parsePTLSPSK(str)
		if err != nil {
			return nil, err
		}
		if !seen[key] {
			seen[key] = true
			pskList = append(pskList, key)
		}
	}
	if len(pskList) == 0 {
		return nil, E.New("ptls: psk cannot be empty")
	}
	return pskList, nil
}

// OutboundPTLSOptions 客户端 PTLS 出站专属配置
type OutboundPTLSOptions struct {
	Enabled          bool               `json:"enabled,omitempty"`
	PSK              string             `json:"password,omitempty"`
	HandshakeTimeout badoption.Duration `json:"handshake_timeout,omitempty"`
}

func (o *OutboundPTLSOptions) ParsePSK() ([32]byte, error) {
	return parsePTLSPSK(o.PSK)
}

func parsePTLSPSK(rawPSK string) ([32]byte, error) {
	var key [32]byte
	str := strings.TrimSpace(rawPSK)
	if str == "" {
		return key, E.New("ptls: psk cannot be empty")
	}

	if len(str) == 64 {
		if b, err := hex.DecodeString(str); err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}

	base64Encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range base64Encodings {
		if b, err := enc.DecodeString(str); err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}

	derivedKey := pbkdf2.Key([]byte(str), ptlsKDFSalt, ptlsKDFIterations, 32, sha256.New)
	copy(key[:], derivedKey)
	return key, nil
}
