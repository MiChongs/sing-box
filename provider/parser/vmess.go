package parser

import (
	"strings"

	"github.com/sagernet/sing-vmess"
)

// resolveVMessAutoSecurity pins the VMess "auto" cipher of foreign
// subscription formats to the AEAD it means there.
//
// mihomo (Clash) and Xray (v2rayN links) resolve "auto" to AES-128-GCM on
// CPUs with AES instructions and ChaCha20-Poly1305 elsewhere, with or without
// TLS. sing-box's VMess outbound instead turns "auto" into "zero" when TLS is
// enabled, which servers that expect an AEAD body reject. Explicit ciphers,
// including none/zero, pass through unchanged, and native sing-box configs are
// not affected.
func resolveVMessAutoSecurity(security string) string {
	switch strings.ToLower(security) {
	case "", "auto":
		if vmess.AutoSecurityType() == vmess.SecurityTypeAes128Gcm {
			return "aes-128-gcm"
		}
		return "chacha20-poly1305"
	default:
		return security
	}
}
