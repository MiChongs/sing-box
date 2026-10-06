package nowhere

import (
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// defaultALPN is the sole ALPN every Nowhere 2 carrier negotiates.
const defaultALPN = wire.DefaultALPN

func normalizeNowhereInboundTLS(options *option.InboundTLSOptions) (*option.InboundTLSOptions, error) {
	if options == nil {
		return nil, C.ErrTLSRequired
	}
	alpn, err := normalizeNowhereALPN(options.ALPN)
	if err != nil {
		return nil, err
	}
	clone := *options
	clone.ALPN = badoption.Listable[string]{alpn}
	clone.MinVersion = "1.3"
	clone.MaxVersion = "1.3"
	return &clone, nil
}

func normalizeNowhereOutboundTLS(options *option.OutboundTLSOptions) (*option.OutboundTLSOptions, error) {
	if options == nil {
		return nil, C.ErrTLSRequired
	}
	alpn, err := normalizeNowhereALPN(options.ALPN)
	if err != nil {
		return nil, err
	}
	clone := *options
	clone.ALPN = badoption.Listable[string]{alpn}
	clone.MinVersion = "1.3"
	clone.MaxVersion = "1.3"
	return &clone, nil
}

// normalizeNowhereNextServerName applies the Rust Vector sni contract to the
// chained Portal's server_name: empty or "none" disables certificate
// verification (the endpoint host may still be sent as ClientHello SNI), while
// an explicit name must be an ASCII DNS name of at most 253 bytes, without
// ':'/'['/']' and not an IP literal.
func normalizeNowhereNextServerName(serverName string) (string, error) {
	if serverName == "" || serverName == "none" {
		return "", nil
	}
	if len(serverName) > 253 || !isASCII(serverName) || strings.ContainsAny(serverName, ":[]") {
		return "", E.New("nowhere: next server_name must be an ASCII DNS name")
	}
	if _, err := netip.ParseAddr(serverName); err == nil {
		return "", E.New("nowhere: next server_name must be an ASCII DNS name")
	}
	return serverName, nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 127 {
			return false
		}
	}
	return true
}

// applyNowhereCertificatePin installs a leaf-certificate SHA-256 pin verifier on
// the host TLS client config. Empty or "none" disables pinning (Rust contract);
// a real pin overrides SNI/chain checks.
func applyNowhereCertificatePin(config tls.Config, pin string) error {
	parsed, err := wire.ParseCertificatePin(pin)
	if err != nil {
		return err
	}
	if parsed == "" {
		return nil
	}
	verifier, err := wire.PeerCertificatePinVerifier(parsed)
	if err != nil {
		return err
	}
	std, err := config.STDConfig()
	if err != nil {
		return E.Cause(err, "nowhere: pin requires a std TLS config")
	}
	std.InsecureSkipVerify = true
	std.VerifyPeerCertificate = verifier
	return nil
}

func normalizeNowhereALPN(values []string) (string, error) {
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return defaultALPN, nil
	}
	if len(values) != 1 {
		return "", E.New("nowhere: exactly one ALPN is required")
	}
	return values[0], nil
}
