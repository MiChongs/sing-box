//go:build with_utls

package v2rayxhttp

import boxtls "github.com/sagernet/sing-box/common/tls"

// isRealityConfig: REALITY 客户端固定走 HTTP/2，且 auto 模式解析为 stream-one。
func isRealityConfig(tlsConfig boxtls.Config) bool {
	if ktlsConfig, isKTLS := tlsConfig.(*boxtls.KTLSClientConfig); isKTLS {
		tlsConfig = ktlsConfig.Config
	}
	_, isReality := tlsConfig.(*boxtls.RealityClientConfig)
	return isReality
}
