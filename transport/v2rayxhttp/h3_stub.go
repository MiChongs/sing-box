//go:build !with_quic

package v2rayxhttp

import (
	"net/http"

	boxtls "github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// buildH3Transport 在未启用 with_quic 构建标签时返回明确错误，避免静默失败。
// 用户配置 alpn=["h3"] 但二进制未编入 quic-go 时，会在 outbound 启动阶段
// 拿到这条信息明确的错误，而不是后续 dial 阶段才出现"unsupported scheme"。
func buildH3Transport(_ N.Dialer, _ M.Socksaddr, _ boxtls.Config) (http.RoundTripper, error) {
	return nil, E.New("xhttp h3: requires -tags with_quic build (HTTP/3 support not compiled in)")
}
