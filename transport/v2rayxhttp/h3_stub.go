//go:build !with_quic

package v2rayxhttp

import (
	"net"
	"net/http"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errH3NotIncluded = E.New("xhttp: HTTP/3 (alpn h3) requires a build with -tags with_quic")

func checkH3Available() error {
	return errH3NotIncluded
}

func buildH3Transport(N.Dialer, M.Socksaddr, boxtls.Config, *config, time.Duration) (http.RoundTripper, error) {
	return nil, errH3NotIncluded
}

func (s *Server) serveH3(net.PacketConn) error {
	return errH3NotIncluded
}
