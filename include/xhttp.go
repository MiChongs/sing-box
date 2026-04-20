//go:build with_xhttp

package include

import "github.com/sagernet/sing-box/transport/v2rayxhttp"

func init() {
	v2rayxhttp.RegisterPlugin()
}
