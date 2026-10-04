//go:build !with_utls

package v2rayxhttp

import boxtls "github.com/sagernet/sing-box/common/tls"

func isRealityConfig(boxtls.Config) bool {
	return false
}
