package tun

import (
	"runtime"

	"github.com/sagernet/sing-tun"
)

// autoRedirectOutputMark returns the output mark sing-tun applies for
// auto-redirect, so the network manager marks outbound sockets with the same
// value. Same as sing-tun Options.AutoRedirectOutputMarkOrDefault, which the
// reF1nd sing-tun fork does not export yet.
func autoRedirectOutputMark(options *tun.Options) uint32 {
	const androidReservedMarkMask = 0xE31FFFFF
	value := options.AutoRedirectOutputMark
	if runtime.GOOS == "android" {
		if value != 0 && value&androidReservedMarkMask == 0 {
			return value
		}
		return tun.DefaultAutoRedirectOutputMarkAndroid
	}
	if value != 0 {
		return value
	}
	return tun.DefaultAutoRedirectOutputMark
}
