//go:build !linux

package tcpinfo

import "net"

// Read is a stub on non-Linux platforms. Reports ok=false so callers zero
// the corresponding fields in their output struct. The `conn` parameter is
// accepted and ignored so the caller's code path does not need to be
// platform-scoped — the compiler inlines the no-op and the cost is zero.
//
// Implementing this on other platforms requires:
//
//	Darwin   — getsockopt(SOL_TCP, TCP_CONNECTION_INFO) gives a partial
//	           subset; mapping onto our Info would lose MTU and change
//	           loss semantics. Deferred.
//	Windows  — GetPerTcp6ConnectionEStats / GetPerTcpConnectionEStats via
//	           iphlpapi. Requires cgo-free bindings and admin privileges
//	           for the full stats block; deferred.
//	FreeBSD  — TCP_INFO exists but the struct layout differs. Deferred.
//
// Smart's fallback is built for this: the ranking strategies gracefully
// treat zero Retransmissions/Losses/PathMTU as "unknown", so non-Linux
// deployments simply don't benefit from the TCP_INFO signal but keep
// working against the same ModelInput schema.
func Read(_ net.Conn) (Info, bool) {
	return Info{}, false
}
