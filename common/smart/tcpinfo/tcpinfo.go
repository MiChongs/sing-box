// Package tcpinfo reads kernel TCP metrics from live sockets for use as
// Smart group ranking signals. The read path is platform-specific:
//
//   - Linux / Android: reads getsockopt(SOL_TCP, TCP_INFO, ...) via
//     golang.org/x/sys/unix.GetsockoptTCPInfo. Returns ok=true along with
//     retransmissions, kernel loss estimate, and path MTU.
//   - Other platforms (Darwin / Windows / FreeBSD / …): returns ok=false
//     with a zero-valued Info. Callers must not treat ok=false as an error
//     state — it just means "this kernel does not expose the counter this
//     code can parse uniformly", and the consumer should zero the
//     corresponding ModelInput fields.
//
// The Read function is safe to call on any net.Conn type; it returns
// ok=false whenever the conn does not implement syscall.Conn (common for
// proxy-wrapped streams — e.g. anytls / vmess / trojan — whose outermost
// layer hides the underlying fd behind encryption/framing). The caller
// should then fall back to best-effort estimation or leave the fields
// zero, as documented on the ModelInput v2 extension block.
package tcpinfo

// Info is the platform-neutral subset of TCP-level metrics we care about
// for ranking. Field semantics:
//
//	Retransmissions — cumulative retransmits for this connection's
//	                   lifetime (Linux: tcp_info.Total_retrans, mapped
//	                   from uint32 to keep the type stable across
//	                   platforms that may expose a different width).
//	Losses          — kernel's current estimate of packets considered
//	                   lost in flight (Linux: tcp_info.Lost). Differs from
//	                   Retransmissions — losses are detected, not yet
//	                   recovered; a healthy connection stays at 0.
//	PathMTU         — observed path MTU in bytes (Linux: tcp_info.Pmtu).
//	                   0 on non-Linux or when the socket pre-dates PMTU
//	                   discovery completion.
//
// All values zero on platforms without TCP_INFO support.
type Info struct {
	Retransmissions uint32
	Losses          uint32
	PathMTU         uint32
}
