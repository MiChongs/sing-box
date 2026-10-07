// Package tcpinfo reads kernel TCP metrics from live sockets for use as
// Smart group ranking signals and LightGBM features. The read path is
// platform-specific:
//
//   - Linux / Android: getsockopt(SOL_TCP, TCP_INFO). Fills every field.
//   - Darwin / iOS: getsockopt(IPPROTO_TCP, TCP_CONNECTION_INFO). Fills the
//     send-side counters (segments and bytes).
//   - FreeBSD: getsockopt(IPPROTO_TCP, TCP_PERF_INFO). Fills the send-side
//     byte counters.
//   - Windows: WSAIoctl(SIO_TCP_INFO). Fills the send-side byte counters.
//   - Elsewhere: returns ok=false with a zero-valued Info.
//
// ok=false is not an error state — it means the socket could not be reached
// or the kernel does not expose the counters — and consumers zero the
// corresponding ModelInput fields.
//
// Read accepts any net.Conn and walks proxy wrappers (Upstream, NetConn,
// exported net.Conn fields) down to the socket, so it also works on
// protocol-wrapped streams whose transport is a TCP socket. Streams carried
// over UDP (QUIC and the like) never reach a TCP socket and report ok=false.
package tcpinfo

import (
	"net"
	"reflect"
	"syscall"

	"github.com/sagernet/sing/common"
)

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
//	SegsOut / RetransSegs   — segments sent and retransmitted over the
//	                   connection's lifetime (Linux, Darwin).
//	BytesSent / BytesRetrans — payload bytes sent and retransmitted
//	                   (Darwin, FreeBSD, Windows).
//
// Fields a platform does not report stay zero.
type Info struct {
	Retransmissions uint32
	Losses          uint32
	PathMTU         uint32

	SegsOut      uint64
	RetransSegs  uint64
	BytesSent    uint64
	BytesRetrans uint64
}

// Sent is the send-side volume the loss rate is measured against: segments
// where the kernel counts them, payload bytes otherwise. 0 when unknown.
func (i Info) Sent() uint64 {
	if i.SegsOut > 0 {
		return i.SegsOut
	}
	return i.BytesSent
}

// Retransmitted is the retransmitted share of Sent, in the same unit.
func (i Info) Retransmitted() uint64 {
	if i.SegsOut > 0 {
		return i.RetransSegs
	}
	return i.BytesRetrans
}

// LossRate is Retransmitted / Sent clamped to [0, 1]; 0 when nothing was
// sent or the counters are unknown.
func (i Info) LossRate() float64 {
	sent := i.Sent()
	if sent == 0 {
		return 0
	}
	return min(float64(i.Retransmitted())/float64(sent), 1)
}

// Read returns the kernel TCP metrics for conn's underlying socket, or
// ok=false when no TCP socket is reachable or the kernel call fails. Errors
// are swallowed: this is an observability path and callers continue with
// zero values rather than failing the connection.
func Read(conn net.Conn) (Info, bool) {
	raw := socketOf(conn)
	if raw == nil {
		return Info{}, false
	}
	return readRaw(raw)
}

// maxUnwrapDepth bounds the wrapper walk; real chains are a handful of
// layers deep, and the bound also ends any wrapper cycle.
const maxUnwrapDepth = 32

// socketOf walks conn's wrapper chain down to the first layer that exposes
// a raw socket.
func socketOf(conn net.Conn) syscall.RawConn {
	for depth := 0; conn != nil && depth < maxUnwrapDepth; depth++ {
		if sc, ok := conn.(syscall.Conn); ok {
			raw, err := sc.SyscallConn()
			if err != nil {
				return nil
			}
			return raw
		}
		conn = innerConn(conn)
	}
	return nil
}

// innerConn returns the conn wrapped by conn: via sing's Upstream or the
// standard library's NetConn, falling back to the first exported net.Conn
// field for wrappers that implement neither.
func innerConn(conn net.Conn) net.Conn {
	if u, ok := conn.(common.WithUpstream); ok {
		if next, ok := u.Upstream().(net.Conn); ok {
			return next
		}
	}
	if u, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return u.NetConn()
	}
	v := reflect.ValueOf(conn)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		if next, ok := v.Field(i).Interface().(net.Conn); ok && next != nil {
			return next
		}
	}
	return nil
}
