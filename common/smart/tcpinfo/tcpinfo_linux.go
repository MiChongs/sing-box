//go:build linux

package tcpinfo

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Read returns the kernel TCP metrics for the given conn, or ok=false if
// the conn does not expose a raw fd (wrapped / non-TCP). Errors from the
// getsockopt call are swallowed because this is an observability path:
// callers receive ok=false and continue with zero values, rather than
// failing the dial. Linux (and Android, which shares the same TCP stack)
// exposes TCP_INFO on every AF_INET/AF_INET6 SOCK_STREAM socket, so the
// failure modes here are really limited to closed fds and races.
//
// The conn parameter may be any net.Conn; we unwrap via syscall.Conn when
// possible and return ok=false otherwise. The SyscallConn-interface probe
// also handles the common case where the outer conn is actually a
// *syscallConnWrapper (e.g. from the standard library's *net.TCPConn) but
// wrapped in a non-syscall.Conn type — we attempt the interface assertion
// rather than the concrete type.
func Read(conn net.Conn) (Info, bool) {
	if conn == nil {
		return Info{}, false
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return Info{}, false
	}
	raw, err := sc.SyscallConn()
	if err != nil || raw == nil {
		return Info{}, false
	}

	var (
		info *unix.TCPInfo
		ge   error
	)
	_ = raw.Control(func(fd uintptr) {
		info, ge = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
	})
	if ge != nil || info == nil {
		return Info{}, false
	}
	return Info{
		Retransmissions: info.Total_retrans,
		Losses:          info.Lost,
		PathMTU:         info.Pmtu,
	}, true
}
