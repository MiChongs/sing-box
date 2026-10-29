//go:build linux

package tcpinfo

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// readRaw reads TCP_INFO, which Linux (and Android, sharing the same TCP
// stack) exposes on every AF_INET/AF_INET6 SOCK_STREAM socket; the failure
// modes are closed fds, races and non-TCP sockets.
func readRaw(raw syscall.RawConn) (Info, bool) {
	var (
		info *unix.TCPInfo
		ge   error
	)
	err := raw.Control(func(fd uintptr) {
		if int(fd) <= 2 {
			ge = syscall.EBADF
			return
		}
		info, ge = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
	})
	if err != nil || ge != nil || info == nil {
		return Info{}, false
	}
	return Info{
		Retransmissions: info.Total_retrans,
		Losses:          info.Lost,
		PathMTU:         info.Pmtu,
		SegsOut:         uint64(info.Segs_out),
		RetransSegs:     uint64(info.Total_retrans),
	}, true
}
