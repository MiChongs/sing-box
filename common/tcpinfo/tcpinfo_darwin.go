//go:build darwin

package tcpinfo

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// readRaw reads TCP_CONNECTION_INFO (Darwin and iOS).
func readRaw(raw syscall.RawConn) (Info, bool) {
	var (
		info *unix.TCPConnectionInfo
		ge   error
	)
	err := raw.Control(func(fd uintptr) {
		if int(fd) <= 2 {
			ge = syscall.EBADF
			return
		}
		info, ge = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	})
	if err != nil || ge != nil || info == nil {
		return Info{}, false
	}
	return Info{
		SegsOut:      info.Txpackets,
		RetransSegs:  info.Txretransmitpackets,
		BytesSent:    info.Txbytes,
		BytesRetrans: info.Txretransmitbytes,
	}, true
}
