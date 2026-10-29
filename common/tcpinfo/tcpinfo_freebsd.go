//go:build freebsd

package tcpinfo

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tcpPerfInfo is TCP_PERF_INFO from <netinet/tcp.h>.
const tcpPerfInfo = 0x4e

// tcpPerfInfoFreeBSD mirrors struct tcp_perf_info.
type tcpPerfInfoFreeBSD struct {
	CntCounters [13]uint64
	ProcTime    [13]uint64
	Timebase    uint64
	TbIsStable  uint8
}

// Indices of the "variables of interest" in CntCounters.
const (
	voiTCPTxPB   = 0 // transmitted payload bytes
	voiTCPRetxPB = 1 // retransmitted payload bytes
)

// readRaw reads TCP_PERF_INFO. Kernels built without stats(3) support
// reject it, and the socket then reports ok=false.
func readRaw(raw syscall.RawConn) (Info, bool) {
	var (
		info tcpPerfInfoFreeBSD
		ge   error
	)
	size := uint32(unsafe.Sizeof(info))
	err := raw.Control(func(fd uintptr) {
		if int(fd) <= 2 {
			ge = syscall.EBADF
			return
		}
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(unix.IPPROTO_TCP), uintptr(tcpPerfInfo),
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			ge = errno
		}
	})
	if err != nil || ge != nil || size < uint32(unsafe.Sizeof(info)) {
		return Info{}, false
	}
	return Info{
		BytesSent:    info.CntCounters[voiTCPTxPB],
		BytesRetrans: info.CntCounters[voiTCPRetxPB],
	}, true
}
