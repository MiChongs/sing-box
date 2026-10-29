//go:build windows

package tcpinfo

import (
	"syscall"
	"unsafe"
)

// sioTCPInfo is SIO_TCP_INFO (Windows 10 1703 and later).
const sioTCPInfo = 0xD8000027

// tcpInfoV0 mirrors TCP_INFO_v0.
type tcpInfoV0 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint32
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint32
}

// readRaw queries SIO_TCP_INFO version 0.
func readRaw(raw syscall.RawConn) (Info, bool) {
	var (
		info     tcpInfoV0
		returned uint32
		ge       error
	)
	err := raw.Control(func(fd uintptr) {
		version := uint32(0)
		ge = syscall.WSAIoctl(syscall.Handle(fd), sioTCPInfo,
			(*byte)(unsafe.Pointer(&version)), uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)),
			&returned, nil, 0)
	})
	if err != nil || ge != nil || returned < uint32(unsafe.Sizeof(info)) {
		return Info{}, false
	}
	return Info{
		BytesSent:    info.BytesOut,
		BytesRetrans: uint64(info.BytesRetrans),
	}, true
}
