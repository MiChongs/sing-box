//go:build !linux && !darwin && !freebsd && !windows

package tcpinfo

import "syscall"

// readRaw reports ok=false: this platform exposes no TCP counters we parse.
// Smart treats the zero values as "unknown".
func readRaw(syscall.RawConn) (Info, bool) {
	return Info{}, false
}
