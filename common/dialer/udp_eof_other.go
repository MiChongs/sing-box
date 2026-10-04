//go:build !(darwin || dragonfly || freebsd || netbsd || openbsd)

package dialer

func isUDPEOF(fd uintptr) bool {
	return false
}
