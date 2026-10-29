//go:build linux && (amd64 || arm64 || riscv64 || ppc64 || ppc64le || s390x)

package process

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// fstatatName stats a NUL-terminated name relative to dirFD without the
// string copy of unix.Fstatat. These architectures pass unix.Stat_t to
// newfstatat unchanged.
func fstatatName(dirFD int, _ []byte, nameZ *byte, stat *unix.Stat_t) error {
	for {
		_, _, errno := unix.Syscall6(unix.SYS_NEWFSTATAT, uintptr(dirFD), uintptr(unsafe.Pointer(nameZ)), uintptr(unsafe.Pointer(stat)), 0, 0, 0)
		switch errno {
		case 0:
			return nil
		case unix.EINTR:
			continue
		default:
			return errno
		}
	}
}
