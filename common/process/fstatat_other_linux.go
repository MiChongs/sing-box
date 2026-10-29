//go:build linux && !(amd64 || arm64 || riscv64 || ppc64 || ppc64le || s390x)

package process

import "golang.org/x/sys/unix"

func fstatatName(dirFD int, name []byte, _ *byte, stat *unix.Stat_t) error {
	for {
		err := unix.Fstatat(dirFD, string(name), stat, 0)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}
