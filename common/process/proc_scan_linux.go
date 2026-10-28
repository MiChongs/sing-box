//go:build linux

package process

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procDirentBufferSize = 32 << 10
	// linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name.
	direntNameOffset = 19
)

var (
	procExeName = [...]byte{'e', 'x', 'e', 0}
	procFDName  = [...]byte{'f', 'd', 0}

	errInvalidDirent = errors.New("invalid directory entry")

	procScannerPool = sync.Pool{New: func() any {
		return &procScanner{
			procDirents: make([]byte, procDirentBufferSize),
			fdDirents:   make([]byte, procDirentBufferSize),
			exe:         make([]byte, syscall.PathMax),
			link:        make([]byte, syscall.PathMax),
			pathLists:   make(map[string][]string),
		}
	}}
)

const (
	processPathsSizeHintCapacity = 64
	procScannerPathListCapacity  = 1024
)

type processPathsSizeHint struct {
	entries int
	lists   int
}

// processPathsSizeHints presizes the next snapshot of a scope so a scan does
// not regrow its slices from empty every time. The counts are taken before
// shared sockets are merged, which is what the builder appends.
var processPathsSizeHints struct {
	access sync.Mutex
	sizes  map[uint32]processPathsSizeHint
}

func loadProcessPathsSizeHint(scope uint32) processPathsSizeHint {
	processPathsSizeHints.access.Lock()
	defer processPathsSizeHints.access.Unlock()
	return processPathsSizeHints.sizes[scope]
}

func storeProcessPathsSizeHint(scope uint32, hint processPathsSizeHint) {
	processPathsSizeHints.access.Lock()
	defer processPathsSizeHints.access.Unlock()
	if processPathsSizeHints.sizes == nil || len(processPathsSizeHints.sizes) >= processPathsSizeHintCapacity {
		processPathsSizeHints.sizes = make(map[uint32]processPathsSizeHint)
	}
	processPathsSizeHints.sizes[scope] = hint
}

// procScanner walks procfs with descriptor-relative syscalls and reused
// buffers. A snapshot visits every descriptor of every process, so the
// os.ReadDir, filepath.Join and string conversions of a path-based walk
// allocated several megabytes per scan on a busy system.
type procScanner struct {
	procDirents []byte
	fdDirents   []byte
	exe         []byte
	link        []byte
	// pathLists interns the single-path list of each executable across
	// scans. Snapshot lists are read-only and have no spare capacity.
	pathLists map[string][]string
	builder   processPathIndexBuilder
}

func buildProcessPaths(ctx context.Context, uid uint32) (processPathIndex, error) {
	scanner := procScannerPool.Get().(*procScanner)
	defer procScannerPool.Put(scanner)
	return scanner.build(ctx, uid)
}

func (s *procScanner) build(ctx context.Context, uid uint32) (processPathIndex, error) {
	procFD, err := openDirectory(unix.AT_FDCWD, pathProc)
	if err != nil {
		return processPathIndex{}, &os.PathError{Op: "open", Path: pathProc, Err: err}
	}
	defer unix.Close(procFD)
	if len(s.pathLists) > procScannerPathListCapacity {
		clear(s.pathLists)
	}
	// The builder's slices become the published snapshot, so each scan
	// starts from fresh backing arrays sized by the previous result.
	hint := loadProcessPathsSizeHint(uid)
	s.builder = processPathIndexBuilder{
		entries: make([]processPathEntry, 0, hint.entries+hint.entries/8),
		lists:   make([][]string, 0, hint.lists+hint.lists/8),
	}
	err = walkDirents(procFD, s.procDirents, func(name []byte, nameZ *byte, direntType uint8) error {
		if direntType != unix.DT_DIR && direntType != unix.DT_UNKNOWN || !isPid(name) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return s.scanProcess(procFD, nameZ, uid)
	})
	if err != nil {
		s.builder = processPathIndexBuilder{}
		return processPathIndex{}, err
	}
	storeProcessPathsSizeHint(uid, processPathsSizeHint{entries: len(s.builder.entries), lists: len(s.builder.lists)})
	index := s.builder.build()
	s.builder = processPathIndexBuilder{}
	return index, nil
}

func (s *procScanner) pathList(exe []byte) []string {
	if paths, loaded := s.pathLists[string(exe)]; loaded {
		return paths
	}
	path := string(exe)
	paths := []string{path}
	s.pathLists[path] = paths
	return paths
}

func (s *procScanner) scanProcess(procFD int, pid *byte, uid uint32) error {
	processFD, err := openatDirectory(procFD, pid)
	if err != nil {
		if isIgnorableProcError(err) {
			return nil
		}
		return err
	}
	defer unix.Close(processFD)
	if uid != processPathsAllUsers {
		var stat unix.Stat_t
		if err = unix.Fstat(processFD, &stat); err != nil {
			if isIgnorableProcError(err) {
				return nil
			}
			return err
		}
		if stat.Uid != uid {
			return nil
		}
	}
	exeLength, err := readlinkat(processFD, &procExeName[0], s.exe)
	if err != nil {
		if isIgnorableProcError(err) {
			return nil
		}
		return err
	}
	fdFD, err := openatDirectory(processFD, &procFDName[0])
	if err != nil {
		return nil
	}
	defer unix.Close(fdFD)
	// The executable path list is resolved once per process and only when it
	// owns a socket; most processes in the walk hold none.
	list := -1
	_ = walkDirents(fdFD, s.fdDirents, func(name []byte, nameZ *byte, _ uint8) error {
		if len(name) == 0 || name[0] == '.' {
			return nil
		}
		n, linkErr := readlinkat(fdFD, nameZ, s.link)
		if linkErr != nil {
			return nil
		}
		inode, ok := parseSocketInode(s.link[:n])
		if !ok {
			return nil
		}
		if list < 0 {
			list = int(s.builder.addList(s.pathList(s.exe[:exeLength])))
		}
		s.builder.add(inode, uint32(list))
		return nil
	})
	return nil
}

func walkDirents(fd int, buffer []byte, visit func(name []byte, nameZ *byte, direntType uint8) error) error {
	for {
		n, err := unix.Getdents(fd, buffer)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n <= 0 {
			return nil
		}
		for offset := 0; offset < n; {
			record := buffer[offset:n]
			if len(record) <= direntNameOffset {
				return errInvalidDirent
			}
			recordLength := int(binary.NativeEndian.Uint16(record[16:18]))
			if recordLength <= direntNameOffset || recordLength > len(record) {
				return errInvalidDirent
			}
			name := record[direntNameOffset:recordLength]
			nameLength := bytes.IndexByte(name, 0)
			if nameLength < 0 {
				return errInvalidDirent
			}
			if err = visit(name[:nameLength], &name[0], record[18]); err != nil {
				return err
			}
			offset += recordLength
		}
	}
}

func openDirectory(dirFD int, path string) (int, error) {
	for {
		fd, err := unix.Openat(dirFD, path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		return fd, err
	}
}

// openatDirectory and readlinkat take NUL-terminated names that point into
// reused buffers, avoiding the string copy of the x/sys/unix wrappers.
func openatDirectory(dirFD int, name *byte) (int, error) {
	for {
		fd, _, errno := unix.Syscall6(unix.SYS_OPENAT, uintptr(dirFD), uintptr(unsafe.Pointer(name)), uintptr(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC), 0, 0, 0)
		switch errno {
		case 0:
			return int(fd), nil
		case unix.EINTR:
			continue
		default:
			return -1, errno
		}
	}
}

func readlinkat(dirFD int, name *byte, buffer []byte) (int, error) {
	n, _, errno := unix.Syscall6(unix.SYS_READLINKAT, uintptr(dirFD), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func isPid(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, char := range name {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
