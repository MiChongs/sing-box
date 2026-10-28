//go:build linux

package process

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildProcessPathsReference is the path-based procfs walk the descriptor
// scanner replaced; the scanner must produce the same snapshot.
func buildProcessPathsReference(ctx context.Context, uid uint32) (map[uint32][]string, error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, syscall.PathMax)
	processPaths := make(map[uint32][]string)
	for _, file := range files {
		if !file.IsDir() || !isPid([]byte(file.Name())) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		if uid != processPathsAllUsers && info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}
		processPath := filepath.Join(pathProc, file.Name())
		fdPath := filepath.Join(processPath, "fd")
		exePath, err := os.Readlink(filepath.Join(processPath, "exe"))
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			n, err := syscall.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(buffer[:n])
			if !ok {
				continue
			}
			if !slices.Contains(processPaths[inode], exePath) {
				processPaths[inode] = append(processPaths[inode], exePath)
			}
		}
	}
	return processPaths, nil
}

func TestBuildProcessPathsMatchesReference(t *testing.T) {
	var sockets []*net.UDPConn
	for range 16 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		defer conn.Close()
		sockets = append(sockets, conn)
	}
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, uid := range []uint32{uint32(os.Getuid()), processPathsAllUsers} {
		paths, err := buildProcessPaths(context.Background(), uid)
		require.NoError(t, err)
		reference, err := buildProcessPathsReference(context.Background(), uid)
		require.NoError(t, err)
		for _, conn := range sockets {
			inode := socketInode(t, conn)
			require.Contains(t, paths.lookup(inode), executable)
			require.Equal(t, reference[inode], paths.lookup(inode))
		}
		// Other processes may open or close sockets between the two walks;
		// the snapshots must still agree on nearly every inode.
		var matched int
		for inode, referencePaths := range reference {
			if slices.Equal(paths.lookup(inode), referencePaths) {
				matched++
			}
		}
		require.GreaterOrEqual(t, matched*10, len(reference)*9, "matched %d of %d inodes", matched, len(reference))
	}
}

func TestBuildProcessPathsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := buildProcessPaths(ctx, processPathsAllUsers)
	require.ErrorIs(t, err, context.Canceled)
}

func TestIsPid(t *testing.T) {
	require.False(t, isPid(nil))
	require.True(t, isPid([]byte("1234")))
	require.False(t, isPid([]byte("12a")))
}
