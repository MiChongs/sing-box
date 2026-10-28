//go:build linux

package process

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// pathIndex builds a snapshot from an inode to paths map for tests.
func pathIndex(paths map[uint32][]string) processPathIndex {
	var builder processPathIndexBuilder
	for _, inode := range slices.Sorted(func(yield func(uint32) bool) {
		for inode := range paths {
			if !yield(inode) {
				return
			}
		}
	}) {
		for _, path := range paths[inode] {
			builder.add(inode, builder.addList([]string{path}))
		}
	}
	return builder.build()
}

func TestProcessPathIndexLookup(t *testing.T) {
	var builder processPathIndexBuilder
	netd := builder.addList([]string{"/system/bin/netd"})
	app := builder.addList([]string{"/system/bin/app"})
	appAgain := builder.addList([]string{"/system/bin/app"})
	for _, inode := range []uint32{30, 10, 20} {
		builder.add(inode, netd)
	}
	builder.add(10, netd)
	builder.add(20, app)
	builder.add(20, appAgain)
	builder.add(40, app)
	index := builder.build()
	require.Equal(t, 4, index.len())
	require.Equal(t, []string{"/system/bin/netd"}, index.lookup(10))
	require.Equal(t, []string{"/system/bin/netd", "/system/bin/app"}, index.lookup(20))
	require.Equal(t, []string{"/system/bin/netd"}, index.lookup(30))
	require.Equal(t, []string{"/system/bin/app"}, index.lookup(40))
	require.Nil(t, index.lookup(15))
	require.Nil(t, processPathIndex{}.lookup(1))
	merged := index.lookup(20)
	require.Equal(t, len(merged), cap(merged), "shared lists must not have spare capacity")
}
