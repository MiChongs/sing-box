//go:build linux

package process

import (
	"cmp"
	"slices"
)

type processPathEntry struct {
	inode uint32
	list  uint32
}

// processPathIndex is an immutable socket inode to executable paths snapshot.
// Entries are sorted by inode and point into shared path lists, so a snapshot
// costs eight bytes per socket instead of a map slot holding a slice header,
// and processes running the same executable share one list.
type processPathIndex struct {
	entries []processPathEntry
	lists   [][]string
}

func (i processPathIndex) lookup(inode uint32) []string {
	index, found := slices.BinarySearchFunc(i.entries, inode, func(entry processPathEntry, target uint32) int {
		return cmp.Compare(entry.inode, target)
	})
	if !found {
		return nil
	}
	return i.lists[i.entries[index].list]
}

func (i processPathIndex) len() int {
	return len(i.entries)
}

type processPathIndexBuilder struct {
	entries []processPathEntry
	lists   [][]string
}

func (b *processPathIndexBuilder) addList(paths []string) uint32 {
	b.lists = append(b.lists, paths)
	return uint32(len(b.lists) - 1)
}

func (b *processPathIndexBuilder) add(inode, list uint32) {
	b.entries = append(b.entries, processPathEntry{inode: inode, list: list})
}

// build sorts the entries and merges the owners of a shared socket into one
// list, keeping the order in which processes were added.
func (b *processPathIndexBuilder) build() processPathIndex {
	entries := b.entries
	slices.SortFunc(entries, func(left, right processPathEntry) int {
		return cmp.Or(cmp.Compare(left.inode, right.inode), cmp.Compare(left.list, right.list))
	})
	merged := entries[:0]
	for start := 0; start < len(entries); {
		end := start + 1
		for end < len(entries) && entries[end].inode == entries[start].inode {
			end++
		}
		entry := entries[start]
		if end-start > 1 {
			var paths []string
			for _, owner := range entries[start:end] {
				for _, path := range b.lists[owner.list] {
					if !slices.Contains(paths, path) {
						paths = append(paths, path)
					}
				}
			}
			if len(paths) > len(b.lists[entry.list]) {
				entry.list = b.addList(slices.Clip(paths))
			}
		}
		merged = append(merged, entry)
		start = end
	}
	return processPathIndex{entries: slices.Clip(merged), lists: b.lists}
}
