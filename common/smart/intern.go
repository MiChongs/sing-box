package smart

import (
	"hash/maphash"
	"sync"
)

// interner maps strings (group and node tags) to small stable ids so cell
// keys stay fixed-size and hash cheaply.
type interner struct {
	access sync.RWMutex
	ids    map[string]uint32
	names  []string
}

func newInterner() *interner {
	return &interner{ids: make(map[string]uint32), names: []string{""}}
}

func (in *interner) id(name string) uint32 {
	in.access.RLock()
	id, ok := in.ids[name]
	in.access.RUnlock()
	if ok {
		return id
	}
	in.access.Lock()
	defer in.access.Unlock()
	if id, ok = in.ids[name]; ok {
		return id
	}
	id = uint32(len(in.names))
	in.names = append(in.names, name)
	in.ids[name] = id
	return id
}

func (in *interner) lookup(name string) (uint32, bool) {
	in.access.RLock()
	defer in.access.RUnlock()
	id, ok := in.ids[name]
	return id, ok
}

func (in *interner) name(id uint32) string {
	in.access.RLock()
	defer in.access.RUnlock()
	if int(id) < len(in.names) {
		return in.names[id]
	}
	return ""
}

var hashSeed = maphash.MakeSeed()

// HashString hashes a target or site key. 0 is reserved for "no scope".
func HashString(s string) uint64 {
	if s == "" {
		return 0
	}
	h := maphash.String(hashSeed, s)
	if h == 0 {
		h = 1
	}
	return h
}
