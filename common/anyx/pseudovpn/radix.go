package pseudovpn

import (
	"net/netip"
	"sync"
)

type node[T any] struct {
	child  [2]*node[T]
	value  T
	hasVal bool
}

func (n *node[T]) isLeaf() bool {
	return n.child[0] == nil && n.child[1] == nil && !n.hasVal
}

// Table 提供并发安全的 IPv4 / IPv6 最长前缀匹配 (LPM) 路由表。
type Table[T any] struct {
	mu    sync.RWMutex
	v4    *node[T]
	v6    *node[T]
	count int
}

// NewTable 创建一个新的 LPM 路由表。
func NewTable[T any]() *Table[T] {
	return &Table[T]{
		v4: &node[T]{},
		v6: &node[T]{},
	}
}

// normalizePrefix 返回前缀在 v4 / v6 树中的位置。IPv4 映射前缀（::ffff:a.b.c.d/n，n >= 96）
// 归入 v4 树并换算掩码长度，与 Lookup 对映射地址先 Unmap 的行为一致；直接按 v4 地址
// 遍历 128 位掩码会越界。
func normalizePrefix(prefix netip.Prefix) (addr netip.Addr, bits int, ok bool) {
	if !prefix.IsValid() {
		return netip.Addr{}, 0, false
	}
	prefix = prefix.Masked()
	addr = prefix.Addr()
	bits = prefix.Bits()
	if addr.Is4In6() && bits >= 96 {
		return addr.Unmap(), bits - 96, true
	}
	return addr, bits, true
}

// Insert 向路由表中插入网段前缀与其关联的目标对象。
func (t *Table[T]) Insert(prefix netip.Prefix, val T) {
	addr, bits, ok := normalizePrefix(prefix)
	if !ok {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var (
		curr  *node[T]
		bytes []byte
	)
	if addr.Is4() {
		curr = t.v4
		b := addr.As4()
		bytes = b[:]
	} else {
		curr = t.v6
		b := addr.As16()
		bytes = b[:]
	}
	for i := 0; i < bits; i++ {
		bit := (bytes[i>>3] >> (7 - (i & 7))) & 1
		if curr.child[bit] == nil {
			curr.child[bit] = &node[T]{}
		}
		curr = curr.child[bit]
	}

	if !curr.hasVal {
		t.count++
	}
	curr.value = val
	curr.hasVal = true
}

// Remove 从路由表中移除指定前缀并修剪无效分支。
func (t *Table[T]) Remove(prefix netip.Prefix) {
	t.RemoveIf(prefix, nil)
}

// RemoveIf 仅当前缀存在且其值满足 predicate（为 nil 时无条件）时移除，返回是否移除。
// 用于按归属删除路由：地址被回收并重新分配给其他客户端后，旧客户端的清理不能误删新路由。
func (t *Table[T]) RemoveIf(prefix netip.Prefix, predicate func(val T) bool) bool {
	addr, bits, ok := normalizePrefix(prefix)
	if !ok {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var removed bool
	if addr.Is4() {
		b4 := addr.As4()
		removed = t.remove(t.v4, b4[:], bits, predicate)
	} else {
		b16 := addr.As16()
		removed = t.remove(t.v6, b16[:], bits, predicate)
	}
	return removed
}

func (t *Table[T]) remove(root *node[T], addrBytes []byte, bits int, predicate func(val T) bool) bool {
	var (
		stack    [129]*node[T]
		stackDir [128]uint8
	)

	curr := root
	stack[0] = curr

	for i := 0; i < bits; i++ {
		bit := (addrBytes[i>>3] >> (7 - (i & 7))) & 1
		stackDir[i] = bit
		curr = curr.child[bit]
		if curr == nil {
			return false
		}
		stack[i+1] = curr
	}

	if !curr.hasVal || (predicate != nil && !predicate(curr.value)) {
		return false
	}

	var zero T
	curr.value = zero
	curr.hasVal = false
	t.count--

	for i := bits - 1; i >= 0; i-- {
		if !stack[i+1].isLeaf() {
			break
		}
		stack[i].child[stackDir[i]] = nil
	}
	return true
}

// RemoveByValue 遍历并移除所有符合谓词条件的路由项。
func (t *Table[T]) RemoveByValue(predicate func(val T) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pruneNode(t.v4, predicate, &t.count)
	pruneNode(t.v6, predicate, &t.count)
}

func pruneNode[T any](n *node[T], predicate func(val T) bool, count *int) bool {
	if n == nil {
		return false
	}
	if n.hasVal && predicate(n.value) {
		var zero T
		n.value = zero
		n.hasVal = false
		*count--
	}
	for i := 0; i < 2; i++ {
		if n.child[i] != nil {
			if pruneNode(n.child[i], predicate, count) {
				n.child[i] = nil
			}
		}
	}
	return n.isLeaf()
}

// Lookup 对输入的目标 IP 进行最长前缀匹配。
func (t *Table[T]) Lookup(addr netip.Addr) (T, bool) {
	var zero T
	if !addr.IsValid() {
		return zero, false
	}
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	var (
		curr      *node[T]
		lastMatch T
		found     bool
	)

	var (
		bytes  []byte
		length int
	)
	if addr.Is4() {
		curr = t.v4
		b := addr.As4()
		bytes, length = b[:], 32
	} else {
		curr = t.v6
		b := addr.As16()
		bytes, length = b[:], 128
	}
	if curr.hasVal {
		lastMatch = curr.value
		found = true
	}
	for i := 0; i < length; i++ {
		bit := (bytes[i>>3] >> (7 - (i & 7))) & 1
		curr = curr.child[bit]
		if curr == nil {
			break
		}
		if curr.hasVal {
			lastMatch = curr.value
			found = true
		}
	}

	return lastMatch, found
}

// Count 返回当前表内的有效路由项总数。
func (t *Table[T]) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count
}

// Clear 清空路由表的所有节点。
func (t *Table[T]) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.v4 = &node[T]{}
	t.v6 = &node[T]{}
	t.count = 0
}
