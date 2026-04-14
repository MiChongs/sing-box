package interrupt

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

// Group 维护一组由特定 outbound/provider 创建的连接，支持在重连、切换节点或
// 配置变更时集中关闭。
//
// 设计取舍（历史教训）：
//   - 曾尝试分片 + sync.Pool 复用 groupConnItem，但 pool 共享同一 *groupConnItem
//     指针会形成"别名"：一个 item 在被 Conn.Close 释放后立即被 NewConn 重新填充，
//     与此同时 Interrupt 正在锁外对旧 item 执行 `Value.conn = nil`，从而把新建连接
//     的 conn 置为 nil，后续遍历读到 nil interface → `conn.Close()` segfault。
//   - 回归单锁 + 每次 new groupConnItem：分配开销在 URLTest/切换节点等非热路径可忽略，
//     正确性远胜过锁粒度微优化。
type Group struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
	isProvider bool
}

func NewGroup() *Group {
	return &Group{}
}

func (g *Group) NewConn(conn net.Conn, isExternal, isProvider bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider})
	return &Conn{Conn: conn, group: g, element: item}
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal, isProvider bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider})
	return &PacketConn{PacketConn: conn, group: g, element: item}
}

// Interrupt 在持锁下关闭所有匹配条件的连接并清理链表。
//
// 注意：close 操作放在锁内——可能调回 Conn.Close 再次尝试加锁（重入死锁风险）？
// 并不会，因为 Conn.Close 在 c.Conn.Close() 外层才加锁，而这里直接关底层 conn，
// 上游 Conn 包装器的 Close 不会被触发（我们直接关 c.Conn.Close 的 target 的话会）。
// 实际上这里关的是 io.Closer（裸 net.Conn / net.PacketConn），不会回调 Conn.Close。
func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	defer g.access.Unlock()
	var toDelete []*list.Element[*groupConnItem]
	for element := g.connections.Front(); element != nil; element = element.Next() {
		if !element.Value.isProvider && (!element.Value.isExternal || interruptExternalConnections) {
			if element.Value.conn != nil {
				_ = element.Value.conn.Close()
			}
			toDelete = append(toDelete, element)
		}
	}
	for _, element := range toDelete {
		g.connections.Remove(element)
	}
}
