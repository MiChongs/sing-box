package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TCPNat struct {
	timeout   time.Duration
	portIndex atomic.Uint32
	access    sync.RWMutex
	addrMap   map[netip.AddrPort]uint16
	portMap   map[uint16]*TCPSession
	pool      sync.Pool
}

type TCPSession struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	lastActive  atomic.Int64 // unix nano timestamp, lock-free
}

func (s *TCPSession) updateLastActive() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *TCPSession) isExpired(timeout time.Duration) bool {
	return time.Since(time.Unix(0, s.lastActive.Load())) > timeout
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout: timeout,
		addrMap: make(map[netip.AddrPort]uint16),
		portMap: make(map[uint16]*TCPSession),
	}
	natMap.portIndex.Store(10000)
	natMap.pool.New = func() any {
		return &TCPSession{}
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	// Phase 1: collect expired entries under read lock (non-blocking for packet path)
	n.access.RLock()
	var expiredPorts []uint16
	for natPort, session := range n.portMap {
		if session.isExpired(n.timeout) {
			expiredPorts = append(expiredPorts, natPort)
		}
	}
	n.access.RUnlock()

	if len(expiredPorts) == 0 {
		return
	}

	// Phase 2: delete expired entries under write lock (brief hold)
	n.access.Lock()
	for _, natPort := range expiredPorts {
		if session, ok := n.portMap[natPort]; ok {
			// Re-check under write lock to avoid race
			if session.isExpired(n.timeout) {
				delete(n.addrMap, session.Source)
				delete(n.portMap, natPort)
				n.pool.Put(session)
			}
		}
	}
	n.access.Unlock()
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.access.RLock()
	session := n.portMap[port]
	n.access.RUnlock()
	if session != nil {
		session.updateLastActive()
	}
	return session
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort, handler Handler) (uint16, error) {
	n.access.RLock()
	port, loaded := n.addrMap[source]
	n.access.RUnlock()
	if loaded {
		return port, nil
	}
	_, pErr := handler.PrepareConnection(N.NetworkTCP, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), nil, 0)
	if pErr != nil {
		return 0, pErr
	}
	n.access.Lock()
	// Double-check after acquiring write lock
	if port, loaded = n.addrMap[source]; loaded {
		n.access.Unlock()
		return port, nil
	}
	nextPort := uint16(n.portIndex.Add(1))
	if nextPort < 10000 {
		n.portIndex.Store(10000)
		nextPort = uint16(n.portIndex.Add(1))
	}
	session := n.pool.Get().(*TCPSession)
	session.Source = source
	session.Destination = destination
	session.updateLastActive()
	n.addrMap[source] = nextPort
	n.portMap[nextPort] = session
	n.access.Unlock()
	return nextPort, nil
}
