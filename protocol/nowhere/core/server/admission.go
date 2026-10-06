package server

import (
	"net"
	"sync"
)

// DefaultMaxUnauthenticatedConnections matches Rust Portal global pre-auth admission.
const DefaultMaxUnauthenticatedConnections = 256

// DefaultMaxUnauthenticatedPerSource matches Rust Portal per-source pre-auth admission.
const DefaultMaxUnauthenticatedPerSource = 32

type sourceKey struct {
	v4  [4]byte
	v6  uint64
	is6 bool
}

func sourceKeyFromAddr(addr net.Addr) (sourceKey, bool) {
	if addr == nil {
		return sourceKey{}, false
	}
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			ip = net.ParseIP(addr.String())
		} else {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return sourceKey{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		var key sourceKey
		copy(key.v4[:], v4)
		return key, true
	}
	v6 := ip.To16()
	if v6 == nil {
		return sourceKey{}, false
	}
	// Group IPv6 by /64 so rotating interface IDs cannot bypass the per-source cap.
	var hi uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(v6[i])
	}
	return sourceKey{v6: hi, is6: true}, true
}

type unauthenticatedAdmission struct {
	maxTotal  int
	maxSource int

	mu        sync.Mutex
	total     int
	perSource map[sourceKey]int
}

func newUnauthenticatedAdmission(maxTotal, maxSource int) *unauthenticatedAdmission {
	if maxTotal <= 0 {
		maxTotal = DefaultMaxUnauthenticatedConnections
	}
	if maxSource <= 0 {
		maxSource = DefaultMaxUnauthenticatedPerSource
	}
	return &unauthenticatedAdmission{
		maxTotal:  maxTotal,
		maxSource: maxSource,
		perSource: make(map[sourceKey]int),
	}
}

type admissionGuard struct {
	admission *unauthenticatedAdmission
	key       sourceKey
	hasKey    bool
	released  bool
}

func (a *unauthenticatedAdmission) tryAcquire(source net.Addr) (*admissionGuard, bool) {
	if a == nil {
		return &admissionGuard{}, true
	}
	key, ok := sourceKeyFromAddr(source)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal {
		return nil, false
	}
	if ok {
		if a.perSource[key] >= a.maxSource {
			return nil, false
		}
		a.perSource[key]++
	}
	a.total++
	return &admissionGuard{admission: a, key: key, hasKey: ok}, true
}

func (g *admissionGuard) Release() {
	if g == nil || g.released || g.admission == nil {
		return
	}
	g.released = true
	a := g.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total > 0 {
		a.total--
	}
	if g.hasKey {
		count := a.perSource[g.key]
		if count <= 1 {
			delete(a.perSource, g.key)
		} else {
			a.perSource[g.key] = count - 1
		}
	}
}
