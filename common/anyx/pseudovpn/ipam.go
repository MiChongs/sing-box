package pseudovpn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrAddressEmpty       = errors.New("pseudovpn: address list cannot be empty")
	ErrTooManyIPv4Subnets = errors.New("pseudovpn: at most one IPv4 subnet is allowed")
	ErrTooManyIPv6Subnets = errors.New("pseudovpn: at most one IPv6 subnet is allowed")
	ErrSubnetExhausted    = errors.New("pseudovpn: ipam subnet exhausted")
	ErrNoSubnet           = errors.New("pseudovpn: no available subnet for address family")
	ErrInvalidPrefix      = errors.New("pseudovpn: invalid ipam prefix")
	ErrIPAllocated        = errors.New("pseudovpn: requested IP is already allocated")
)

const (
	MinLeaseDuration     = 5 * time.Minute
	MaxLeaseDuration     = 7 * 24 * time.Hour
	DefaultLeaseDuration = 3 * 24 * time.Hour

	// MaxLeasesPerPool 限制单个地址池同时持有的租约数。/64 这类超大子网实践上不会耗尽，
	// 但租约表常驻内存，不设上限时已认证的客户端可以靠不断更换 ClientID 撑爆服务端内存。
	MaxLeasesPerPool = 1 << 16
)

// ReleasedLease 描述一条被 IPAM 回收（过期清扫或驱逐）的租约，引擎据此按归属清理路由与客户端状态。
type ReleasedLease struct {
	IP       netip.Addr
	ClientID uint64
}

// ClampLeaseDuration 将租约时间严格约束在 [5m, 7d] 之间，缺省或非正数默认调整为 3 天。
func ClampLeaseDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultLeaseDuration
	}
	if d < MinLeaseDuration {
		return MinLeaseDuration
	}
	if d > MaxLeaseDuration {
		return MaxLeaseDuration
	}
	return d
}

// IPLease 记录特定客户端所占用的虚拟 IP 租约信息。
type IPLease struct {
	IP       netip.Addr
	ClientID uint64
	Token    uint64
	// UserKey 标识租约所属的已认证用户（0 表示未知），用于跨客户端重启的粘性分配。
	UserKey   uint64
	expireAt  atomic.Int64 // UnixNano
	lastTouch atomic.Int64 // Unix (秒) 节流时间戳
}

func (l *IPLease) ExpireAt() time.Time {
	nano := l.expireAt.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

func (l *IPLease) SetExpireAt(t time.Time) {
	if t.IsZero() {
		l.expireAt.Store(0)
	} else {
		l.expireAt.Store(t.UnixNano())
	}
}

// ExtendExpireAtIfNewer 采用 CAS 原子操作顺延到期时间戳，杜绝并发乱序写覆盖。
func (l *IPLease) ExtendExpireAtIfNewer(newNano int64) bool {
	for {
		curr := l.expireAt.Load()
		if curr >= newNano {
			return false
		}
		if l.expireAt.CompareAndSwap(curr, newNano) {
			return true
		}
	}
}

func (l *IPLease) IsExpired(now time.Time) bool {
	nano := l.expireAt.Load()
	if nano == 0 {
		return false
	}
	return now.UnixNano() > nano
}

func generateToken() uint64 {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			continue
		}
		val := binary.BigEndian.Uint64(b[:])
		if val != 0 {
			return val
		}
	}
}

type subnetPool struct {
	prefix    netip.Prefix
	serverIP  netip.Addr
	cursor    netip.Addr
	capacity  uint64
	leases    map[netip.Addr]*IPLease
	stickyMap map[uint64]netip.Addr // ClientID -> 粘性保留 IP
	// userSticky 记录每个用户最近一次持有的地址。客户端重启后 ClientID 会变，
	// 同一用户的新客户端仍优先拿回该地址（原持有者离线或租约已过期时）。
	userSticky map[uint64]netip.Addr
	// released 暂存分配路径上顺带清扫掉的过期租约，由 PurgeExpired 一并交给引擎，
	// 否则引擎不知道这些地址已易主，旧客户端的路由与状态会残留。
	released []ReleasedLease
}

func newSubnetPool(prefix netip.Prefix) (*subnetPool, error) {
	if !prefix.IsValid() {
		return nil, ErrInvalidPrefix
	}
	serverIP := prefix.Addr().Unmap()
	prefix = prefix.Masked()
	if prefix.Bits() == prefix.Addr().BitLen() {
		return nil, ErrInvalidPrefix
	}

	// 若传入的网关地址恰好为网络基地址，自适应修正为其下一位可用主机地址
	if serverIP == prefix.Addr() && prefix.Bits() < prefix.Addr().BitLen() {
		serverIP = serverIP.Next()
	}

	var capacity uint64
	if prefix.Addr().Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits == 0 {
			return nil, ErrInvalidPrefix
		}
		if hostBits == 1 {
			// /31 点对点子网 (RFC 3021)，共 2 个地址，除去服务端 1 个，可用 1 个
			capacity = 1
		} else {
			total := uint64(1) << hostBits
			if total > 3 {
				// 扣除网络地址、广播地址与服务端网关地址
				capacity = total - 3
			} else {
				return nil, ErrInvalidPrefix
			}
		}
	} else {
		hostBits := 128 - prefix.Bits()
		if hostBits == 0 {
			return nil, ErrInvalidPrefix
		}
		if hostBits == 1 {
			// /127 点对点子网 (RFC 6164)，共 2 个地址，除去服务端 1 个，可用 1 个
			capacity = 1
		} else if hostBits <= 32 {
			total := uint64(1) << hostBits
			if total > 2 {
				// 扣除子网零地址与服务端网关地址
				capacity = total - 2
			} else {
				return nil, ErrInvalidPrefix
			}
		} else {
			capacity = MaxLeasesPerPool
		}
	}
	capacity = min(capacity, MaxLeasesPerPool)

	return &subnetPool{
		prefix:     prefix,
		serverIP:   serverIP,
		cursor:     serverIP,
		capacity:   capacity,
		leases:     make(map[netip.Addr]*IPLease),
		stickyMap:  make(map[uint64]netip.Addr),
		userSticky: make(map[uint64]netip.Addr),
	}, nil
}

func (p *subnetPool) isReserved(addr netip.Addr) bool {
	if addr == p.serverIP {
		return true
	}
	if addr.Is4() {
		// RFC 3021: /31 点对点子网无网络号与广播号限制
		if p.prefix.Bits() <= 30 {
			if addr == p.prefix.Addr() {
				return true
			}
			if !p.prefix.Contains(addr.Next()) {
				return true
			}
		}
	} else if addr.Is6() {
		// RFC 6164: /127 点对点子网无子网路由器任播地址限制
		if p.prefix.Bits() <= 126 {
			if addr == p.prefix.Addr() {
				return true
			}
		}
	}
	return false
}

func (p *subnetPool) purgeExpired(now time.Time) {
	for ip, lease := range p.leases {
		if lease.IsExpired(now) {
			delete(p.leases, ip)
			if lease.ClientID != 0 && p.stickyMap[lease.ClientID] == ip {
				delete(p.stickyMap, lease.ClientID)
			}
			p.released = append(p.released, ReleasedLease{IP: ip, ClientID: lease.ClientID})
		}
	}
	// 清理 stickyMap 中指向不存在于 leases 中的孤立条目，确保映射表不产生残留膨胀
	for cid, ip := range p.stickyMap {
		if l, exists := p.leases[ip]; !exists || l.ClientID != cid {
			delete(p.stickyMap, cid)
		}
	}
}

func (p *subnetPool) full() bool {
	return uint64(len(p.leases)) >= p.capacity
}

// takeReleased 交出暂存的回收记录。
func (p *subnetPool) takeReleased() []ReleasedLease {
	released := p.released
	p.released = nil
	return released
}

// dropLease 删除租约，并把它记为已回收，供引擎同步路由。
func (p *subnetPool) dropLease(ip netip.Addr) {
	lease, exists := p.leases[ip]
	if !exists {
		return
	}
	delete(p.leases, ip)
	if lease.ClientID != 0 && p.stickyMap[lease.ClientID] == ip {
		delete(p.stickyMap, lease.ClientID)
	}
	p.released = append(p.released, ReleasedLease{IP: ip, ClientID: lease.ClientID})
}

func (p *subnetPool) allocate(clientID uint64, token uint64, duration time.Duration, now time.Time) (netip.Addr, error) {
	// 过期清扫是 O(n) 的，只在池满时才在分配路径上做，常规回收交给引擎的 GC 周期。
	if p.full() {
		p.purgeExpired(now)
	}
	addr, err := p.allocateOnce(clientID, token, duration, now)
	if err == ErrSubnetExhausted && !p.full() {
		// 线性扫描撞上了一片未清扫的过期租约，清扫后重试一次。
		p.purgeExpired(now)
		addr, err = p.allocateOnce(clientID, token, duration, now)
	}
	return addr, err
}

func (p *subnetPool) allocateOnce(clientID uint64, token uint64, duration time.Duration, now time.Time) (netip.Addr, error) {
	// 1. 粘性保留优先检查：若该 ClientID 已有记录，优先复用
	if clientID != 0 {
		if stickyIP, ok := p.stickyMap[clientID]; ok && p.prefix.Contains(stickyIP) && !p.isReserved(stickyIP) {
			lease, exists := p.leases[stickyIP]
			if exists {
				// 仅当租约属于自己，或者租约已过期时，才允许原位激活
				if lease.ClientID == clientID || lease.IsExpired(now) {
					if lease.ClientID != clientID {
						// 接管他人的过期租约：旧主的粘性记录作废，并通知引擎清理其路由。
						if p.stickyMap[lease.ClientID] == stickyIP {
							delete(p.stickyMap, lease.ClientID)
						}
						p.released = append(p.released, ReleasedLease{IP: stickyIP, ClientID: lease.ClientID})
					}
					lease.ClientID = clientID
					lease.Token = token
					if duration > 0 {
						lease.SetExpireAt(now.Add(duration))
					}
					lease.lastTouch.Store(now.Unix())
					return stickyIP, nil
				}
				// 若已被其他活跃客户端占用，放弃该粘性 IP，回退至下方全局分配
			} else {
				// 此前已被 GC 移除，若容量允许则优先认领回自己的粘性 IP
				if !p.full() {
					newLease := &IPLease{
						IP:       stickyIP,
						ClientID: clientID,
						Token:    token,
					}
					if duration > 0 {
						newLease.SetExpireAt(now.Add(duration))
					}
					newLease.lastTouch.Store(now.Unix())
					p.leases[stickyIP] = newLease
					p.cursor = stickyIP
					return stickyIP, nil
				}
			}
		}
	}

	if p.full() {
		return netip.Addr{}, ErrSubnetExhausted
	}

	start := p.cursor
	if !start.IsValid() || !p.prefix.Contains(start) {
		start = p.prefix.Addr()
	}

	curr := start
	var totalChecked uint64
	// 已占用地址最多 capacity 个，再加上保留地址，扫描这么多次必然能遇到空位或确认池满。
	maxAttempts := p.capacity + uint64(len(p.leases)) + 4

	for {
		curr = curr.Next()
		if !p.prefix.Contains(curr) {
			curr = p.prefix.Addr()
		}

		if totalChecked >= maxAttempts {
			return netip.Addr{}, ErrSubnetExhausted
		}
		totalChecked++

		if p.isReserved(curr) {
			continue
		}

		lease, exists := p.leases[curr]
		if !exists || lease.IsExpired(now) {
			if exists {
				p.dropLease(curr)
			}
			newLease := &IPLease{
				IP:       curr,
				ClientID: clientID,
				Token:    token,
			}
			if duration > 0 {
				newLease.SetExpireAt(now.Add(duration))
			}
			newLease.lastTouch.Store(now.Unix())
			p.leases[curr] = newLease
			p.cursor = curr
			if clientID != 0 {
				p.stickyMap[clientID] = curr
			}
			return curr, nil
		}
	}
}

func (p *subnetPool) acquire(addr netip.Addr, clientID uint64, token uint64, duration time.Duration, now time.Time) error {
	if !p.prefix.Contains(addr) {
		return ErrInvalidPrefix
	}
	if p.isReserved(addr) {
		return ErrInvalidPrefix
	}

	lease, exists := p.leases[addr]
	if exists && !lease.IsExpired(now) {
		if clientID == 0 || lease.ClientID != clientID {
			return ErrIPAllocated
		}
		// 相同 ClientID 跨 Session 重新协商：允许原子接管
		lease.Token = token
		if duration > 0 {
			lease.SetExpireAt(now.Add(duration))
		}
		lease.lastTouch.Store(now.Unix())
		if oldIP, ok := p.stickyMap[clientID]; ok && oldIP != addr {
			p.dropOwnedLease(oldIP, clientID)
		}
		p.stickyMap[clientID] = addr
		return nil
	}
	if exists {
		// 过期租约的旧主需要被告知（路由与状态清理）。
		p.dropLease(addr)
	} else if p.full() {
		return ErrSubnetExhausted
	}

	newLease := &IPLease{
		IP:       addr,
		ClientID: clientID,
		Token:    token,
	}
	if duration > 0 {
		newLease.SetExpireAt(now.Add(duration))
	}
	newLease.lastTouch.Store(now.Unix())
	p.leases[addr] = newLease

	if clientID != 0 {
		if oldIP, ok := p.stickyMap[clientID]; ok && oldIP != addr {
			p.dropOwnedLease(oldIP, clientID)
		}
		p.stickyMap[clientID] = addr
	}
	return nil
}

// claimUserSticky 尝试把用户上次持有的地址分配给该用户的新客户端：地址空闲、租约已过期、
// 或仍被同一用户的离线客户端持有时成功。offline 报告某个 ClientID 当前是否没有存活会话。
func (p *subnetPool) claimUserSticky(clientID, userKey, token uint64, duration time.Duration, now time.Time, offline func(uint64) bool) (netip.Addr, bool) {
	if addr, ok := p.userSticky[userKey]; ok {
		if claimed, ok := p.claimAddrForUser(addr, clientID, userKey, token, duration, now, offline); ok {
			return claimed, true
		}
	}
	// 同一用户可能有多台设备，userSticky 只记最近一个地址：再找该用户离线客户端持有的
	// 租约，取最近活动的一条接管。
	var (
		candidate netip.Addr
		touched   int64
	)
	for addr, lease := range p.leases {
		if lease.UserKey != userKey || lease.ClientID == clientID || lease.IsExpired(now) || offline == nil || !offline(lease.ClientID) {
			continue
		}
		if touch := lease.lastTouch.Load(); !candidate.IsValid() || touch > touched {
			candidate, touched = addr, touch
		}
	}
	if !candidate.IsValid() {
		return netip.Addr{}, false
	}
	return p.claimAddrForUser(candidate, clientID, userKey, token, duration, now, offline)
}

func (p *subnetPool) claimAddrForUser(addr netip.Addr, clientID, userKey, token uint64, duration time.Duration, now time.Time, offline func(uint64) bool) (netip.Addr, bool) {
	if !p.prefix.Contains(addr) || p.isReserved(addr) {
		return netip.Addr{}, false
	}
	lease, exists := p.leases[addr]
	switch {
	case !exists:
		if p.full() {
			return netip.Addr{}, false
		}
	case lease.ClientID == clientID:
		lease.Token = token
		if duration > 0 {
			lease.SetExpireAt(now.Add(duration))
		}
		lease.lastTouch.Store(now.Unix())
		return addr, true
	case lease.IsExpired(now), lease.UserKey == userKey && offline != nil && offline(lease.ClientID):
		p.dropLease(addr)
	default:
		return netip.Addr{}, false
	}
	if oldIP, ok := p.stickyMap[clientID]; ok && oldIP != addr {
		p.dropOwnedLease(oldIP, clientID)
	}
	newLease := &IPLease{IP: addr, ClientID: clientID, Token: token, UserKey: userKey}
	if duration > 0 {
		newLease.SetExpireAt(now.Add(duration))
	}
	newLease.lastTouch.Store(now.Unix())
	p.leases[addr] = newLease
	p.stickyMap[clientID] = addr
	return addr, true
}

// bindUser 把地址记为用户的粘性地址。
func (p *subnetPool) bindUser(addr netip.Addr, userKey uint64) {
	if userKey == 0 {
		return
	}
	if lease, exists := p.leases[addr]; exists {
		lease.UserKey = userKey
	}
	p.userSticky[userKey] = addr
}

// dropOwnedLease 仅当租约仍归 clientID 所有时删除，避免误删已被重新分配给他人的地址。
func (p *subnetPool) dropOwnedLease(ip netip.Addr, clientID uint64) {
	if lease, exists := p.leases[ip]; exists && lease.ClientID == clientID {
		p.dropLease(ip)
	}
}

func (p *subnetPool) reclaim(addr netip.Addr, clientID uint64, token uint64, duration time.Duration, now time.Time) bool {
	lease, exists := p.leases[addr]
	if !exists || lease.IsExpired(now) {
		return false
	}
	if lease.ClientID != clientID || lease.Token != token {
		return false
	}
	if duration > 0 {
		lease.ExtendExpireAtIfNewer(now.Add(duration).UnixNano())
	}
	lease.lastTouch.Store(now.Unix())
	return true
}

// IPAM 提供服务端 PseudoVPN 虚拟子网的 IP 动态租借、认领、滑动续约与回收。
type IPAM struct {
	mu     sync.RWMutex
	v4Pool *subnetPool
	v6Pool *subnetPool
	pools  []*subnetPool
}

// NewIPAM 依据传入的网段切片初始化 IPAM。最多允许 1 个 IPv4 和 1 个 IPv6 网段，非空。
func NewIPAM(prefixes []netip.Prefix) (*IPAM, error) {
	if len(prefixes) == 0 {
		return nil, ErrAddressEmpty
	}

	var v4Pool *subnetPool
	var v6Pool *subnetPool
	var pools []*subnetPool

	for _, p := range prefixes {
		if !p.IsValid() {
			return nil, ErrInvalidPrefix
		}
		pool, err := newSubnetPool(p)
		if err != nil {
			return nil, err
		}
		if pool.serverIP.Is4() {
			if v4Pool != nil {
				return nil, ErrTooManyIPv4Subnets
			}
			v4Pool = pool
		} else if pool.serverIP.Is6() {
			if v6Pool != nil {
				return nil, ErrTooManyIPv6Subnets
			}
			v6Pool = pool
		}
		pools = append(pools, pool)
	}

	return &IPAM{
		v4Pool: v4Pool,
		v6Pool: v6Pool,
		pools:  pools,
	}, nil
}

func (ipam *IPAM) HasV4() bool {
	ipam.mu.RLock()
	defer ipam.mu.RUnlock()
	return ipam.v4Pool != nil
}

func (ipam *IPAM) HasV6() bool {
	ipam.mu.RLock()
	defer ipam.mu.RUnlock()
	return ipam.v6Pool != nil
}

func (ipam *IPAM) ServerV4() netip.Addr {
	ipam.mu.RLock()
	defer ipam.mu.RUnlock()
	if ipam.v4Pool != nil {
		return ipam.v4Pool.serverIP
	}
	return netip.Addr{}
}

func (ipam *IPAM) ServerV6() netip.Addr {
	ipam.mu.RLock()
	defer ipam.mu.RUnlock()
	if ipam.v6Pool != nil {
		return ipam.v6Pool.serverIP
	}
	return netip.Addr{}
}

// AllocateDualStackForSession 为指定客户端协同分配 IPv4 与 IPv6 虚拟租约并生成随机 Token。
func (ipam *IPAM) AllocateDualStackForSession(
	clientID uint64,
	duration time.Duration,
	wantV4 bool,
	reqV4 netip.Addr,
	wantV6 bool,
	reqV6 netip.Addr,
) (v4 netip.Addr, v6 netip.Addr, flags byte, token uint64, err error) {
	return ipam.AllocateDualStackForUser(clientID, 0, nil, duration, wantV4, reqV4, wantV6, reqV6)
}

// AllocateDualStackForUser 在 AllocateDualStackForSession 的基础上按用户粘性分配：每个地址族依次
// 尝试客户端请求的旧地址、该用户上次持有的地址、地址池中的空闲地址。userKey 为 0 时不做用户粘性。
func (ipam *IPAM) AllocateDualStackForUser(
	clientID uint64,
	userKey uint64,
	offline func(clientID uint64) bool,
	duration time.Duration,
	wantV4 bool,
	reqV4 netip.Addr,
	wantV6 bool,
	reqV6 netip.Addr,
) (v4 netip.Addr, v6 netip.Addr, flags byte, token uint64, err error) {
	duration = ClampLeaseDuration(duration)
	now := time.Now()
	token = generateToken()
	if clientID == 0 {
		clientID = generateToken()
	}

	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	var lastErr error
	allocateFamily := func(pool *subnetPool, requested netip.Addr, is4 bool) netip.Addr {
		if requested.IsValid() && requested.Is4() == is4 && !requested.IsUnspecified() {
			if pool.acquire(requested, clientID, token, duration, now) == nil {
				pool.bindUser(requested, userKey)
				return requested
			}
		}
		if userKey != 0 {
			if addr, ok := pool.claimUserSticky(clientID, userKey, token, duration, now, offline); ok {
				pool.bindUser(addr, userKey)
				return addr
			}
		}
		addr, allocErr := pool.allocate(clientID, token, duration, now)
		if allocErr != nil {
			lastErr = allocErr
			return netip.Addr{}
		}
		pool.bindUser(addr, userKey)
		return addr
	}

	if wantV4 && ipam.v4Pool != nil {
		if v4 = allocateFamily(ipam.v4Pool, reqV4.Unmap(), true); v4.IsValid() {
			flags |= 0x01
		}
	}
	if wantV6 && ipam.v6Pool != nil {
		if v6 = allocateFamily(ipam.v6Pool, reqV6, false); v6.IsValid() {
			flags |= 0x02
		}
	}

	if flags == 0 {
		if lastErr != nil {
			return netip.Addr{}, netip.Addr{}, 0, 0, lastErr
		}
		return netip.Addr{}, netip.Addr{}, 0, 0, ErrNoSubnet
	}

	return v4, v6, flags, token, nil
}

// ReclaimLease 在客户端重连时校验 ClientID 与 Token 凭据。
func (ipam *IPAM) ReclaimLease(addr netip.Addr, clientID uint64, token uint64, duration time.Duration) bool {
	if !addr.IsValid() || clientID == 0 || token == 0 {
		return false
	}
	addr = addr.Unmap()
	duration = ClampLeaseDuration(duration)
	now := time.Now()

	ipam.mu.RLock()
	defer ipam.mu.RUnlock()

	var pool *subnetPool
	if addr.Is4() {
		pool = ipam.v4Pool
	} else if addr.Is6() {
		pool = ipam.v6Pool
	}
	if pool != nil && pool.prefix.Contains(addr) {
		return pool.reclaim(addr, clientID, token, duration, now)
	}
	return false
}

// Touch 供数据面按缺省时长被动节流刷新租约。
func (ipam *IPAM) Touch(addr netip.Addr) bool {
	return ipam.TouchWithDuration(addr, DefaultLeaseDuration)
}

// TouchWithDuration 供数据面按指定时长被动刷新租约。
// 内部采用读锁寻表 + 原子 CAS 节流（15 秒内最多更新一次时间戳），杜绝数据面锁争用。
func (ipam *IPAM) TouchWithDuration(addr netip.Addr, duration time.Duration) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	now := time.Now()
	nowUnix := now.Unix()
	duration = ClampLeaseDuration(duration)

	ipam.mu.RLock()
	defer ipam.mu.RUnlock()

	var pool *subnetPool
	if addr.Is4() {
		pool = ipam.v4Pool
	} else if addr.Is6() {
		pool = ipam.v6Pool
	}
	if pool == nil || !pool.prefix.Contains(addr) {
		return false
	}

	lease, ok := pool.leases[addr]
	if !ok || lease.IsExpired(now) {
		return false
	}

	last := lease.lastTouch.Load()
	if nowUnix-last > 15 {
		if lease.lastTouch.CompareAndSwap(last, nowUnix) {
			lease.ExtendExpireAtIfNewer(now.Add(duration).UnixNano())
		}
	}
	return true
}

// ValidateClientAndTouch 严格校验指定 ClientID 是否合法持有该虚拟 IP，并在租约有效时顺延滑动窗口。
func (ipam *IPAM) ValidateClientAndTouch(addr netip.Addr, clientID uint64, duration time.Duration) bool {
	if !addr.IsValid() || clientID == 0 {
		return false
	}
	addr = addr.Unmap()
	now := time.Now()
	nowUnix := now.Unix()
	duration = ClampLeaseDuration(duration)

	ipam.mu.RLock()
	defer ipam.mu.RUnlock()

	var pool *subnetPool
	if addr.Is4() {
		pool = ipam.v4Pool
	} else if addr.Is6() {
		pool = ipam.v6Pool
	}
	if pool == nil || !pool.prefix.Contains(addr) {
		return false
	}

	lease, ok := pool.leases[addr]
	if !ok || lease.IsExpired(now) || lease.ClientID != clientID {
		return false
	}

	last := lease.lastTouch.Load()
	if nowUnix-last > 15 {
		if lease.lastTouch.CompareAndSwap(last, nowUnix) {
			lease.ExtendExpireAtIfNewer(now.Add(duration).UnixNano())
		}
	}
	return true
}

func (ipam *IPAM) poolFor(addr netip.Addr) *subnetPool {
	var pool *subnetPool
	if addr.Is4() {
		pool = ipam.v4Pool
	} else if addr.Is6() {
		pool = ipam.v6Pool
	}
	if pool == nil || !pool.prefix.Contains(addr) {
		return nil
	}
	return pool
}

// Release 将租借的虚拟 IP 归还到所属网段池中，不论其归属。
func (ipam *IPAM) Release(addr netip.Addr) {
	ipam.ReleaseOwned(addr, 0)
}

// ReleaseOwned 仅当 addr 的租约仍属于 clientID 时归还（clientID 为 0 时不校验归属），
// 返回是否归还。客户端换址或被清理时使用，避免误删已被重新分配给其他客户端的地址。
func (ipam *IPAM) ReleaseOwned(addr netip.Addr, clientID uint64) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()

	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	pool := ipam.poolFor(addr)
	if pool == nil {
		return false
	}
	lease, ok := pool.leases[addr]
	if !ok || (clientID != 0 && lease.ClientID != clientID) {
		return false
	}
	if lease.ClientID != 0 && pool.stickyMap[lease.ClientID] == addr {
		delete(pool.stickyMap, lease.ClientID)
	}
	delete(pool.leases, addr)
	return true
}

// Owner 返回 addr 当前有效租约的持有者。
func (ipam *IPAM) Owner(addr netip.Addr) (uint64, bool) {
	if !addr.IsValid() {
		return 0, false
	}
	addr = addr.Unmap()
	now := time.Now()

	ipam.mu.RLock()
	defer ipam.mu.RUnlock()

	pool := ipam.poolFor(addr)
	if pool == nil {
		return 0, false
	}
	lease, ok := pool.leases[addr]
	if !ok || lease.IsExpired(now) {
		return 0, false
	}
	return lease.ClientID, true
}

// LeaseCount 返回当前持有的租约数（含尚未清扫的过期租约）。
func (ipam *IPAM) LeaseCount() int {
	ipam.mu.RLock()
	defer ipam.mu.RUnlock()
	var count int
	for _, pool := range ipam.pools {
		count += len(pool.leases)
	}
	return count
}

// EvictIdle 在地址族对应的池中驱逐一条最久未活动、且其客户端不在 keep 中的租约。
// 池被已离线客户端的长租约占满时，新客户端借此获得地址，而不是被永久拒绝。
func (ipam *IPAM) EvictIdle(is4 bool, keep func(clientID uint64) bool) (ReleasedLease, bool) {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	pool := ipam.v6Pool
	if is4 {
		pool = ipam.v4Pool
	}
	if pool == nil {
		return ReleasedLease{}, false
	}
	var (
		victim     *IPLease
		victimTime int64
	)
	for _, lease := range pool.leases {
		if keep != nil && keep(lease.ClientID) {
			continue
		}
		touch := lease.lastTouch.Load()
		if victim == nil || touch < victimTime {
			victim, victimTime = lease, touch
		}
	}
	if victim == nil {
		return ReleasedLease{}, false
	}
	released := ReleasedLease{IP: victim.IP, ClientID: victim.ClientID}
	delete(pool.leases, victim.IP)
	if victim.ClientID != 0 && pool.stickyMap[victim.ClientID] == victim.IP {
		delete(pool.stickyMap, victim.ClientID)
	}
	return released, true
}

// PurgeExpired 扫描并回收所有池中已自然过期的租约。
func (ipam *IPAM) PurgeExpired() []netip.Addr {
	released := ipam.PurgeExpiredLeases()
	purged := make([]netip.Addr, 0, len(released))
	for _, lease := range released {
		purged = append(purged, lease.IP)
	}
	return purged
}

// PurgeExpiredLeases 扫描回收过期租约，并连同分配路径上顺带回收的租约一起返回。
func (ipam *IPAM) PurgeExpiredLeases() []ReleasedLease {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	now := time.Now()
	var released []ReleasedLease
	for _, pool := range ipam.pools {
		pool.purgeExpired(now)
		released = append(released, pool.takeReleased()...)
	}
	return released
}

// TakeReleased 交出分配路径上顺带回收的租约记录，不做全量扫描。
func (ipam *IPAM) TakeReleased() []ReleasedLease {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()
	var released []ReleasedLease
	for _, pool := range ipam.pools {
		released = append(released, pool.takeReleased()...)
	}
	return released
}

// PrefixFor 查询指定虚拟 IP 属于哪个子网网段。
func (ipam *IPAM) PrefixFor(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()

	ipam.mu.RLock()
	defer ipam.mu.RUnlock()

	for _, pool := range ipam.pools {
		if pool.prefix.Contains(addr) {
			return pool.prefix, true
		}
	}
	return netip.Prefix{}, false
}
