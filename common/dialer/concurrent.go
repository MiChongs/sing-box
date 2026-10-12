package dialer

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
)

const (
	concurrentHistoryCapacity = 4096
	// A destination keeps its last winning address for this long. Each new
	// winner renews it.
	concurrentWinnerLifetime = 10 * time.Minute
	// An address whose attempt failed is tried after the others for this long.
	concurrentFailureLifetime = time.Minute
	// The last winner starts alone and gets twice its smoothed connect time,
	// clamped to these bounds, before the other addresses join the race.
	concurrentMinHeadStart = 20 * time.Millisecond
	concurrentMaxHeadStart = 250 * time.Millisecond
	// Wins are counted per attempt position; the last bucket covers the rest.
	concurrentWinPositions = 4
)

// TCPConcurrent races TCP connection attempts to the addresses a destination
// resolved to and returns the first established connection (dns.tcp_concurrent).
//
// Attempts are ordered by connection history and address family: the last
// winning address of the destination goes first, addresses that failed
// recently go last, and IPv6 and IPv4 addresses alternate, starting with the
// preferred family. Without a fixed attempt delay, a destination without
// history races all of its addresses at once, while a known destination gives
// its last winner a head start based on its connect time before the others
// join, so a healthy destination costs a single handshake. A failed attempt
// starts the next one immediately, and the remaining attempts are canceled as
// soon as one connection is established. The history is dropped when the
// network changes.
type TCPConcurrent struct {
	logger        logger.ContextLogger
	enabled       atomic.Bool
	fixedDelay    bool
	attemptDelay  time.Duration
	maxConcurrent int
	winners       *freelru.Cache[concurrentDestination, concurrentWinner]
	failures      *freelru.Cache[netip.AddrPort, struct{}]
	statistics    concurrentStatistics
}

type concurrentDestination struct {
	host string
	port uint16
}

type concurrentWinner struct {
	address     netip.Addr
	connectTime time.Duration
}

type concurrentResult struct {
	index   int
	address netip.Addr
	conn    net.Conn
	err     error
	elapsed time.Duration
}

type concurrentStatistics struct {
	races          atomic.Uint64
	raceFailures   atomic.Uint64
	historyHits    atomic.Uint64
	attempts       atomic.Uint64
	failures       atomic.Uint64
	canceled       atomic.Uint64
	lateClosed     atomic.Uint64
	wins           [concurrentWinPositions]atomic.Uint64
	connectTimeSum atomic.Int64
}

// TCPConcurrentStatus is a snapshot of the configuration, counters and
// connection history.
type TCPConcurrentStatus struct {
	Enabled bool
	// AttemptDelay is meaningful when FixedDelay is set; otherwise the delay
	// adapts to the history of each destination.
	FixedDelay    bool
	AttemptDelay  time.Duration
	MaxConcurrent int
	Statistics    TCPConcurrentStatistics
	Destinations  []TCPConcurrentDestination
	Failures      []TCPConcurrentFailure
}

type TCPConcurrentStatistics struct {
	// Races counts dials with more than one address; RaceFailures the ones
	// where every attempt failed, and HistoryHits the ones the remembered
	// address won during its head start, at the cost of one handshake.
	Races        uint64
	RaceFailures uint64
	HistoryHits  uint64
	// Attempts counts started attempts, Failures the ones that failed on
	// their own, Canceled the ones still pending when the race was decided,
	// and LateClosed the connections they established anyway.
	Attempts   uint64
	Failures   uint64
	Canceled   uint64
	LateClosed uint64
	// Wins counts won races by the position of the winning attempt; the last
	// element covers the positions after it.
	Wins []uint64
	// ConnectTime sums the connect times of the winning attempts.
	ConnectTime        time.Duration
	AverageConnectTime time.Duration
}

type TCPConcurrentDestination struct {
	Host        string
	Port        uint16
	Address     netip.Addr
	ConnectTime time.Duration
	ExpiresAt   time.Time
}

type TCPConcurrentFailure struct {
	Address   netip.AddrPort
	ExpiresAt time.Time
}

func NewTCPConcurrent(logger logger.ContextLogger, options *option.TCPConcurrentOptions) (*TCPConcurrent, error) {
	concurrent := &TCPConcurrent{
		logger:   logger,
		winners:  common.Must1(freelru.New[concurrentDestination, concurrentWinner](concurrentHistoryCapacity, maphash.NewHasher[concurrentDestination]().Hash32, true)),
		failures: common.Must1(freelru.New[netip.AddrPort, struct{}](concurrentHistoryCapacity, maphash.NewHasher[netip.AddrPort]().Hash32, true)),
	}
	concurrent.winners.SetLifetime(concurrentWinnerLifetime)
	concurrent.failures.SetLifetime(concurrentFailureLifetime)
	if options != nil {
		if options.AttemptDelay != nil {
			if *options.AttemptDelay < 0 {
				return nil, E.New("invalid tcp_concurrent.attempt_delay: ", time.Duration(*options.AttemptDelay))
			}
			concurrent.fixedDelay = true
			concurrent.attemptDelay = time.Duration(*options.AttemptDelay)
		}
		concurrent.maxConcurrent = int(options.MaxConcurrent)
		concurrent.enabled.Store(options.Enabled)
	}
	return concurrent, nil
}

// TCPConcurrentFromContext returns the instance of the box ctx belongs to.
func TCPConcurrentFromContext(ctx context.Context) *TCPConcurrent {
	return service.PtrFromContext[TCPConcurrent](ctx)
}

func (c *TCPConcurrent) Enabled() bool {
	return c != nil && c.enabled.Load()
}

// SetEnabled switches concurrent dialing at runtime (Clash API tcp-concurrent).
// Dialers with their own tcp_concurrent keep it.
func (c *TCPConcurrent) SetEnabled(enabled bool) {
	if c.enabled.Swap(enabled) == enabled {
		return
	}
	if enabled {
		c.logger.Info("tcp concurrent enabled")
	} else {
		c.logger.Info("tcp concurrent disabled")
	}
}

// ResetHistory forgets the winning and failed addresses, which describe the
// previous network after it changes.
func (c *TCPConcurrent) ResetHistory() {
	if c == nil {
		return
	}
	c.winners.Purge()
	c.failures.Purge()
	c.logger.Debug("tcp concurrent: history reset")
}

func (c *TCPConcurrent) Status() TCPConcurrentStatus {
	status := TCPConcurrentStatus{
		Enabled:       c.Enabled(),
		FixedDelay:    c.fixedDelay,
		AttemptDelay:  c.attemptDelay,
		MaxConcurrent: c.maxConcurrent,
		Statistics:    c.Statistics(),
	}
	for _, key := range c.winners.Keys() {
		winner, expiresAt, loaded := c.winners.PeekWithLifetime(key)
		if !loaded {
			continue
		}
		status.Destinations = append(status.Destinations, TCPConcurrentDestination{
			Host:        key.host,
			Port:        key.port,
			Address:     winner.address,
			ConnectTime: winner.connectTime,
			ExpiresAt:   expiresAt,
		})
	}
	slices.SortFunc(status.Destinations, func(a, b TCPConcurrentDestination) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port))
	})
	for _, address := range c.failures.Keys() {
		_, expiresAt, loaded := c.failures.PeekWithLifetime(address)
		if !loaded {
			continue
		}
		status.Failures = append(status.Failures, TCPConcurrentFailure{Address: address, ExpiresAt: expiresAt})
	}
	slices.SortFunc(status.Failures, func(a, b TCPConcurrentFailure) int {
		return a.Address.Compare(b.Address)
	})
	return status
}

func (c *TCPConcurrent) Statistics() TCPConcurrentStatistics {
	statistics := TCPConcurrentStatistics{
		Races:        c.statistics.races.Load(),
		RaceFailures: c.statistics.raceFailures.Load(),
		HistoryHits:  c.statistics.historyHits.Load(),
		Attempts:     c.statistics.attempts.Load(),
		Failures:     c.statistics.failures.Load(),
		Canceled:     c.statistics.canceled.Load(),
		LateClosed:   c.statistics.lateClosed.Load(),
		Wins:         make([]uint64, concurrentWinPositions),
	}
	var won uint64
	for i := range statistics.Wins {
		statistics.Wins[i] = c.statistics.wins[i].Load()
		won += statistics.Wins[i]
	}
	statistics.ConnectTime = time.Duration(c.statistics.connectTimeSum.Load())
	if won > 0 {
		statistics.AverageConnectTime = statistics.ConnectTime / time.Duration(won)
	}
	return statistics
}

// HistorySize returns the number of remembered destinations and failed
// addresses, including entries about to expire.
func (c *TCPConcurrent) HistorySize() (destinations int, failures int) {
	return c.winners.Len(), c.failures.Len()
}

// TCPConcurrentPolicy decides whether a dialer races the addresses it dials:
// the tcp_concurrent dialer option overrides the runtime switch of
// dns.tcp_concurrent. The zero value never races, for dialers that cannot,
// such as TCP Fast Open ones, which defer the handshake to the first write.
type TCPConcurrentPolicy struct {
	instance *TCPConcurrent
	override *bool
}

func NewTCPConcurrentPolicy(ctx context.Context, override *bool) TCPConcurrentPolicy {
	return TCPConcurrentPolicy{instance: TCPConcurrentFromContext(ctx), override: override}
}

func (p TCPConcurrentPolicy) Enabled() bool {
	if p.instance == nil {
		return false
	}
	if p.override != nil {
		return *p.override
	}
	return p.instance.Enabled()
}

func (p TCPConcurrentPolicy) applies(network string, destinationAddresses []netip.Addr) bool {
	return N.NetworkName(network) == N.NetworkTCP && len(destinationAddresses) > 1 && p.Enabled()
}

// Dial connects to one of destinationAddresses. dial opens a single attempt and
// must stop when its context is canceled, which happens once the race is
// decided or ctx is done.
func (c *TCPConcurrent) Dial(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, dial func(ctx context.Context, address netip.Addr) (net.Conn, error)) (net.Conn, error) {
	key := concurrentDestination{port: destination.Port}
	if destination.IsDomain() {
		key.host = destination.Fqdn
	} else {
		key.host = destination.AddrString()
	}
	winner, hasWinner := c.winners.Get(key)
	addresses := c.order(destinationAddresses, destination.Port, preferIPv6, winner.address)
	if len(addresses) == 0 {
		return nil, E.New("missing destination addresses")
	}
	c.statistics.races.Add(1)
	hasWinner = hasWinner && addresses[0] == winner.address
	var (
		// Without a fixed delay, the head start of a known winner is the only
		// delay; afterwards the remaining addresses start together.
		delay     time.Duration
		staggered bool
	)
	if c.fixedDelay {
		delay = c.attemptDelay
		staggered = true
	} else if hasWinner {
		delay = min(max(2*winner.connectTime, concurrentMinHeadStart), concurrentMaxHeadStart)
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan concurrentResult, len(addresses))
	var next, pending int
	defer func() {
		cancel()
		if pending > 0 {
			c.statistics.canceled.Add(uint64(pending))
			// Close connections established after the race was decided, and
			// remember attempts that failed on their own rather than by the
			// cancellation.
			go func(pending int) {
				for range pending {
					result := <-results
					if result.conn != nil {
						result.conn.Close()
						c.statistics.lateClosed.Add(1)
					} else if !E.IsCanceled(result.err) {
						c.recordFailure(result.address, destination.Port)
					}
				}
			}(pending)
		}
	}()
	canStart := func() bool {
		return next < len(addresses) && (c.maxConcurrent == 0 || pending < c.maxConcurrent)
	}
	start := func() {
		index, address := next, addresses[next]
		next++
		pending++
		c.statistics.attempts.Add(1)
		c.logger.TraceContext(ctx, "tcp concurrent: attempt ", index+1, "/", len(addresses), " to ", M.SocksaddrFrom(address, destination.Port), " for ", destination)
		go func() {
			startedAt := time.Now()
			conn, err := dial(raceCtx, address)
			results <- concurrentResult{index, address, conn, err, time.Since(startedAt)}
		}()
	}
	startAll := func() {
		for canStart() {
			start()
		}
	}

	start()
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	if delay == 0 {
		startAll()
	} else if next < len(addresses) {
		timer = time.NewTimer(delay)
		defer timer.Stop()
		timerC = timer.C
	}
	errors := make([]error, len(addresses))
	for {
		select {
		case <-timerC:
			if !staggered {
				startAll()
				timerC = nil
			} else {
				if canStart() {
					start()
				}
				if next < len(addresses) {
					timer.Reset(delay)
				} else {
					timerC = nil
				}
			}
		case result := <-results:
			pending--
			if result.err == nil {
				c.recordWinner(key, winner, result.address, result.elapsed, result.index)
				if hasWinner && next == 1 {
					c.statistics.historyHits.Add(1)
				}
				if next > 1 {
					c.logger.DebugContext(ctx, "tcp concurrent: connected to ", destination, " via ", result.address, " in ", result.elapsed.Round(time.Millisecond), ", attempt ", result.index+1, " of ", next, " started")
				}
				return result.conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c.logger.TraceContext(ctx, "tcp concurrent: attempt to ", M.SocksaddrFrom(result.address, destination.Port), " failed: ", result.err)
			errors[result.index] = result.err
			c.recordFailure(result.address, destination.Port)
			if hasWinner && result.address == winner.address {
				c.winners.Remove(key)
				hasWinner = false
				if !staggered && timerC != nil {
					// The head start was for this address.
					startAll()
					timerC = nil
				}
			}
			if canStart() {
				start()
				if staggered && timerC != nil {
					timer.Reset(delay)
				}
			}
			if pending == 0 && next == len(addresses) {
				c.statistics.raceFailures.Add(1)
				return nil, E.Errors(errors...)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// order deduplicates destinationAddresses and sorts them by connection history
// and address family.
func (c *TCPConcurrent) order(destinationAddresses []netip.Addr, port uint16, preferIPv6 bool, winner netip.Addr) []netip.Addr {
	var (
		seen                      = make(map[netip.Addr]struct{}, len(destinationAddresses))
		preferred, others, failed []netip.Addr
		hasWinner                 bool
	)
	for _, address := range destinationAddresses {
		address = address.Unmap()
		if _, loaded := seen[address]; loaded {
			continue
		}
		seen[address] = struct{}{}
		switch {
		case address == winner:
			hasWinner = true
		case c.failures.Contains(netip.AddrPortFrom(address, port)):
			failed = append(failed, address)
		case address.Is6() == preferIPv6:
			preferred = append(preferred, address)
		default:
			others = append(others, address)
		}
	}
	ordered := make([]netip.Addr, 0, len(seen))
	if hasWinner {
		ordered = append(ordered, winner)
	}
	ordered = appendInterleaved(ordered, preferred, others)
	return append(ordered, failed...)
}

func appendInterleaved(ordered []netip.Addr, preferred []netip.Addr, others []netip.Addr) []netip.Addr {
	for i := 0; i < len(preferred) || i < len(others); i++ {
		if i < len(preferred) {
			ordered = append(ordered, preferred[i])
		}
		if i < len(others) {
			ordered = append(ordered, others[i])
		}
	}
	return ordered
}

func (c *TCPConcurrent) recordWinner(key concurrentDestination, previous concurrentWinner, address netip.Addr, connectTime time.Duration, index int) {
	c.statistics.wins[min(index, concurrentWinPositions-1)].Add(1)
	c.statistics.connectTimeSum.Add(int64(connectTime))
	if previous.address == address && previous.connectTime > 0 {
		// Smooth like the TCP RTT estimator (RFC 6298, alpha 1/8).
		connectTime = previous.connectTime + (connectTime-previous.connectTime)/8
	}
	c.winners.Add(key, concurrentWinner{address: address, connectTime: connectTime})
	c.failures.Remove(netip.AddrPortFrom(address, key.port))
}

func (c *TCPConcurrent) recordFailure(address netip.Addr, port uint16) {
	c.statistics.failures.Add(1)
	c.failures.Add(netip.AddrPortFrom(address, port), struct{}{})
}

// DialConcurrent dials through dns.tcp_concurrent when policy applies, and
// otherwise races the address families like N.DialParallel.
func DialConcurrent(ctx context.Context, policy TCPConcurrentPolicy, dialer N.Dialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, fallbackDelay time.Duration) (net.Conn, error) {
	if policy.applies(network, destinationAddresses) {
		return policy.instance.Dial(ctx, destination, destinationAddresses, preferIPv6, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.SocksaddrFrom(address, destination.Port))
		})
	}
	return N.DialParallel(ctx, dialer, network, destination, destinationAddresses, preferIPv6, fallbackDelay)
}

// DialConcurrentNetwork is DialConcurrent for dialers with network strategies;
// each attempt dials its address like DialSerialNetwork.
func DialConcurrentNetwork(ctx context.Context, policy TCPConcurrentPolicy, dialer ParallelInterfaceDialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if policy.applies(network, destinationAddresses) {
		return policy.instance.Dial(ctx, destination, destinationAddresses, preferIPv6, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return DialSerialNetwork(ctx, dialer, network, destination, []netip.Addr{address}, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		})
	}
	return DialParallelNetwork(ctx, dialer, network, destination, destinationAddresses, preferIPv6, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
}

// DialSerialConcurrent dials through dns.tcp_concurrent when policy applies,
// and otherwise one address after another like N.DialSerial. It serves dialers
// that confirm the connection to the destination before returning, such as
// the network stacks of VPN endpoints and SOCKS or HTTP CONNECT clients, and
// keeps the family of the first address preferred.
func DialSerialConcurrent(ctx context.Context, policy TCPConcurrentPolicy, dialer N.Dialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if policy.applies(network, destinationAddresses) {
		return policy.instance.Dial(ctx, destination, destinationAddresses, destinationAddresses[0].Is6(), func(ctx context.Context, address netip.Addr) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.SocksaddrFrom(address, destination.Port))
		})
	}
	return N.DialSerial(ctx, dialer, network, destination, destinationAddresses)
}

// dialDetourConcurrent dials resolved addresses through a detour. When policy
// applies and the detour outbound dials address lists itself (N.ParallelDialer),
// it receives all of them and races them if it can confirm its handshakes;
// otherwise the addresses are dialed one after another as before.
func dialDetourConcurrent(ctx context.Context, policy TCPConcurrentPolicy, detour *DetourDialer, parallel bool, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, fallbackDelay time.Duration) (net.Conn, error) {
	if policy.applies(network, destinationAddresses) {
		outbound, err := detour.Dialer()
		if err != nil {
			return nil, err
		}
		if parallelDialer, isParallel := outbound.(N.ParallelDialer); isParallel {
			return parallelDialer.DialParallel(ctx, network, destination, destinationAddresses)
		}
	}
	if parallel {
		return N.DialParallel(ctx, detour, network, destination, destinationAddresses, preferIPv6, fallbackDelay)
	}
	return N.DialSerial(ctx, detour, network, destination, destinationAddresses)
}

// setTCPConcurrentOverride applies the tcp_concurrent dialer option to a
// resolve dialer.
func setTCPConcurrentOverride(dialer N.Dialer, override *bool) {
	switch resolveDialer := dialer.(type) {
	case *resolveDialer:
		resolveDialer.concurrent.override = override
	case *resolveParallelNetworkDialer:
		resolveDialer.concurrent.override = override
	}
}

// DialEach dials destinationAddresses one after another through
// dialer.DialContext. Unlike N.DialSerial, it does not defer to the dialer's
// own DialParallel, so that DialParallel implementations can use it for the
// networks they do not race.
func DialEach(ctx context.Context, dialer N.Dialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	var errors []error
	for _, address := range destinationAddresses {
		conn, err := dialer.DialContext(ctx, network, M.SocksaddrFrom(address, destination.Port))
		if err == nil {
			return conn, nil
		}
		errors = append(errors, err)
	}
	return nil, E.Errors(errors...)
}

// NewProxyTCPConcurrentPolicy is the policy for racing destinations through a
// proxy protocol whose server answers a connect request, such as SOCKS or HTTP
// CONNECT. Whether the answer waits until the server reached the destination
// depends on the server (sing-box's SOCKS inbound waits, while its HTTP
// inbound and mihomo answer at once), so only an explicit tcp_concurrent on
// the outbound enables it.
func NewProxyTCPConcurrentPolicy(ctx context.Context, override *bool) TCPConcurrentPolicy {
	if override == nil || !*override {
		return TCPConcurrentPolicy{}
	}
	return NewTCPConcurrentPolicy(ctx, override)
}
