package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type concurrentTestConn struct {
	net.Conn
	address netip.Addr
	closed  atomic.Bool
}

func (c *concurrentTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

type concurrentTestAttempt struct {
	address   netip.Addr
	startedAt time.Time
	canceled  chan struct{}
}

// concurrentTestDialer records attempts and answers each address with its
// behavior; addresses without one hang until their attempt is canceled.
type concurrentTestDialer struct {
	access    sync.Mutex
	attempts  []*concurrentTestAttempt
	behaviors map[netip.Addr]func(ctx context.Context) (net.Conn, error)
	conns     []*concurrentTestConn
}

func newConcurrentTestDialer() *concurrentTestDialer {
	return &concurrentTestDialer{behaviors: make(map[netip.Addr]func(ctx context.Context) (net.Conn, error))}
}

func (d *concurrentTestDialer) succeedAfter(address netip.Addr, delay time.Duration) {
	d.behaviors[address] = func(ctx context.Context) (net.Conn, error) {
		select {
		case <-time.After(delay):
			return d.newConn(address), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// succeedIgnoringCancel completes the handshake even after the race is decided,
// like a connection the kernel finishes before the attempt sees the cancel.
func (d *concurrentTestDialer) succeedIgnoringCancel(address netip.Addr, delay time.Duration) {
	d.behaviors[address] = func(ctx context.Context) (net.Conn, error) {
		time.Sleep(delay)
		return d.newConn(address), nil
	}
}

func (d *concurrentTestDialer) failAfter(address netip.Addr, delay time.Duration, err error) {
	d.behaviors[address] = func(ctx context.Context) (net.Conn, error) {
		select {
		case <-time.After(delay):
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (d *concurrentTestDialer) newConn(address netip.Addr) *concurrentTestConn {
	conn := &concurrentTestConn{address: address}
	d.access.Lock()
	d.conns = append(d.conns, conn)
	d.access.Unlock()
	return conn
}

func (d *concurrentTestDialer) dial(ctx context.Context, address netip.Addr) (net.Conn, error) {
	attempt := &concurrentTestAttempt{address: address, startedAt: time.Now(), canceled: make(chan struct{})}
	d.access.Lock()
	d.attempts = append(d.attempts, attempt)
	behavior := d.behaviors[address]
	d.access.Unlock()
	go func() {
		<-ctx.Done()
		close(attempt.canceled)
	}()
	if behavior == nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return behavior(ctx)
}

func (d *concurrentTestDialer) started() []netip.Addr {
	d.access.Lock()
	defer d.access.Unlock()
	addresses := make([]netip.Addr, 0, len(d.attempts))
	for _, attempt := range d.attempts {
		addresses = append(addresses, attempt.address)
	}
	return addresses
}

func (d *concurrentTestDialer) attempt(address netip.Addr) *concurrentTestAttempt {
	d.access.Lock()
	defer d.access.Unlock()
	for _, attempt := range d.attempts {
		if attempt.address == address {
			return attempt
		}
	}
	return nil
}

func newTestTCPConcurrent(t *testing.T, options option.TCPConcurrentOptions) *TCPConcurrent {
	t.Helper()
	options.Enabled = true
	concurrent, err := NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &options)
	require.NoError(t, err)
	return concurrent
}

func concurrentTestDuration(duration time.Duration) *badoption.Duration {
	return (*badoption.Duration)(&duration)
}

var (
	testAddress4A = netip.MustParseAddr("192.0.2.1")
	testAddress4B = netip.MustParseAddr("192.0.2.2")
	testAddress4C = netip.MustParseAddr("192.0.2.3")
	testAddress6A = netip.MustParseAddr("2001:db8::1")
	testAddress6B = netip.MustParseAddr("2001:db8::2")
	testDomain    = M.ParseSocksaddrHostPort("example.com", 443)
)

func requireCanceled(t *testing.T, attempt *concurrentTestAttempt) {
	t.Helper()
	require.NotNil(t, attempt)
	select {
	case <-attempt.canceled:
	case <-time.After(time.Second):
		t.Fatalf("attempt to %s was not canceled", attempt.address)
	}
}

func TestTCPConcurrentOrder(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	addresses := []netip.Addr{
		testAddress4A, testAddress4B, testAddress6A, testAddress4C,
		testAddress6B, netip.AddrFrom16(testAddress4A.As16()),
	}
	require.Equal(t, []netip.Addr{testAddress4A, testAddress6A, testAddress4B, testAddress6B, testAddress4C},
		concurrent.order(addresses, 443, false, netip.Addr{}))
	require.Equal(t, []netip.Addr{testAddress6A, testAddress4A, testAddress6B, testAddress4B, testAddress4C},
		concurrent.order(addresses, 443, true, netip.Addr{}))

	concurrent.failures.Add(netip.AddrPortFrom(testAddress4A, 443), struct{}{})
	require.Equal(t, []netip.Addr{testAddress4C, testAddress4B, testAddress6A, testAddress6B, testAddress4A},
		concurrent.order(addresses, 443, false, testAddress4C), "winner first, failed addresses last")
	require.Equal(t, testAddress4A, concurrent.order(addresses, 80, false, netip.Addr{})[0], "failures are per port")
}

func TestTCPConcurrentColdRaceCancelsLosers(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	dialer := newConcurrentTestDialer()
	dialer.succeedAfter(testAddress4B, 30*time.Millisecond)

	startedAt := time.Now()
	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)
	require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
	require.Less(t, time.Since(startedAt), 500*time.Millisecond)
	require.ElementsMatch(t, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, dialer.started(), "a destination without history races every address")
	requireCanceled(t, dialer.attempt(testAddress4A))
	requireCanceled(t, dialer.attempt(testAddress4C))

	winner, loaded := concurrent.winners.Get(concurrentDestination{host: "example.com", port: 443})
	require.True(t, loaded)
	require.Equal(t, testAddress4B, winner.address)
	require.Positive(t, winner.connectTime)
}

func TestTCPConcurrentClosesLateConnections(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	dialer := newConcurrentTestDialer()
	dialer.succeedAfter(testAddress4A, 10*time.Millisecond)
	dialer.succeedIgnoringCancel(testAddress4B, 60*time.Millisecond)

	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
	require.NoError(t, err)
	require.Equal(t, testAddress4A, conn.(*concurrentTestConn).address)
	require.Eventually(t, func() bool {
		dialer.access.Lock()
		defer dialer.access.Unlock()
		for _, conn := range dialer.conns {
			if conn.address == testAddress4B {
				return conn.closed.Load()
			}
		}
		return false
	}, time.Second, 5*time.Millisecond, "the late connection must be closed")
	require.False(t, conn.(*concurrentTestConn).closed.Load())
}

func TestTCPConcurrentFailureStartsNextAttempt(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{AttemptDelay: concurrentTestDuration(time.Hour)})
	dialer := newConcurrentTestDialer()
	refused := errors.New("connection refused")
	dialer.failAfter(testAddress4A, 0, refused)
	dialer.succeedAfter(testAddress4B, 0)

	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
	require.NoError(t, err, "a failed attempt must not wait for the attempt delay")
	require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
	require.True(t, concurrent.failures.Contains(netip.AddrPortFrom(testAddress4A, 443)))
	require.Equal(t, testAddress4A, concurrent.order([]netip.Addr{testAddress4A, testAddress4C}, 443, false, netip.Addr{})[1])
}

func TestTCPConcurrentFixedDelayStaggers(t *testing.T) {
	const delay = 60 * time.Millisecond
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{AttemptDelay: concurrentTestDuration(delay)})
	dialer := newConcurrentTestDialer()
	dialer.succeedAfter(testAddress4C, 0)

	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)
	require.Equal(t, testAddress4C, conn.(*concurrentTestConn).address)
	first, second, third := dialer.attempt(testAddress4A), dialer.attempt(testAddress4B), dialer.attempt(testAddress4C)
	require.GreaterOrEqual(t, second.startedAt.Sub(first.startedAt), delay-5*time.Millisecond)
	require.GreaterOrEqual(t, third.startedAt.Sub(second.startedAt), delay-5*time.Millisecond)
	requireCanceled(t, first)
	requireCanceled(t, second)
}

func TestTCPConcurrentZeroDelayStartsAll(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{AttemptDelay: concurrentTestDuration(0)})
	dialer := newConcurrentTestDialer()
	dialer.succeedAfter(testAddress4C, 20*time.Millisecond)

	_, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)
	require.Len(t, dialer.started(), 3)
}

func TestTCPConcurrentMaxConcurrent(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{MaxConcurrent: 2})
	dialer := newConcurrentTestDialer()
	refused := errors.New("connection refused")
	dialer.failAfter(testAddress4A, 50*time.Millisecond, refused)
	dialer.succeedAfter(testAddress4C, 0)

	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)
	require.Equal(t, testAddress4C, conn.(*concurrentTestConn).address)
	first, third := dialer.attempt(testAddress4A), dialer.attempt(testAddress4C)
	require.GreaterOrEqual(t, third.startedAt.Sub(first.startedAt), 45*time.Millisecond, "the third attempt waits for a free slot")
}

func TestTCPConcurrentWinnerHeadStart(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	key := concurrentDestination{host: "example.com", port: 443}
	concurrent.winners.Add(key, concurrentWinner{address: testAddress4B, connectTime: 40 * time.Millisecond})

	t.Run("healthy winner costs one handshake", func(t *testing.T) {
		dialer := newConcurrentTestDialer()
		dialer.succeedAfter(testAddress4B, 10*time.Millisecond)
		conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
		require.NoError(t, err)
		require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
		require.Equal(t, []netip.Addr{testAddress4B}, dialer.started())
	})

	t.Run("stalled winner lets the others join", func(t *testing.T) {
		concurrent.winners.Add(key, concurrentWinner{address: testAddress4B, connectTime: 40 * time.Millisecond})
		dialer := newConcurrentTestDialer()
		dialer.succeedAfter(testAddress4C, 0)
		conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
		require.NoError(t, err)
		require.Equal(t, testAddress4C, conn.(*concurrentTestConn).address)
		head, joined := dialer.attempt(testAddress4B), dialer.attempt(testAddress4C)
		headStart := joined.startedAt.Sub(head.startedAt)
		require.GreaterOrEqual(t, headStart, 75*time.Millisecond, "twice the smoothed connect time")
		require.Less(t, headStart, concurrentMaxHeadStart+100*time.Millisecond)
		requireCanceled(t, head)
		winner, _ := concurrent.winners.Get(key)
		require.Equal(t, testAddress4C, winner.address)
	})

	t.Run("failed winner is forgotten", func(t *testing.T) {
		concurrent.winners.Add(key, concurrentWinner{address: testAddress4B, connectTime: time.Second})
		dialer := newConcurrentTestDialer()
		dialer.failAfter(testAddress4B, 0, errors.New("connection refused"))
		dialer.succeedAfter(testAddress4A, 0)
		startedAt := time.Now()
		conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
		require.NoError(t, err)
		require.Equal(t, testAddress4A, conn.(*concurrentTestConn).address)
		require.Less(t, time.Since(startedAt), concurrentMaxHeadStart, "the head start ends with its failure")
		winner, _ := concurrent.winners.Get(key)
		require.Equal(t, testAddress4A, winner.address)
		require.Equal(t, []netip.Addr{testAddress4A, testAddress4B}, concurrent.order([]netip.Addr{testAddress4B, testAddress4A}, 443, false, winner.address))
	})
}

func TestTCPConcurrentSmoothsConnectTime(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	key := concurrentDestination{host: "example.com", port: 443}
	previous := concurrentWinner{address: testAddress4A, connectTime: 80 * time.Millisecond}
	concurrent.recordWinner(key, previous, testAddress4A, 160*time.Millisecond, 0)
	winner, _ := concurrent.winners.Get(key)
	require.Equal(t, 90*time.Millisecond, winner.connectTime)
	concurrent.recordWinner(key, winner, testAddress4B, 30*time.Millisecond, 0)
	winner, _ = concurrent.winners.Get(key)
	require.Equal(t, 30*time.Millisecond, winner.connectTime, "a new winner starts a new estimate")
}

func TestTCPConcurrentAllFail(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	dialer := newConcurrentTestDialer()
	dialer.failAfter(testAddress4A, 0, errors.New("refused A"))
	dialer.failAfter(testAddress4B, 10*time.Millisecond, errors.New("refused B"))

	_, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
	require.ErrorContains(t, err, "refused A")
	require.ErrorContains(t, err, "refused B")
	_, loaded := concurrent.winners.Get(concurrentDestination{host: "example.com", port: 443})
	require.False(t, loaded)
}

func TestTCPConcurrentCallerCancel(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	dialer := newConcurrentTestDialer()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	_, err := concurrent.Dial(ctx, testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
	require.ErrorIs(t, err, context.Canceled)
	requireCanceled(t, dialer.attempt(testAddress4A))
	requireCanceled(t, dialer.attempt(testAddress4B))
	require.False(t, concurrent.failures.Contains(netip.AddrPortFrom(testAddress4A, 443)), "canceled attempts are not failures")
}

type concurrentTestNDialer struct {
	access  sync.Mutex
	dialed  []M.Socksaddr
	results map[netip.Addr]error
}

func (d *concurrentTestNDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dialed = append(d.dialed, destination)
	d.access.Unlock()
	if err := d.results[destination.Addr]; err != nil {
		return nil, err
	}
	return &concurrentTestConn{address: destination.Addr}, nil
}

func (d *concurrentTestNDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestDialConcurrentAppliesOnlyToEnabledTCP(t *testing.T) {
	addresses := []netip.Addr{testAddress4A, testAddress4B}
	refused := map[netip.Addr]error{testAddress4A: errors.New("refused")}

	t.Run("disabled dials in order", func(t *testing.T) {
		concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
		concurrent.SetEnabled(false)
		dialer := &concurrentTestNDialer{results: refused}
		conn, err := DialConcurrent(context.Background(), TCPConcurrentPolicy{instance: concurrent}, dialer, N.NetworkTCP, testDomain, addresses, false, 0)
		require.NoError(t, err)
		require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
		require.False(t, concurrent.failures.Contains(netip.AddrPortFrom(testAddress4A, 443)))
	})

	t.Run("udp is not raced", func(t *testing.T) {
		concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
		dialer := &concurrentTestNDialer{results: refused}
		_, err := DialConcurrent(context.Background(), TCPConcurrentPolicy{instance: concurrent}, dialer, N.NetworkUDP, testDomain, addresses, false, 0)
		require.NoError(t, err)
		require.False(t, concurrent.failures.Contains(netip.AddrPortFrom(testAddress4A, 443)))
	})

	t.Run("enabled tcp races", func(t *testing.T) {
		concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
		dialer := &concurrentTestNDialer{results: refused}
		conn, err := DialConcurrent(context.Background(), TCPConcurrentPolicy{instance: concurrent}, dialer, N.NetworkTCP, testDomain, addresses, false, 0)
		require.NoError(t, err)
		require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
		// Recorded by the race or, when the winner came first, after it.
		require.Eventually(t, func() bool {
			return concurrent.failures.Contains(netip.AddrPortFrom(testAddress4A, 443))
		}, time.Second, 5*time.Millisecond)
	})

	t.Run("nil instance", func(t *testing.T) {
		dialer := &concurrentTestNDialer{results: refused}
		_, err := DialConcurrent(context.Background(), TCPConcurrentPolicy{}, dialer, N.NetworkTCP, testDomain, addresses, false, 0)
		require.NoError(t, err)
	})
}

// Real sockets on loopback: 127.0.0.2 refuses the port the listener holds on
// 127.0.0.1, so the race must end on the listener.
func TestTCPConcurrentLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	refusing, listening := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")
	var netDialer net.Dialer
	conn, err := concurrent.Dial(context.Background(), M.ParseSocksaddrHostPort("localhost", port), []netip.Addr{refusing, listening}, false, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
		return netDialer.DialContext(ctx, N.NetworkTCP, netip.AddrPortFrom(address, port).String())
	})
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, listening, M.AddrPortFromNet(conn.RemoteAddr()).Addr())
	require.Eventually(t, func() bool {
		return concurrent.failures.Contains(netip.AddrPortFrom(refusing, port))
	}, time.Second, 5*time.Millisecond)
}

func TestTCPConcurrentOptions(t *testing.T) {
	var options option.DNSOptions
	require.NoError(t, json.Unmarshal([]byte(`{"tcp_concurrent": true}`), &options))
	require.Equal(t, &option.TCPConcurrentOptions{Enabled: true}, options.TCPConcurrent)
	encoded, err := json.Marshal(options.TCPConcurrent)
	require.NoError(t, err)
	require.JSONEq(t, `true`, string(encoded))

	options = option.DNSOptions{}
	require.NoError(t, json.Unmarshal([]byte(`{"tcp_concurrent": {"enabled": true, "attempt_delay": "100ms", "max_concurrent": 4}}`), &options))
	require.True(t, options.TCPConcurrent.Enabled)
	require.Equal(t, badoption.Duration(100*time.Millisecond), *options.TCPConcurrent.AttemptDelay)
	require.Equal(t, uint32(4), options.TCPConcurrent.MaxConcurrent)
	encoded, err = json.Marshal(options.TCPConcurrent)
	require.NoError(t, err)
	require.JSONEq(t, `{"enabled": true, "attempt_delay": "100ms", "max_concurrent": 4}`, string(encoded))

	require.Error(t, json.Unmarshal([]byte(`{"tcp_concurrent": {"enabled": true, "unknown": 1}}`), &option.DNSOptions{}))

	_, err = NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true, AttemptDelay: concurrentTestDuration(-time.Second)})
	require.Error(t, err)
}

func TestTCPConcurrentStatisticsAndStatus(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{MaxConcurrent: 3})
	dialer := newConcurrentTestDialer()
	refused := errors.New("connection refused")
	dialer.failAfter(testAddress4A, 0, refused)
	dialer.succeedAfter(testAddress4B, 20*time.Millisecond)
	dialer.succeedIgnoringCancel(testAddress4C, 60*time.Millisecond)

	conn, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)
	require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
	require.Eventually(t, func() bool { return concurrent.Statistics().LateClosed == 1 }, time.Second, 5*time.Millisecond)

	// The remembered winner connects alone during its head start.
	dialer.succeedAfter(testAddress4B, 0)
	_, err = concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B, testAddress4C}, false, dialer.dial)
	require.NoError(t, err)

	statistics := concurrent.Statistics()
	require.Equal(t, uint64(2), statistics.Races)
	require.Equal(t, uint64(1), statistics.HistoryHits)
	require.Equal(t, uint64(0), statistics.RaceFailures)
	require.Equal(t, uint64(4), statistics.Attempts)
	require.Equal(t, uint64(1), statistics.Failures)
	require.Equal(t, uint64(1), statistics.Canceled)
	require.Equal(t, []uint64{1, 1, 0, 0}, statistics.Wins, "the first race was won by its second attempt, the second by its first")
	require.Positive(t, statistics.AverageConnectTime)
	require.Equal(t, statistics.ConnectTime/2, statistics.AverageConnectTime)

	status := concurrent.Status()
	require.True(t, status.Enabled)
	require.False(t, status.FixedDelay)
	require.Equal(t, 3, status.MaxConcurrent)
	require.Len(t, status.Destinations, 1)
	require.Equal(t, "example.com", status.Destinations[0].Host)
	require.Equal(t, uint16(443), status.Destinations[0].Port)
	require.Equal(t, testAddress4B, status.Destinations[0].Address)
	require.WithinDuration(t, time.Now().Add(concurrentWinnerLifetime), status.Destinations[0].ExpiresAt, 5*time.Second)
	require.Equal(t, []TCPConcurrentFailure{{Address: netip.AddrPortFrom(testAddress4A, 443), ExpiresAt: status.Failures[0].ExpiresAt}}, status.Failures)
	destinations, failures := concurrent.HistorySize()
	require.Equal(t, 1, destinations)
	require.Equal(t, 1, failures)

	concurrent.ResetHistory()
	status = concurrent.Status()
	require.Empty(t, status.Destinations)
	require.Empty(t, status.Failures)
	require.Equal(t, uint64(2), status.Statistics.Races, "statistics survive a history reset")
}

func TestTCPConcurrentRaceFailureCounted(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	dialer := newConcurrentTestDialer()
	dialer.failAfter(testAddress4A, 0, errors.New("refused"))
	dialer.failAfter(testAddress4B, 0, errors.New("refused"))
	_, err := concurrent.Dial(context.Background(), testDomain, []netip.Addr{testAddress4A, testAddress4B}, false, dialer.dial)
	require.Error(t, err)
	statistics := concurrent.Statistics()
	require.Equal(t, uint64(1), statistics.RaceFailures)
	require.Equal(t, uint64(2), statistics.Failures)
	require.Equal(t, []uint64{0, 0, 0, 0}, statistics.Wins)
	require.Zero(t, statistics.AverageConnectTime)
}

func TestTCPConcurrentPolicy(t *testing.T) {
	concurrent := newTestTCPConcurrent(t, option.TCPConcurrentOptions{})
	enabled, disabled := true, false
	require.True(t, TCPConcurrentPolicy{instance: concurrent}.Enabled())
	require.False(t, TCPConcurrentPolicy{instance: concurrent, override: &disabled}.Enabled())
	concurrent.SetEnabled(false)
	require.False(t, TCPConcurrentPolicy{instance: concurrent}.Enabled())
	require.True(t, TCPConcurrentPolicy{instance: concurrent, override: &enabled}.Enabled())
	require.False(t, TCPConcurrentPolicy{override: &enabled}.Enabled(), "without an instance nothing races")
	require.False(t, TCPConcurrentPolicy{}.Enabled())
	require.False(t, TCPConcurrentPolicy{instance: concurrent, override: &enabled}.applies(N.NetworkUDP, []netip.Addr{testAddress4A, testAddress4B}))
	require.False(t, TCPConcurrentPolicy{instance: concurrent, override: &enabled}.applies(N.NetworkTCP, []netip.Addr{testAddress4A}))
	require.True(t, TCPConcurrentPolicy{instance: concurrent, override: &enabled}.applies("tcp4", []netip.Addr{testAddress4A, testAddress4B}))

	var nilInstance *TCPConcurrent
	require.False(t, nilInstance.Enabled())
	nilInstance.ResetHistory()
}
