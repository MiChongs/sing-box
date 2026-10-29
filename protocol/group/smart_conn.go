package group

import (
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/tcpinfo"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// smartFeedback observes one connection carried by a member and reports it
// to the engine: setup, first response, business RX, goodput windows and,
// on close, the judged outcome.
type smartFeedback struct {
	s       *Smart
	member  adapter.Outbound
	node    uint32
	meta    *smartDialMeta
	attempt *smart.Attempt
	conn    net.Conn // the member's conn, for TCP statistics

	start        time.Time
	setupLatency time.Duration

	tx, rx          atomic.Int64
	firstTXAt       atomic.Int64
	responseLatency atomic.Int64
	lastRXPublish   atomic.Int64

	winStart atomic.Int64
	winTX    atomic.Int64
	winRX    atomic.Int64

	upRate   smartRateWindow
	downRate smartRateWindow

	readErr     atomic.Pointer[error]
	writeErr    atomic.Pointer[error]
	degraded    atomic.Bool
	manualBlock atomic.Bool
	settled     atomic.Bool

	lossWindow tcpinfo.Info
	lossJudged bool

	info *smartConnInfo
}

func (s *Smart) newFeedback(member adapter.Outbound, node uint32, meta *smartDialMeta, attempt *smart.Attempt, start time.Time, setup time.Duration) *smartFeedback {
	fb := &smartFeedback{
		s:            s,
		member:       member,
		node:         node,
		meta:         meta,
		attempt:      attempt,
		start:        start,
		setupLatency: setup,
	}
	fb.winStart.Store(time.Now().UnixNano())
	fb.info = s.conns.add(fb)
	s.nodeLoad.inc(member.Tag())
	return fb
}

func (f *smartFeedback) onTX(n int64) {
	now := time.Now().UnixNano()
	f.tx.Add(n)
	f.firstTXAt.CompareAndSwap(0, now)
	f.winTX.Add(n)
	f.upRate.add(n, now)
	f.maybeWindow(now)
}

func (f *smartFeedback) onRX(n int64) {
	now := time.Now().UnixNano()
	f.rx.Add(n)
	if f.responseLatency.Load() == 0 {
		latency := max(time.Duration(now)-time.Duration(f.start.UnixNano()), time.Millisecond)
		if f.responseLatency.CompareAndSwap(0, int64(latency)) {
			f.attempt.Response(latency)
		}
	}
	f.winRX.Add(n)
	f.downRate.add(n, now)
	// Business progress: a receive after a send, published at most once
	// per second.
	if f.firstTXAt.Load() != 0 {
		last := f.lastRXPublish.Load()
		if (last == 0 || now-last >= int64(time.Second)) && f.lastRXPublish.CompareAndSwap(last, now) {
			f.attempt.RX(smart.MonoAt(time.Unix(0, now)))
		}
	}
	f.maybeWindow(now)
}

// maybeWindow publishes a goodput window of 1-10 seconds once a direction
// carried 64 KiB; an older window is discarded.
func (f *smartFeedback) maybeWindow(now int64) {
	start := f.winStart.Load()
	elapsed := time.Duration(now - start)
	if elapsed < time.Second {
		return
	}
	if elapsed > 10*time.Second {
		if f.winStart.CompareAndSwap(start, now) {
			f.winTX.Store(0)
			f.winRX.Store(0)
		}
		return
	}
	tx, rx := f.winTX.Load(), f.winRX.Load()
	if max(tx, rx) < 64*1024 || f.responseLatency.Load() == 0 || f.tx.Load() == 0 || f.rx.Load() == 0 {
		return
	}
	if f.winStart.CompareAndSwap(start, now) {
		f.winTX.Add(-tx)
		f.winRX.Add(-rx)
		f.attempt.Transfer(tx, rx, elapsed)
	}
}

func (f *smartFeedback) noteReadErr(err error) {
	if smartIgnorableErr(err) {
		return
	}
	f.readErr.CompareAndSwap(nil, &err)
}

func (f *smartFeedback) noteWriteErr(err error) {
	if smartIgnorableErr(err) {
		return
	}
	f.writeErr.CompareAndSwap(nil, &err)
}

func smartIgnorableErr(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
}

// close settles the connection once, in the background.
func (f *smartFeedback) close() {
	if !f.settled.CompareAndSwap(false, true) {
		return
	}
	f.s.conns.remove(f.info)
	f.s.nodeLoad.dec(f.member.Tag())
	go f.s.judge(f)
}

// smartRateWindow tracks the peak rate of one direction over 100 ms
// buckets within the last second (mihomo tracker rates), in bytes/s.
type smartRateWindow struct {
	access      sync.Mutex
	bucketStart int64
	bucketBytes int64
	peak        float64
}

func (w *smartRateWindow) add(n int64, now int64) {
	const bucket = int64(100 * time.Millisecond)
	w.access.Lock()
	if now-w.bucketStart >= bucket {
		if w.bucketStart != 0 {
			w.peak = math.Max(w.peak, float64(w.bucketBytes)*float64(time.Second)/float64(bucket))
		}
		w.bucketStart = now - now%bucket
		w.bucketBytes = 0
	}
	w.bucketBytes += n
	w.access.Unlock()
}

func (w *smartRateWindow) max() float64 {
	w.access.Lock()
	defer w.access.Unlock()
	const bucket = float64(100 * time.Millisecond)
	return math.Max(w.peak, float64(w.bucketBytes)*float64(time.Second)/bucket)
}

// smartConn reports a TCP connection's traffic. It keeps the extended
// buffer paths of the member's conn; upstream errors are recorded so a
// failure through the node can be told apart from the client going away.
type smartConn struct {
	N.ExtendedConn
	feedback *smartFeedback
}

func (c *smartConn) Read(p []byte) (int, error) {
	n, err := c.ExtendedConn.Read(p)
	if n > 0 {
		c.feedback.onRX(int64(n))
	}
	if err != nil && err != io.EOF {
		c.feedback.noteReadErr(err)
	}
	return n, err
}

func (c *smartConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.ExtendedConn.ReadBuffer(buffer)
	if err != nil {
		if err != io.EOF {
			c.feedback.noteReadErr(err)
		}
		return err
	}
	if buffer.Len() > 0 {
		c.feedback.onRX(int64(buffer.Len()))
	}
	return nil
}

func (c *smartConn) Write(p []byte) (int, error) {
	n, err := c.ExtendedConn.Write(p)
	if n > 0 {
		c.feedback.onTX(int64(n))
	}
	if err != nil {
		c.feedback.noteWriteErr(err)
	}
	return n, err
}

func (c *smartConn) WriteBuffer(buffer *buf.Buffer) error {
	n := int64(buffer.Len())
	err := c.ExtendedConn.WriteBuffer(buffer)
	if err != nil {
		c.feedback.noteWriteErr(err)
		return err
	}
	if n > 0 {
		c.feedback.onTX(n)
	}
	return nil
}

func (c *smartConn) Close() error {
	if !c.feedback.settled.Load() {
		c.feedback.captureTCP()
	}
	c.feedback.close()
	return c.ExtendedConn.Close()
}

func (c *smartConn) Upstream() any { return c.ExtendedConn }

// smartSpliceConn is smartConn over a raw socket: it exposes its counters so
// the copy loop can still splice, at the cost of not seeing upstream errors
// (mihomo skips its error observer for the same reason).
type smartSpliceConn struct {
	smartConn
}

func (c *smartSpliceConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.feedback.onRX}
}

func (c *smartSpliceConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.feedback.onTX}
}

func (s *Smart) wrapConn(conn net.Conn, fb *smartFeedback) net.Conn {
	fb.conn = conn
	wrapped := smartConn{ExtendedConn: bufio.NewExtendedConn(conn), feedback: fb}
	if _, raw := conn.(syscall.Conn); raw {
		return &smartSpliceConn{wrapped}
	}
	return &wrapped
}

// smartPacketConn reports a UDP association's traffic.
type smartPacketConn struct {
	net.PacketConn
	feedback *smartFeedback
}

func (c *smartPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.feedback.onRX(int64(n))
	}
	if err != nil && !smartICMPRefusal(err) {
		c.feedback.noteReadErr(err)
	}
	return n, addr, err
}

func (c *smartPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.feedback.onTX(int64(n))
	}
	if err != nil && !smartICMPRefusal(err) {
		c.feedback.noteWriteErr(err)
	}
	return n, err
}

func (c *smartPacketConn) Close() error {
	c.feedback.close()
	return c.PacketConn.Close()
}

func (c *smartPacketConn) Upstream() any { return c.PacketConn }

func smartICMPRefusal(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// smartConnInfo indexes a live connection for convergence closes.
type smartConnInfo struct {
	feedback *smartFeedback
	key      string
	wildcard string
	node     uint32
	closer   io.Closer
}

// smartConnRegistry holds the group's live connections by service key, so
// switching a key's exit can close its connections through other members.
type smartConnRegistry struct {
	access sync.Mutex
	byKey  map[string]map[*smartConnInfo]struct{}
}

func (r *smartConnRegistry) add(fb *smartFeedback) *smartConnInfo {
	info := &smartConnInfo{feedback: fb, key: fb.meta.smartTarget, wildcard: fb.meta.wildcard, node: fb.node}
	r.access.Lock()
	if r.byKey == nil {
		r.byKey = make(map[string]map[*smartConnInfo]struct{})
	}
	set := r.byKey[info.key]
	if set == nil {
		set = make(map[*smartConnInfo]struct{})
		r.byKey[info.key] = set
	}
	set[info] = struct{}{}
	r.access.Unlock()
	return info
}

func (r *smartConnRegistry) setCloser(info *smartConnInfo, closer io.Closer) {
	r.access.Lock()
	info.closer = closer
	r.access.Unlock()
}

func (r *smartConnRegistry) remove(info *smartConnInfo) {
	r.access.Lock()
	if set := r.byKey[info.key]; set != nil {
		delete(set, info)
		if len(set) == 0 {
			delete(r.byKey, info.key)
		}
	}
	r.access.Unlock()
}

// closeKey closes the connections of key; with keep set, only those
// carried by other members. Closed connections settle neutrally.
func (r *smartConnRegistry) closeKey(key string, keep uint32, keepSet bool) int {
	r.access.Lock()
	var victims []*smartConnInfo
	for info := range r.byKey[key] {
		if keepSet && info.node == keep {
			continue
		}
		victims = append(victims, info)
	}
	r.access.Unlock()
	return closeVictims(victims)
}

func (r *smartConnRegistry) closeMatching(match func(*smartConnInfo) bool) int {
	r.access.Lock()
	var victims []*smartConnInfo
	for _, set := range r.byKey {
		for info := range set {
			if match(info) {
				victims = append(victims, info)
			}
		}
	}
	r.access.Unlock()
	return closeVictims(victims)
}

func closeVictims(victims []*smartConnInfo) int {
	closed := 0
	for _, info := range victims {
		if info.closer == nil {
			continue
		}
		info.feedback.degraded.Store(true)
		_ = info.closer.Close()
		closed++
	}
	return closed
}

func (r *smartConnRegistry) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	n := 0
	for _, set := range r.byKey {
		n += len(set)
	}
	return n
}

// smartDestinationString renders a destination for logs.
func smartDestinationString(meta *smartDialMeta, destination M.Socksaddr) string {
	if meta != nil && meta.host != "" {
		return meta.host
	}
	return destination.String()
}
