// Package mux implements the Nowhere 2 TLS Mux stream engine.
//
// AuthFrame and the 0xff marker are consumed before Start. The reconstructed
// logical stream then carries FlowHeader, Target, SetupResult, and payload.
package mux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	// FrameBytes is the sender cap per DATA payload.
	FrameBytes = 32 * 1024
	mib        = 1024 * 1024
	// BaseStreamWindowBytes is the OPEN initial stream receive window.
	BaseStreamWindowBytes = 4 * mib
	// BaseConnectionWindowBytes is the initial connection receive window.
	BaseConnectionWindowBytes = 8 * mib
	maxStreamWindowBytes      = 16 * mib
	maxConnectionWindowBytes  = 32 * mib
	creditUnitBytes           = 1024
	windowUpdateDivisor       = 8
	activeStreamResourceLimit = 4096

	// IdleTimeout closes an authenticated Mux carrier with no active streams.
	IdleTimeout = 30 * time.Second
)

var (
	errClosed         = errors.New("nowhere: mux carrier is closed")
	errWindowExceeded = errors.New("nowhere: peer exceeded mux window")
	errWindowOverflow = errors.New("nowhere: mux window overflow")
	errStreamLimit    = errors.New("nowhere: mux stream limit reached")
	errFlowExists     = errors.New("nowhere: mux flow already exists")
	errInvalidLimits  = errors.New("nowhere: invalid mux limits")
	errReset          = errors.New("nowhere: mux flow reset")
	errInvalidFlowID  = errors.New("nowhere: mux flow id out of range")
	errInterrupted    = errors.New("nowhere: mux wait interrupted")
	errUnknownFlow    = errors.New("nowhere: DATA frame for unknown mux flow")
	errDataAfterFin   = errors.New("nowhere: DATA received after mux FIN")
)

// Config is the per-carrier Mux window and queue budget.
type Config struct {
	StreamWindowBytes     int
	ConnectionWindowBytes int
	MaxStreams            int
	OutboundFrames        int
}

// DefaultConfig returns the protocol defaults (16/32 MiB throughput profile).
func DefaultConfig() Config {
	return Config{
		StreamWindowBytes:     maxStreamWindowBytes,
		ConnectionWindowBytes: maxConnectionWindowBytes,
		MaxStreams:            activeStreamResourceLimit,
		OutboundFrames:        512,
	}
}

func (c Config) validate() (Config, error) {
	if c.StreamWindowBytes < BaseStreamWindowBytes ||
		c.StreamWindowBytes > maxStreamWindowBytes ||
		c.ConnectionWindowBytes < BaseConnectionWindowBytes ||
		c.ConnectionWindowBytes > maxConnectionWindowBytes ||
		c.StreamWindowBytes%creditUnitBytes != 0 ||
		c.ConnectionWindowBytes%creditUnitBytes != 0 ||
		c.ConnectionWindowBytes < c.StreamWindowBytes ||
		c.MaxStreams <= 0 ||
		c.OutboundFrames <= 0 {
		return Config{}, errInvalidLimits
	}
	return c, nil
}

func creditUnits(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	return (bytes + creditUnitBytes - 1) / creditUnitBytes
}

func frameCharge(payload int) int {
	return creditUnits(payload)
}

func inboundQueueDepth(config Config) int {
	n := config.StreamWindowBytes / FrameBytes
	if n < 64 {
		n = 64
	}
	return n
}

// Handle is one authenticated Mux TLS carrier.
type Handle struct {
	shared *shared
}

// Incoming accepts peer-opened streams. Client shards should Discard it.
type Incoming struct {
	ch     <-chan *Stream
	closed <-chan struct{}
	cancel context.CancelFunc
}

type inboundKind uint8

const (
	inboundData inboundKind = iota
	inboundFin
	inboundReset
)

type inbound struct {
	kind    inboundKind
	payload []byte
	charge  int
}

type outbound struct {
	header  wire.MuxHeader
	payload []byte
	release *semaphore
	flushed chan error
}

type flowState struct {
	inbound        chan inbound
	sendCredit     *semaphore
	sendSlot       *semaphore
	receiveCredit  int
	pendingReceive int
	windowQueued   bool
	localParts     uint8
	localFinSent   bool
	remoteFin      bool
	readerClosed   bool
}

type shared struct {
	config Config
	conn   net.Conn

	flowsMu sync.Mutex
	flows   map[uint32]*flowState

	connSend     *semaphore
	connSendPeak atomic.Int64
	connRecvMu   sync.Mutex
	connRecv     int
	pendingConn  atomic.Int64
	readyMu      sync.Mutex
	ready        []uint32

	dataTx   chan outbound
	control  chan struct{}
	incoming chan *Stream

	activeNotify chan struct{}

	closed   atomic.Bool
	closedCh chan struct{}
	closeMu  sync.Mutex

	local  net.Addr
	remote net.Addr
}

// Start runs reader and writer tasks on conn.
func Start(conn net.Conn, config Config) (*Handle, *Incoming, error) {
	if conn == nil {
		return nil, nil, errors.New("nowhere: nil mux connection")
	}
	config, err := config.validate()
	if err != nil {
		return nil, nil, err
	}
	incomingCtx, incomingCancel := context.WithCancel(context.Background())
	baseConn := creditUnits(BaseConnectionWindowBytes)
	shared := &shared{
		config:       config,
		conn:         conn,
		flows:        make(map[uint32]*flowState),
		connSend:     newSemaphore(baseConn),
		connRecv:     creditUnits(config.ConnectionWindowBytes),
		dataTx:       make(chan outbound, config.OutboundFrames),
		control:      make(chan struct{}, 1),
		incoming:     make(chan *Stream, config.MaxStreams),
		activeNotify: make(chan struct{}, 1),
		closedCh:     make(chan struct{}),
		local:        conn.LocalAddr(),
		remote:       conn.RemoteAddr(),
	}
	shared.connSendPeak.Store(int64(baseConn))
	extraConn := creditUnits(config.ConnectionWindowBytes - BaseConnectionWindowBytes)
	if extraConn > 0 {
		shared.pendingConn.Store(int64(extraConn))
	}
	handle := &Handle{shared: shared}
	incoming := &Incoming{ch: shared.incoming, closed: shared.closedCh, cancel: incomingCancel}
	go shared.runReader(conn)
	go shared.runWriter(conn)
	go func() {
		<-incomingCtx.Done()
		shared.rejectIncoming()
	}()
	if extraConn > 0 {
		shared.notifyControl()
	}
	return handle, incoming, nil
}

func (s *shared) rejectIncoming() {
	s.flowsMu.Lock()
	s.incoming = nil
	s.flowsMu.Unlock()
}

// OpenStream creates a local stream and emits OPEN.
func (h *Handle) OpenStream(flowID uint32) (*Stream, error) {
	if h == nil || h.shared == nil {
		return nil, errClosed
	}
	stream, err := h.shared.insertFlow(flowID, false)
	if err != nil {
		return nil, err
	}
	extra := creditUnits(h.shared.config.StreamWindowBytes - BaseStreamWindowBytes)
	header, err := wire.OpenMuxHeader(flowID, extra)
	if err != nil {
		h.shared.removeFlow(flowID)
		return nil, err
	}
	if err := h.shared.sendOutbound(outbound{header: header}, nil); err != nil {
		h.shared.removeFlow(flowID)
		return nil, err
	}
	return stream, nil
}

func (h *Handle) IsClosed() bool {
	return h == nil || h.shared == nil || h.shared.closed.Load()
}

func (h *Handle) ActiveStreams() int {
	if h == nil || h.shared == nil {
		return 0
	}
	h.shared.flowsMu.Lock()
	n := activeFlowCount(h.shared.flows)
	h.shared.flowsMu.Unlock()
	return n
}

// CanOpenFlow reports whether this carrier may still admit flowID: it is
// open, under the retained-state ceiling, and not already holding protocol
// state for that ID.
func (h *Handle) CanOpenFlow(flowID uint32) bool {
	if h == nil || h.shared == nil || h.shared.closed.Load() {
		return false
	}
	h.shared.flowsMu.Lock()
	defer h.shared.flowsMu.Unlock()
	return len(h.shared.flows) < h.shared.config.MaxStreams && h.shared.flows[flowID] == nil
}

// Pressure is the max occupancy of send credit, receive credit, and outbound
// frame slots, in 1/1024 units. Used by the client pool at capacity.
func (h *Handle) Pressure() int {
	if h == nil || h.shared == nil {
		return 0
	}
	available := h.shared.connSend.availablePermits()
	peak := int(h.shared.connSendPeak.Load())
	h.shared.connRecvMu.Lock()
	receive := h.shared.connRecv
	h.shared.connRecvMu.Unlock()
	receivePeak := creditUnits(h.shared.config.ConnectionWindowBytes)
	queue := h.shared.config.OutboundFrames
	occupancy := func(free, total int) int {
		if total <= 0 {
			return 0
		}
		used := total - free
		if used < 0 {
			used = 0
		}
		return used * 1024 / total
	}
	p := occupancy(available, peak)
	if r := occupancy(receive, receivePeak); r > p {
		p = r
	}
	if q := occupancy(cap(h.shared.dataTx)-len(h.shared.dataTx), queue); q > p {
		p = q
	}
	return p
}

func (h *Handle) Close() {
	if h == nil || h.shared == nil {
		return
	}
	h.shared.close()
}

func (h *Handle) SameCarrier(other *Handle) bool {
	return h != nil && other != nil && h.shared != nil && h.shared == other.shared
}

// IdleFor reports whether the carrier stays at zero streams for duration.
func (h *Handle) IdleFor(ctx context.Context, duration time.Duration) bool {
	if h == nil || h.shared == nil {
		return false
	}
	for {
		if h.IsClosed() {
			return false
		}
		if h.ActiveStreams() != 0 {
			select {
			case <-ctx.Done():
				return false
			case <-h.shared.closedCh:
				return false
			case <-h.shared.activeNotify:
			}
			continue
		}
		timer := time.NewTimer(duration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-h.shared.closedCh:
			timer.Stop()
			return false
		case <-h.shared.activeNotify:
			timer.Stop()
		case <-timer.C:
			if h.ActiveStreams() == 0 && !h.IsClosed() {
				return true
			}
		}
	}
}

func (h *Handle) Closed() <-chan struct{} {
	if h == nil || h.shared == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.shared.closedCh
}

func (in *Incoming) Accept(ctx context.Context) (*Stream, error) {
	if in == nil {
		return nil, errClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-in.closed:
		return nil, errClosed
	case stream, ok := <-in.ch:
		if !ok {
			return nil, errClosed
		}
		return stream, nil
	}
}

func (in *Incoming) Discard() {
	if in != nil && in.cancel != nil {
		in.cancel()
	}
}

func (s *shared) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	close(s.closedCh)
	s.connSend.close()
	s.flowsMu.Lock()
	for _, flow := range s.flows {
		flow.sendCredit.close()
		flow.sendSlot.close()
	}
	s.flows = make(map[uint32]*flowState)
	s.flowsMu.Unlock()
	s.notifyActive()
	s.closeMu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.closeMu.Unlock()
}

func (s *shared) insertFlow(flowID uint32, advertiseWindow bool) (*Stream, error) {
	if flowID == 0 || flowID > wire.MaxFlowID {
		return nil, errInvalidFlowID
	}
	if s.closed.Load() {
		return nil, errClosed
	}
	s.flowsMu.Lock()
	if s.closed.Load() {
		s.flowsMu.Unlock()
		return nil, errClosed
	}
	if len(s.flows) >= s.config.MaxStreams {
		s.flowsMu.Unlock()
		return nil, errStreamLimit
	}
	if _, exists := s.flows[flowID]; exists {
		s.flowsMu.Unlock()
		return nil, errFlowExists
	}
	extra := 0
	if advertiseWindow {
		extra = creditUnits(s.config.StreamWindowBytes - BaseStreamWindowBytes)
	}
	state := &flowState{
		inbound:        make(chan inbound, inboundQueueDepth(s.config)),
		sendCredit:     newSemaphore(creditUnits(BaseStreamWindowBytes)),
		sendSlot:       newSemaphore(1),
		receiveCredit:  creditUnits(s.config.StreamWindowBytes),
		pendingReceive: extra,
		windowQueued:   advertiseWindow && extra != 0,
		localParts:     2,
	}
	s.flows[flowID] = state
	s.flowsMu.Unlock()
	s.notifyActive()
	if advertiseWindow && extra != 0 {
		s.readyMu.Lock()
		s.ready = append(s.ready, flowID)
		s.readyMu.Unlock()
		s.notifyControl()
	}
	return newStream(s, flowID, state.inbound), nil
}

func (s *shared) notifyActive() {
	select {
	case s.activeNotify <- struct{}{}:
	default:
	}
}

func (s *shared) notifyControl() {
	select {
	case s.control <- struct{}{}:
	default:
	}
}

func (s *shared) removeFlow(flowID uint32) *flowState {
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow != nil {
		delete(s.flows, flowID)
		flow.sendCredit.close()
		flow.sendSlot.close()
	}
	s.flowsMu.Unlock()
	s.notifyActive()
	return flow
}

type receiveTarget uint8

const (
	// receiveDeliver hands the frame to a live application reader.
	receiveDeliver receiveTarget = iota
	// receiveDiscard drops the frame for a flow the application fully
	// released; only connection credit is returned and the stream debit
	// stays behind to bound the discarded bytes.
	receiveDiscard
	// receiveAbandoned drops the frame because the read half closed while
	// its writer is still live; both receive windows are restored.
	receiveAbandoned
)

func (s *shared) admitReceive(flowID uint32, charge int) (receiveTarget, chan inbound, error) {
	s.connRecvMu.Lock()
	s.flowsMu.Lock()
	defer s.connRecvMu.Unlock()
	defer s.flowsMu.Unlock()
	flow := s.flows[flowID]
	if flow == nil {
		return receiveDeliver, nil, errUnknownFlow
	}
	if flow.remoteFin {
		return receiveDeliver, nil, errDataAfterFin
	}
	if flow.receiveCredit < charge || s.connRecv < charge {
		return receiveDeliver, nil, errWindowExceeded
	}
	flow.receiveCredit -= charge
	s.connRecv -= charge
	if flow.localParts == 0 {
		return receiveDiscard, nil, nil
	}
	if flow.readerClosed {
		return receiveAbandoned, nil, nil
	}
	return receiveDeliver, flow.inbound, nil
}

func (s *shared) releaseConnReceive(charge int) {
	if s.closed.Load() {
		return
	}
	s.connRecvMu.Lock()
	s.connRecv += charge
	maxConn := creditUnits(s.config.ConnectionWindowBytes)
	if s.connRecv > maxConn {
		s.connRecv = maxConn
	}
	s.connRecvMu.Unlock()
	previous := s.pendingConn.Add(int64(charge))
	connThreshold := creditUnits(s.config.ConnectionWindowBytes / windowUpdateDivisor)
	if connThreshold > 0xffff {
		connThreshold = 0xffff
	}
	if previous >= int64(connThreshold) {
		s.notifyControl()
	}
}

func (s *shared) releaseReceive(flowID uint32, charge int) {
	if s.closed.Load() {
		return
	}
	s.connRecvMu.Lock()
	s.connRecv += charge
	maxConn := creditUnits(s.config.ConnectionWindowBytes)
	if s.connRecv > maxConn {
		s.connRecv = maxConn
	}
	s.connRecvMu.Unlock()

	ready, notify := false, false
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow != nil && flow.localParts != 0 {
		flow.receiveCredit += charge
		maxStream := creditUnits(s.config.StreamWindowBytes)
		if flow.receiveCredit > maxStream {
			flow.receiveCredit = maxStream
		}
		flow.pendingReceive += charge
		if !flow.windowQueued {
			flow.windowQueued = true
			ready = true
		}
		threshold := creditUnits(s.config.StreamWindowBytes / windowUpdateDivisor)
		if threshold > 0xffff {
			threshold = 0xffff
		}
		notify = flow.pendingReceive >= threshold
	}
	s.flowsMu.Unlock()
	if ready {
		s.readyMu.Lock()
		s.ready = append(s.ready, flowID)
		s.readyMu.Unlock()
	}
	previous := s.pendingConn.Add(int64(charge))
	connThreshold := creditUnits(s.config.ConnectionWindowBytes / windowUpdateDivisor)
	if connThreshold > 0xffff {
		connThreshold = 0xffff
	}
	if notify || previous >= int64(connThreshold) {
		s.notifyControl()
	}
}

func (s *shared) releasePart(flowID uint32) {
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow == nil {
		s.flowsMu.Unlock()
		return
	}
	flush := flow.pendingReceive != 0
	if flow.localParts > 0 {
		flow.localParts--
	}
	if flow.localParts == 0 {
		flow.pendingReceive = 0
		flow.windowQueued = false
		if flow.remoteFin && flow.localFinSent {
			delete(s.flows, flowID)
			flow.sendCredit.close()
			flow.sendSlot.close()
		}
	}
	s.flowsMu.Unlock()
	s.notifyActive()
	if flush {
		s.notifyControl()
	}
}

// finishLocalFin retires retained flow state once the local FIN frame has
// actually been written to the carrier.
func (s *shared) finishLocalFin(flowID uint32) {
	s.flowsMu.Lock()
	if flow := s.flows[flowID]; flow != nil {
		flow.localFinSent = true
		if flow.localParts == 0 && flow.remoteFin {
			delete(s.flows, flowID)
			flow.sendCredit.close()
			flow.sendSlot.close()
		}
	}
	s.flowsMu.Unlock()
}

func activeFlowCount(flows map[uint32]*flowState) int {
	n := 0
	for _, flow := range flows {
		if flow.localParts != 0 {
			n++
		}
	}
	return n
}

func (s *shared) markReaderClosed(flowID uint32) {
	s.flowsMu.Lock()
	if flow := s.flows[flowID]; flow != nil {
		flow.readerClosed = true
	}
	s.flowsMu.Unlock()
}

func (s *shared) sendOutbound(item outbound, stop <-chan struct{}) error {
	select {
	case <-s.closedCh:
		return errClosed
	case <-stop:
		return errClosed
	case s.dataTx <- item:
		return nil
	}
}

func (s *shared) offerIncoming(stream *Stream) error {
	s.flowsMu.Lock()
	ch := s.incoming
	s.flowsMu.Unlock()
	if ch == nil {
		return errClosed
	}
	select {
	case <-s.closedCh:
		return errClosed
	case ch <- stream:
		return nil
	default:
		return errStreamLimit
	}
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
