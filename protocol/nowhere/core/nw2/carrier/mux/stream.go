package mux

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

// Stream is one reconstructed Mux logical stream. It implements net.Conn.
type Stream struct {
	shared *shared
	flowID uint32
	// generation fences this handle against a reused flow ID (upstream
	// b4482fe). Captured when the flow state was reserved.
	generation uint64
	reset      *atomic.Bool
	local      net.Addr
	remote     net.Addr
	inbound    <-chan inbound

	readMu        sync.Mutex
	current       []byte
	currentCharge int
	currentOff    int
	eof           bool

	ctrlMu       sync.Mutex
	readDead     time.Time
	readerClosed bool
	readWait     chan struct{}
	writeDead    time.Time
	writeClosed  bool
	writeWait    chan struct{}

	writeMu      sync.Mutex
	terminalSent bool
}

func newStream(s *shared, flowID uint32, flow *flowState) *Stream {
	return &Stream{
		shared:     s,
		flowID:     flowID,
		generation: flow.generation,
		reset:      flow.reset,
		local:      s.local,
		remote:     s.remote,
		inbound:    flow.inbound,
		readWait:   make(chan struct{}),
		writeWait:  make(chan struct{}),
	}
}

func (st *Stream) FlowID() uint32 { return st.flowID }

func (st *Stream) broadcastLocked(wait *chan struct{}) {
	ch := *wait
	*wait = make(chan struct{})
	close(ch)
}

func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if st.reset.Load() {
			// Flow termination discards buffered DATA and returns its
			// connection credit once before failing the reader.
			st.discardBuffered()
			st.readMu.Lock()
			st.eof = true
			st.readMu.Unlock()
			return 0, errReset
		}
		st.readMu.Lock()
		if len(st.current) > st.currentOff {
			n := copy(p, st.current[st.currentOff:])
			st.currentOff += n
			if st.currentOff == len(st.current) {
				st.shared.releaseReceive(st.flowID, st.generation, st.currentCharge)
				st.current = nil
				st.currentCharge = 0
				st.currentOff = 0
			}
			st.readMu.Unlock()
			return n, nil
		}
		if st.eof {
			st.readMu.Unlock()
			return 0, io.EOF
		}
		st.readMu.Unlock()

		st.ctrlMu.Lock()
		if st.readerClosed {
			st.ctrlMu.Unlock()
			return 0, errClosed
		}
		st.ctrlMu.Unlock()

		msg, err := st.waitInbound()
		if err != nil {
			return 0, err
		}
		st.ctrlMu.Lock()
		closed := st.readerClosed
		st.ctrlMu.Unlock()
		if closed {
			if msg.kind == inboundData {
				st.shared.releaseReceive(st.flowID, st.generation, msg.charge)
			}
			return 0, errClosed
		}
		st.readMu.Lock()
		switch msg.kind {
		case inboundData:
			st.current = msg.payload
			st.currentCharge = msg.charge
			st.currentOff = 0
			st.readMu.Unlock()
		case inboundFin:
			st.eof = true
			st.readMu.Unlock()
			return 0, io.EOF
		case inboundReset:
			// The reset marker only wakes the reader; the loop top sees
			// the flag, discards buffered payloads, and fails.
			st.readMu.Unlock()
		default:
			st.readMu.Unlock()
		}
	}
}

// discardBuffered releases every DATA payload this stream still holds or has
// queued. Receive credit only returns to the connection window: the flow is
// gone, so its stream window is never replenished.
func (st *Stream) discardBuffered() {
	st.readMu.Lock()
	if st.current != nil {
		st.shared.releaseReceive(st.flowID, st.generation, st.currentCharge)
		st.current = nil
		st.currentCharge = 0
		st.currentOff = 0
	}
	st.readMu.Unlock()
	for {
		select {
		case msg, ok := <-st.inbound:
			if !ok {
				return
			}
			if msg.kind == inboundData {
				st.shared.releaseReceive(st.flowID, st.generation, msg.charge)
			}
		default:
			return
		}
	}
}

func (st *Stream) waitInbound() (inbound, error) {
	for {
		st.ctrlMu.Lock()
		if st.readerClosed {
			st.ctrlMu.Unlock()
			return inbound{}, errClosed
		}
		dead := st.readDead
		wait := st.readWait
		st.ctrlMu.Unlock()

		timer, timeout := deadlineChan(dead)
		select {
		case <-st.shared.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return inbound{}, errClosed
		case <-wait:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			if timer != nil {
				timer.Stop()
			}
			return inbound{}, os.ErrDeadlineExceeded
		case msg, ok := <-st.inbound:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				st.readMu.Lock()
				st.eof = true
				st.readMu.Unlock()
				return inbound{kind: inboundFin}, nil
			}
			return msg, nil
		}
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		if st.isWriteClosed() {
			return 0, errClosed
		}
		return 0, nil
	}
	written := 0
	for written < len(p) {
		if err := st.checkWriteDeadline(); err != nil {
			return written, err
		}
		if st.isWriteClosed() {
			if written == 0 {
				return 0, errClosed
			}
			return written, errClosed
		}
		chunk := p[written:]
		if len(chunk) > FrameBytes {
			chunk = chunk[:FrameBytes]
		}
		if err := st.shared.sendData(st, chunk); err != nil {
			if written == 0 {
				return 0, err
			}
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

func (st *Stream) isWriteClosed() bool {
	st.ctrlMu.Lock()
	defer st.ctrlMu.Unlock()
	return st.writeClosed
}

func (st *Stream) writeSnapshot() (<-chan struct{}, time.Time, bool) {
	st.ctrlMu.Lock()
	defer st.ctrlMu.Unlock()
	return st.writeWait, st.writeDead, st.writeClosed
}

func (st *Stream) checkWriteDeadline() error {
	st.ctrlMu.Lock()
	dead := st.writeDead
	st.ctrlMu.Unlock()
	if dead.IsZero() {
		return nil
	}
	if !time.Now().Before(dead) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (st *Stream) Close() error {
	err := st.CloseWrite()
	st.closeReader()
	return err
}

func (st *Stream) CloseWrite() error {
	st.ctrlMu.Lock()
	if st.writeClosed {
		st.ctrlMu.Unlock()
		return nil
	}
	st.writeClosed = true
	st.broadcastLocked(&st.writeWait)
	st.ctrlMu.Unlock()

	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	if st.terminalSent {
		return nil
	}
	if !st.shared.isCurrentFlow(st.flowID, st.generation) {
		// The flow was terminated (peer RESET or reuse); a FIN would write
		// into a different generation.
		st.terminalSent = true
		return errClosed
	}
	st.terminalSent = true
	header, err := wire.FinMuxHeader(st.flowID)
	if err != nil {
		st.shared.releasePart(st.flowID, st.generation)
		return err
	}
	sendErr := st.shared.sendOutbound(outbound{header: header, generation: st.generation}, nil)
	st.shared.releasePart(st.flowID, st.generation)
	return sendErr
}

func (st *Stream) CloseRead() error {
	st.closeReader()
	return nil
}

func (st *Stream) closeReader() {
	st.ctrlMu.Lock()
	if st.readerClosed {
		st.ctrlMu.Unlock()
		return
	}
	st.readerClosed = true
	st.broadcastLocked(&st.readWait)
	st.ctrlMu.Unlock()

	st.shared.markReaderClosed(st.flowID)

	st.readMu.Lock()
	defer st.readMu.Unlock()
	if st.current != nil {
		st.shared.releaseReceive(st.flowID, st.generation, st.currentCharge)
		st.current = nil
		st.currentCharge = 0
	}
	for {
		select {
		case msg, ok := <-st.inbound:
			if !ok {
				st.shared.releasePart(st.flowID, st.generation)
				return
			}
			if msg.kind == inboundData {
				st.shared.releaseReceive(st.flowID, st.generation, msg.charge)
			}
		default:
			st.shared.releasePart(st.flowID, st.generation)
			return
		}
	}
}

func (st *Stream) LocalAddr() net.Addr  { return st.local }
func (st *Stream) RemoteAddr() net.Addr { return st.remote }

func (st *Stream) SetDeadline(t time.Time) error {
	if err := st.SetReadDeadline(t); err != nil {
		return err
	}
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.ctrlMu.Lock()
	st.readDead = t
	st.broadcastLocked(&st.readWait)
	st.ctrlMu.Unlock()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.ctrlMu.Lock()
	st.writeDead = t
	st.broadcastLocked(&st.writeWait)
	st.ctrlMu.Unlock()
	return nil
}

func deadlineChan(t time.Time) (*time.Timer, <-chan time.Time) {
	if t.IsZero() {
		return nil, nil
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return nil, ch
	}
	timer := time.NewTimer(d)
	return timer, timer.C
}
