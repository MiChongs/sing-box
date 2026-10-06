package tcptls

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// carrierState tracks TLS/TCP carrier lifecycle for diagnostics only.
// After the first request frame a carrier is consumed and must not return to idle.
type carrierState uint8

const (
	stateNew               carrierState = iota
	stateAuthenticatedIdle              // warm pool; no request sent
	stateBorrowed                       // popped; about to send request
	stateRequestSent                    // request written; consumed
	stateConsumed
	stateActiveRelay
	stateClosing
	stateClosed
)

func (s carrierState) String() string {
	switch s {
	case stateNew:
		return "new"
	case stateAuthenticatedIdle:
		return "authenticated_idle"
	case stateBorrowed:
		return "borrowed"
	case stateRequestSent:
		return "request_sent"
	case stateConsumed:
		return "consumed"
	case stateActiveRelay:
		return "active_relay"
	case stateClosing:
		return "closing"
	case stateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Local log-correlation ids only; not sent on the wire.
var nextCarrierID atomic.Uint64

type carrierInfo struct {
	id        uint64
	state     atomic.Uint64 // carrierState
	createdAt time.Time
	log       carrier.Logger
}

func newCarrierInfo(log carrier.Logger) *carrierInfo {
	if log == nil {
		log = carrier.NopLogger{}
	}
	ci := &carrierInfo{
		id:        nextCarrierID.Add(1),
		createdAt: time.Now(),
		log:       log,
	}
	ci.state.Store(uint64(stateNew))
	return ci
}

func (c *carrierInfo) logger() carrier.Logger {
	if c != nil && c.log != nil {
		return c.log
	}
	return carrier.NopLogger{}
}

func (c *carrierInfo) stateOf() carrierState {
	return carrierState(c.state.Load())
}

// transition logs illegal edges but never panics (data path stays open).
func (c *carrierInfo) transition(next carrierState) {
	prev := c.stateOf()
	if !legalTransition(prev, next) {
		c.logger().Warnf("[Nowhere] [carrier] illegal transition carrier_id=%d %s -> %s (consumed-carrier reuse or double-borrow suspected)", c.id, prev, next)
	}
	c.state.Store(uint64(next))
}

func legalTransition(prev, next carrierState) bool {
	if next == stateClosing || next == stateClosed {
		return true
	}
	switch prev {
	case stateNew:
		return next == stateAuthenticatedIdle || next == stateBorrowed
	case stateAuthenticatedIdle:
		return next == stateBorrowed || next == stateAuthenticatedIdle
	case stateBorrowed:
		return next == stateRequestSent
	case stateRequestSent:
		return next == stateConsumed || next == stateActiveRelay
	case stateConsumed:
		// Never idle/borrowed again (pool-reuse bug).
		return next == stateActiveRelay
	case stateActiveRelay:
		return next == stateConsumed
	default:
		return false
	}
}

type trackedConn struct {
	net.Conn
	carrier      *carrierInfo
	flowID       wire.FlowID // local log id (symmetric)
	network      string      // "tcp" or "udp" (UoT)
	target       string
	openedAt     time.Time
	firstByteMs  atomic.Int64
	rxBytes      atomic.Uint64
	txBytes      atomic.Uint64
	sawRemoteEOF atomic.Bool
	closed       atomic.Bool
}

func newTrackedConn(conn net.Conn, ci *carrierInfo, flowID wire.FlowID, network, target string) *trackedConn {
	t := &trackedConn{
		Conn:     conn,
		carrier:  ci,
		flowID:   flowID,
		network:  network,
		target:   target,
		openedAt: time.Now(),
	}
	t.firstByteMs.Store(-1)
	return t
}

func (t *trackedConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.rxBytes.Add(uint64(n))
		if t.firstByteMs.Load() < 0 {
			t.firstByteMs.CompareAndSwap(-1, time.Since(t.openedAt).Milliseconds())
		}
	}
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		t.sawRemoteEOF.Store(true)
	}
	return n, err
}

func (t *trackedConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.txBytes.Add(uint64(n))
	}
	return n, err
}

func (t *trackedConn) CloseRead() error {
	if closer, ok := t.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return t.Close()
}

func (t *trackedConn) CloseWrite() error {
	if closer, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return t.Close()
}

func (t *trackedConn) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.carrier.transition(stateClosing)
	err := t.Conn.Close()
	t.carrier.transition(stateClosed)
	reason := "ok"
	if err != nil {
		_, class := diagnostic.ClassifyClose(err)
		if class != "" {
			reason = class
		} else {
			reason = err.Error()
		}
	} else if t.sawRemoteEOF.Load() {
		reason = diagnostic.ErrorClassRemoteClose
	}
	firstByte := t.firstByteMs.Load()
	if firstByte < 0 {
		firstByte = 0
	}
	t.carrier.logger().Debugf("[Nowhere] [carrier] relay_end flow_id=%d carrier_id=%d network=%s target=%s first_byte_ms=%d rx_bytes=%d tx_bytes=%d close_reason=%s",
		t.flowID, t.carrier.id, t.network, t.target, firstByte, t.rxBytes.Load(), t.txBytes.Load(), reason)
	return err
}
