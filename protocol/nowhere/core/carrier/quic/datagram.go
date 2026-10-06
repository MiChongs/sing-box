package quic

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// ErrDatagramMTUUnstable reports two consecutive TooLarge results for one UDP
// packet even after synchronously clamping and re-encoding at the new limit.
var ErrDatagramMTUUnstable = errors.New("nowhere: QUIC datagram MTU remained unstable after retry")

// DatagramTooLargeError is returned when a DATAGRAM exceeds the current path limit.
type DatagramTooLargeError struct {
	MaxDatagramSize int
	Cause           error
}

func (e *DatagramTooLargeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("nowhere: datagram too large (max %d): %v", e.MaxDatagramSize, e.Cause)
}

func (e *DatagramTooLargeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

const (
	// DatagramProbeCeiling bounds optimistic single-frame probes. Probing stays
	// inside classic Ethernet MTU territory; larger working sizes are picked up
	// directly from the transport-reported limit instead.
	DatagramProbeCeiling = 1500
	// DatagramProbeInterval rate-limits optimistic probes so a path that keeps
	// rejecting them pays at most one failed send per interval.
	DatagramProbeInterval = time.Second
)

// DatagramProber tracks the connection's effective maximum DATAGRAM payload.
// quic-go only reports the live limit through DatagramTooLargeError, so a
// static default (1200) would fragment every larger packet forever even after
// path MTU discovery raised the real limit. The prober mirrors the Rust
// reference behaviour (quinn reports max_datagram_size() live): when a packet
// would be fragmented and an optimistic single DATA frame fits under
// DatagramProbeCeiling, the caller may send it unfragmented once per interval;
// the result feeds back into MaxDatagramSize.
type DatagramProber struct {
	current func() int
	now     func() time.Time

	mu         sync.Mutex
	probed     int
	upperBound int
	lastProbe  time.Time
}

// NewDatagramProber wraps the transport-reported current maximum. current must
// return the latest clamped value (it shrinks on DatagramTooLargeError).
func NewDatagramProber(current func() int) *DatagramProber {
	return &DatagramProber{current: current, now: time.Now}
}

// MaxDatagramSize is the largest DATAGRAM payload known to fit the path: the
// transport-reported limit, raised by any successful optimistic probe.
func (p *DatagramProber) MaxDatagramSize() int {
	current := 0
	if p.current != nil {
		current = p.current()
	}
	p.mu.Lock()
	probed := p.probed
	upperBound := p.upperBound
	p.mu.Unlock()
	if probed > current {
		current = probed
	}
	if upperBound > 0 && (current == 0 || current > upperBound) {
		current = upperBound
	}
	return current
}

// EncodeUDPDataFragments plans one NOWU packet. It behaves exactly like
// wire.EncodeUDPDataFragments at MaxDatagramSize, except that a packet that
// would fragment may be returned as a single optimistic DATA probe frame; in
// that case probedSize > 0 and the caller MUST report the send outcome through
// NoteProbeSuccess or NoteProbeFailure.
func (p *DatagramProber) EncodeUDPDataFragments(flowID wire.FlowID, packetID uint32, payload []byte) (frames [][]byte, probedSize int, err error) {
	max := p.MaxDatagramSize()
	frameSize := len(payload) + wire.UDPHeaderLen
	if frameSize <= max {
		frame, err := wire.EncodeUDPData(flowID, payload)
		if err != nil {
			return nil, 0, err
		}
		return [][]byte{frame}, 0, nil
	}
	if frameSize <= DatagramProbeCeiling && p.allowProbe(frameSize) {
		frame, err := wire.EncodeUDPData(flowID, payload)
		if err != nil {
			return nil, 0, err
		}
		return [][]byte{frame}, frameSize, nil
	}
	frames, err = wire.EncodeUDPDataFragments(flowID, packetID, payload, max)
	return frames, 0, err
}

// NoteProbeSuccess records a working size; future packets up to it skip
// fragmentation.
func (p *DatagramProber) NoteProbeSuccess(size int) {
	p.mu.Lock()
	if size > p.probed {
		p.probed = size
	}
	p.mu.Unlock()
}

// NoteProbeFailure folds a rejected probe back to the transport-reported
// limit, which the transport has already clamped down.
func (p *DatagramProber) NoteProbeFailure() {
	if p.current == nil {
		return
	}
	current := p.current()
	p.mu.Lock()
	if current > 0 && current < p.probed {
		p.probed = current
	}
	p.mu.Unlock()
}

// NoteTooLarge immediately clamps this session's effective limit, independent
// of whether the host adapter updates CurrentMaxDatagramSize synchronously.
func (p *DatagramProber) NoteTooLarge(maxSize int) {
	if maxSize <= 0 {
		return
	}
	p.mu.Lock()
	if p.upperBound == 0 || maxSize < p.upperBound {
		p.upperBound = maxSize
	}
	if p.probed > maxSize {
		p.probed = maxSize
	}
	p.mu.Unlock()
}

// DatagramSendFunc sends one owned DATAGRAM frame.
type DatagramSendFunc func(context.Context, []byte) error

// PacketIDSource returns a fresh non-zero packet ID whenever fragmentation is
// actually required.
type PacketIDSource func() uint32

// SendUDPData is the sole outbound NOWU PMTU state machine. It lazily encodes
// and sends one frame at a time, clamps on TooLarge, then re-encodes once with
// a fresh packet ID. A second TooLarge is never treated as success.
func SendUDPData(
	ctx context.Context,
	send DatagramSendFunc,
	prober *DatagramProber,
	flowID wire.FlowID,
	nextPacketID PacketIDSource,
	payload []byte,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if send == nil {
		return errors.New("nowhere: nil QUIC datagram sender")
	}
	if prober == nil {
		return errors.New("nowhere: nil QUIC datagram prober")
	}
	if nextPacketID == nil {
		return errors.New("nowhere: nil packet ID source")
	}

	var firstTooLarge error
	for attempt := 0; attempt < 2; attempt++ {
		probedSize, err := prober.sendAttempt(ctx, send, flowID, nextPacketID, payload)
		if err == nil {
			if probedSize > 0 {
				prober.NoteProbeSuccess(probedSize)
			}
			return nil
		}
		var tooLarge *DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			return err
		}
		prober.NoteTooLarge(tooLarge.MaxDatagramSize)
		if probedSize > 0 {
			prober.NoteProbeFailure()
		}
		if attempt == 0 {
			firstTooLarge = err
			continue
		}
		return errors.Join(
			ErrDatagramMTUUnstable,
			fmt.Errorf("nowhere: initial datagram too large: %w", firstTooLarge),
			fmt.Errorf("nowhere: datagram retry too large: %w", err),
		)
	}
	return nil
}

func (p *DatagramProber) sendAttempt(
	ctx context.Context,
	send DatagramSendFunc,
	flowID wire.FlowID,
	nextPacketID PacketIDSource,
	payload []byte,
) (int, error) {
	maxSize := p.MaxDatagramSize()
	frameSize := len(payload) + wire.UDPHeaderLen
	if frameSize <= maxSize {
		frame, err := wire.EncodeUDPData(flowID, payload)
		if err != nil {
			return 0, err
		}
		return 0, send(ctx, frame)
	}
	if frameSize <= DatagramProbeCeiling && p.allowProbe(frameSize) {
		frame, err := wire.EncodeUDPData(flowID, payload)
		if err != nil {
			return 0, err
		}
		return frameSize, send(ctx, frame)
	}
	packetID := nextPacketID()
	err := wire.EncodeUDPDataFragmentsYield(flowID, packetID, payload, maxSize, func(frame []byte) error {
		return send(ctx, frame)
	})
	return 0, err
}

func (p *DatagramProber) allowProbe(size int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if size <= p.probed {
		return false
	}
	now := p.now()
	if !p.lastProbe.IsZero() && now.Sub(p.lastProbe) < DatagramProbeInterval {
		return false
	}
	p.lastProbe = now
	return true
}
