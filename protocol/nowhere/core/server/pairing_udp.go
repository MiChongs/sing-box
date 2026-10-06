package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	carrierquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	nowuDataHeaderLen      = wire.UDPFragmentHeaderLen
	defaultMaxDatagramSize = 1200
	udpCloseWriteTimeout   = 100 * time.Millisecond
)

// udpHalf is one side of an asymmetric UDP flow.
type udpHalf struct {
	Role     wire.FlowRole
	Uplink   udpUplink
	Downlink udpDownlink
}

type udpUplink interface {
	ReadPacket() ([]byte, error)
	Close() error
}

type udpDownlink interface {
	WritePacket(p []byte) error
	WriteClose() error
	Close() error
}

// pairedUDP is a completed UDP flow ready for routing.
type pairedUDP struct {
	FlowID      wire.FlowID
	Target      wire.Target
	Hops        uint8
	Uplink      udpUplink
	Downlink    udpDownlink
	IdleTimeout time.Duration
	Readiness   *flowReadiness
	Context     context.Context
	Release     func()
}

// SubmitUDP caches or pairs a UDP half. Completing half returns *pairedUDP;
// waiting half returns (nil, nil).
func (r *claimRegistry) SubmitUDP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target wire.Target, half udpHalf) (*pairedUDP, error) {
	return r.SubmitUDPWithSource(ctx, sessionID, header, target, half, nil, udpHalfTransport(header, half))
}

// SubmitUDPWithSource is SubmitUDP with optional source/transport diagnostics.
func (r *claimRegistry) SubmitUDPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target wire.Target, half udpHalf, source net.Addr, transport string) (*pairedUDP, error) {
	return r.SubmitUDPWithGeneration(ctx, sessionID, r.CurrentGeneration(sessionID), false, header, target, half, source, transport)
}

func (r *claimRegistry) SubmitUDPWithGeneration(ctx context.Context, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, target wire.Target, half udpHalf, source net.Addr, _ string) (*pairedUDP, error) {
	if header.Kind != wire.FlowKindUDP || header.FlowID == 0 {
		return nil, fmt.Errorf("%w: invalid UDP flow header", ErrUnsupportedFlow)
	}
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
		target = wire.Target{}
	}
	claim := flowClaim{
		SessionID: sessionID, FlowID: header.FlowID, Generation: generation, BoundGeneration: boundGeneration,
		Role: header.Role, Carrier: carrier,
		Metadata: claimMetadata{Kind: header.Kind, Uplink: header.Uplink, Downlink: header.Downlink, Hops: header.Hops},
		Target:   target, Stream: udpHalfResultConn(half), UDP: half, Source: source,
	}
	active, err := r.Submit(ctx, claim)
	if err != nil || active == nil {
		return nil, err
	}
	var uplink udpUplink
	var downlink udpDownlink
	if active.Duplex != nil {
		uplink = active.Duplex.UDP.Uplink
		downlink = active.Duplex.UDP.Downlink
	} else if active.Open != nil && active.Attach != nil {
		uplink = active.Open.UDP.Uplink
		downlink = active.Attach.UDP.Downlink
	}
	if uplink == nil || downlink == nil {
		err := fmt.Errorf("%w: incomplete UDP pair", ErrInvalidHandler)
		closeClaimedFlow(active, err)
		active.Release()
		return nil, err
	}
	return &pairedUDP{
		FlowID: header.FlowID, Target: active.Target, Hops: active.Metadata.Hops, Uplink: uplink, Downlink: downlink,
		Readiness: active.Readiness, Context: active.Context, Release: active.Release,
	}, nil
}

func udpHalfResultConn(half udpHalf) net.Conn {
	switch downlink := half.Downlink.(type) {
	case *tcpUDPDownlink:
		return downlink.conn
	case *quicUDPDownlink:
		return downlink.control
	default:
		return nil
	}
}

func udpHalfTransport(header wire.FlowHeader, half udpHalf) string {
	carrier := header.Uplink
	if half.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
	}
	switch carrier {
	case wire.CarrierQUIC:
		if half.Role == wire.FlowRoleAttach {
			return "quic"
		}
		return "udp"
	default:
		return "tcp"
	}
}

func closeUDPHalfWithError(half udpHalf, err error) {
	if half.Uplink != nil {
		if value, ok := half.Uplink.(*tcpUDPUplink); ok {
			closeConnWithError(value.conn, err)
		} else {
			_ = half.Uplink.Close()
		}
	}
	if half.Downlink != nil {
		if value, ok := half.Downlink.(*tcpUDPDownlink); ok {
			closeConnWithError(value.conn, err)
		} else {
			_ = half.Downlink.Close()
		}
	}
}

// --- TCP UoT halves ---

type tcpUDPUplink struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPUDPUplink(conn net.Conn) udpUplink { return &tcpUDPUplink{conn: conn} }

func (u *tcpUDPUplink) ReadPacket() ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	payload, err := wire.ReadUDPPacket(u.conn)
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, io.EOF
	}
	return payload, nil
}

func (u *tcpUDPUplink) Close() error { return u.conn.Close() }

type tcpUDPDownlink struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPUDPDownlink(conn net.Conn) udpDownlink { return &tcpUDPDownlink{conn: conn} }

func (d *tcpUDPDownlink) WritePacket(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return wire.WriteUDPPacket(d.conn, p)
}

func (d *tcpUDPDownlink) WriteClose() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if closer, ok := d.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return d.conn.Close()
}

func (d *tcpUDPDownlink) Close() error { return d.conn.Close() }

// --- QUIC DATAGRAM halves ---

type quicUDPDownlink struct {
	control         net.Conn
	send            func(context.Context, []byte) error
	maxDatagramSize func() int
	probe           *carrierquic.DatagramProber
	abort           func(error)
	closeOnce       sync.Once
}

func newQUICUDPDownlink(control net.Conn, send func(context.Context, []byte) error, maxDatagramSize func() int, probe *carrierquic.DatagramProber, abort ...func(error)) *quicUDPDownlink {
	var abortSession func(error)
	if len(abort) > 0 {
		abortSession = abort[0]
	}
	return &quicUDPDownlink{
		control: control, send: send, maxDatagramSize: maxDatagramSize, probe: probe, abort: abortSession,
	}
}

func (d *quicUDPDownlink) WritePacket([]byte) error {
	return fmt.Errorf("nowhere: quic downlink WritePacket requires paired wrapper")
}

func (d *quicUDPDownlink) WriteClose() error { return nil }

func (d *quicUDPDownlink) Close() error { return d.closeControl() }

func (d *quicUDPDownlink) closeControl() (err error) {
	d.closeOnce.Do(func() {
		if d.control != nil {
			err = d.control.Close()
		}
	})
	return err
}

type quicUDPDownlinkBound struct {
	flowID          wire.FlowID
	base            *quicUDPDownlink
	maxDatagramSize func() int
	probe           *carrierquic.DatagramProber
	nextPacketID    atomic.Uint32
	stateMu         sync.Mutex
	closed          bool
	terminalDone    chan struct{}
	terminalForce   chan struct{}
	terminalErr     error
	sendOnce        sync.Once
	sendToken       chan struct{}
}

func (d *quicUDPDownlinkBound) WritePacket(p []byte) error {
	if d.isClosed() {
		return net.ErrClosed
	}
	token := d.sendGate()
	<-token
	defer func() { token <- struct{}{} }()
	if d.isClosed() {
		return net.ErrClosed
	}
	if d.base == nil || d.base.send == nil {
		return net.ErrClosed
	}
	currentMax := d.maxDatagramSize
	if currentMax == nil && d.base != nil {
		currentMax = d.base.maxDatagramSize
	}
	prober := d.probe
	if prober == nil && d.base != nil {
		prober = d.base.probe
	}
	if prober == nil {
		prober = carrierquic.NewDatagramProber(func() int {
			if currentMax != nil {
				return currentMax()
			}
			return defaultMaxDatagramSize
		})
	}
	nextPacketID := func() uint32 {
		packetID := d.nextPacketID.Add(1)
		if packetID == 0 {
			packetID = d.nextPacketID.Add(1)
		}
		return packetID
	}
	return carrierquic.SendUDPData(context.Background(), d.base.send, prober, d.flowID, nextPacketID, p)
}

func (d *quicUDPDownlinkBound) WriteClose() error {
	return d.terminate(nil, true)
}

func (d *quicUDPDownlinkBound) Close() error {
	return d.terminate(markForcedTermination(net.ErrClosed), false)
}

func (d *quicUDPDownlinkBound) terminate(cause error, graceful bool) error {
	forced := isForcedTermination(cause)
	d.stateMu.Lock()
	if d.closed {
		if forced {
			d.forceTerminalLocked()
		}
		done := d.terminalDone
		d.stateMu.Unlock()
		if done != nil {
			<-done
		}
		d.stateMu.Lock()
		err := d.terminalErr
		d.stateMu.Unlock()
		return err
	}
	d.closed = true
	d.terminalDone = make(chan struct{})
	d.terminalForce = make(chan struct{})
	if forced {
		d.forceTerminalLocked()
	}
	done := d.terminalDone
	force := d.terminalForce
	d.stateMu.Unlock()

	err := d.runTerminal(cause, graceful, forced, force)
	d.stateMu.Lock()
	d.terminalErr = err
	close(done)
	d.stateMu.Unlock()
	return err
}

func (d *quicUDPDownlinkBound) runTerminal(cause error, graceful, forced bool, force <-chan struct{}) (err error) {
	token := d.sendGate()
	acquired := false
	select {
	case <-token:
		acquired = true
	default:
	}
	aborted := false
	if forced || !acquired {
		if d.base != nil && d.base.abort != nil {
			d.base.abort(markForcedTermination(cause))
			aborted = true
		}
		if !acquired {
			<-token
			acquired = true
		}
	}
	if acquired {
		defer func() { token <- struct{}{} }()
	}
	if graceful && !forced && !aborted && d.base != nil && d.base.send != nil {
		frame, encodeErr := wire.EncodeUDPClose(d.flowID)
		if encodeErr != nil {
			err = encodeErr
		} else {
			err = d.sendGracefulClose(frame[:], force)
		}
	}
	if d.base != nil {
		err = errors.Join(err, d.base.Close())
	}
	return err
}

func (d *quicUDPDownlinkBound) sendGracefulClose(frame []byte, force <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), udpCloseWriteTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		select {
		case <-force:
			if d.base.abort != nil {
				d.base.abort(markForcedTermination(ErrClosed))
			}
			cancel()
		case <-ctx.Done():
		case <-done:
		}
	}()
	err := d.base.send(ctx, frame)
	close(done)
	if errors.Is(err, context.DeadlineExceeded) && d.base.abort != nil {
		if d.base.abort != nil {
			d.base.abort(markForcedTermination(context.DeadlineExceeded))
		}
	}
	return err
}

func (d *quicUDPDownlinkBound) forceTerminalLocked() {
	if d.terminalForce == nil {
		return
	}
	select {
	case <-d.terminalForce:
	default:
		close(d.terminalForce)
	}
}

func (d *quicUDPDownlinkBound) isClosed() bool {
	d.stateMu.Lock()
	closed := d.closed
	d.stateMu.Unlock()
	return closed
}

func (d *quicUDPDownlinkBound) sendGate() chan struct{} {
	d.sendOnce.Do(func() {
		d.sendToken = make(chan struct{}, 1)
		d.sendToken <- struct{}{}
	})
	return d.sendToken
}

// pairedUDPConn exposes a pairedUDP as net.PacketConn.
type pairedUDPConn struct {
	flowID      wire.FlowID
	dest        net.Addr
	uplink      udpUplink
	downlink    udpDownlink
	release     func()
	closeMu     sync.Mutex
	closing     bool
	closeDone   chan struct{}
	ready       atomic.Bool
	readDL      deadlineSignal
	writeDL     deadlineSignal
	idle        *time.Timer
	idleTimeout time.Duration
	idleMu      sync.Mutex
}

// newPairedUDPConn adapts a pairedUDP to net.PacketConn.
func newPairedUDPConn(paired *pairedUDP) net.PacketConn {
	down := paired.Downlink
	if q, ok := down.(*quicUDPDownlink); ok {
		down = &quicUDPDownlinkBound{flowID: paired.FlowID, base: q, maxDatagramSize: q.maxDatagramSize, probe: q.probe}
	}
	dest := targetNetAddr(paired.Target)
	conn := &pairedUDPConn{
		flowID: paired.FlowID, dest: dest, uplink: paired.Uplink, downlink: down,
		release: paired.Release, idleTimeout: paired.IdleTimeout,
	}
	if conn.idleTimeout <= 0 {
		conn.idleTimeout = DefaultUDPIdleTimeout
	}
	conn.resetIdle()
	return conn
}

func (c *pairedUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.readDL.wait():
		return 0, nil, deadlineError()
	default:
	}
	payload, err := c.uplink.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	c.resetIdle()
	n = copy(p, payload)
	return n, c.dest, nil
}

func (c *pairedUDPConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-c.writeDL.wait():
		return 0, deadlineError()
	default:
	}
	if err := c.downlink.WritePacket(p); err != nil {
		return 0, err
	}
	c.resetIdle()
	return len(p), nil
}

func (c *pairedUDPConn) Close() error {
	c.closeWithError(nil)
	return nil
}

func (c *pairedUDPConn) markReady() {
	if c != nil {
		c.ready.Store(true)
		if flow, ok := c.uplink.(*nowuFlow); ok {
			flow.markReady()
		}
	}
}

func (c *pairedUDPConn) closeWithError(cause error) {
	forced := forcedUDPClosure(cause)
	c.closeMu.Lock()
	if c.closing {
		done := c.closeDone
		downlink, isQUIC := c.downlink.(*quicUDPDownlinkBound)
		c.closeMu.Unlock()
		if forced && isQUIC {
			_ = downlink.terminate(cause, false)
		}
		<-done
		return
	}
	c.closing = true
	done := make(chan struct{})
	c.closeDone = done
	c.closeMu.Unlock()

	c.idleMu.Lock()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idleMu.Unlock()
	c.readDL.stop()
	c.writeDL.stop()
	if downlink, ok := c.downlink.(*quicUDPDownlinkBound); ok {
		_ = downlink.terminate(cause, c.ready.Load() && !forced)
		closeUDPHalfWithError(udpHalf{Uplink: c.uplink}, cause)
	} else {
		if c.ready.Load() && c.downlink != nil && !forced {
			_ = c.downlink.WriteClose()
		}
		closeUDPHalfWithError(udpHalf{Uplink: c.uplink, Downlink: c.downlink}, cause)
	}
	if c.release != nil {
		c.release()
	}
	close(done)
}

func forcedUDPClosure(cause error) bool {
	return isForcedTermination(cause)
}

func (c *pairedUDPConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *pairedUDPConn) SetDeadline(value time.Time) error {
	if err := c.SetReadDeadline(value); err != nil {
		return err
	}
	return c.SetWriteDeadline(value)
}

func (c *pairedUDPConn) SetReadDeadline(value time.Time) error {
	c.readDL.set(value)
	if deadline, ok := c.uplink.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(value)
	}
	return nil
}

func (c *pairedUDPConn) SetWriteDeadline(value time.Time) error {
	c.writeDL.set(value)
	if deadline, ok := c.downlink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(value)
	}
	return nil
}

func (c *pairedUDPConn) resetIdle() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idle = time.AfterFunc(c.idleTimeout, func() { _ = c.Close() })
}

var _ net.PacketConn = (*pairedUDPConn)(nil)
