package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// udpUplink is the write side of a UDP logical flow.
type udpUplink interface {
	WritePacket(p []byte) (int, error)
	ClosePacket() error
}

// udpDownlink is the read side of a UDP logical flow.
type udpDownlink interface {
	ReadPacket(p []byte) (int, error)
	ClosePacket() error
}

// uotStreamWriter serializes UoT packets (u16 length + payload). In 1.5 there
// is no explicit CLOSE frame: closing the writer closes the underlying stream,
// which the reader observes as a clean half-close (ReadUDPPacket returns nil).
type uotStreamWriter struct {
	conn      net.Conn
	mu        sync.Mutex
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (w *uotStreamWriter) WritePacket(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, net.ErrClosed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := wire.WriteUDPPacket(w.conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *uotStreamWriter) Close() error {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.mu.TryLock() {
			// Best-effort flush of any buffered data via a zero-deadline wake;
			// the real close below tears the stream down.
			_ = w.conn.SetWriteDeadline(time.Now())
			w.mu.Unlock()
		}
		w.closeErr = w.conn.Close()
	})
	return w.closeErr
}

// uotPacketConn adapts a UoT stream (u16 length + payload) to net.PacketConn.
type uotPacketConn struct {
	conn        net.Conn
	destination net.Addr
	readMu      sync.Mutex
	writerOnce  sync.Once
	writer      *uotStreamWriter
}

func newUOTPacketConn(conn net.Conn, destination net.Addr) *uotPacketConn {
	if destination == nil {
		destination = &net.UDPAddr{}
	}
	return &uotPacketConn{conn: conn, destination: destination}
}

func (c *uotPacketConn) streamWriter() *uotStreamWriter {
	c.writerOnce.Do(func() {
		c.writer = &uotStreamWriter{conn: c.conn}
	})
	return c.writer
}

func (c *uotPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	payload, err := wire.ReadUDPPacket(c.conn)
	if err != nil {
		return 0, nil, err
	}
	if payload == nil {
		// clean EOF: the peer half-closed the stream.
		return 0, nil, io.EOF
	}
	return copy(p, payload), c.destination, nil
}

func (c *uotPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.streamWriter().WritePacket(p)
}

func (c *uotPacketConn) Close() error {
	return c.streamWriter().Close()
}

func (c *uotPacketConn) LocalAddr() net.Addr {
	if c.conn.LocalAddr() != nil {
		return c.conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *uotPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *uotPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *uotPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var _ net.PacketConn = (*uotPacketConn)(nil)

// targetToAddr renders a typed target into a net.Addr for PacketConn bookkeeping.
// Domain targets resolve to a zero-IP placeholder (the host dials them later).
func targetToAddr(t wire.Target) net.Addr {
	port := int(t.Port)
	switch t.Type {
	case wire.TargetTypeIPv4, wire.TargetTypeIPv6:
		return &net.UDPAddr{IP: t.Addr.AsSlice(), Port: port}
	case wire.TargetTypeDomain:
		return &net.UDPAddr{IP: net.IPv4zero, Port: port}
	default:
		return &net.UDPAddr{}
	}
}

// targetString renders a target for diagnostics only; never parsed back.
func targetString(t wire.Target) string {
	switch t.Type {
	case wire.TargetTypeIPv4, wire.TargetTypeIPv6:
		return net.JoinHostPort(t.Addr.String(), itoaPort(t.Port))
	case wire.TargetTypeDomain:
		return net.JoinHostPort(t.Host, itoaPort(t.Port))
	default:
		return ""
	}
}

func itoaPort(port uint16) string {
	return itoa(int(port))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// quicPacketConn adapts a QUIC UDP logical flow (control stream + datagrams) to net.PacketConn.
type quicPacketConn struct {
	session      *qSessionHandle
	control      net.Conn
	flowID       wire.FlowID
	destination  net.Addr
	readMu       sync.Mutex
	writeMu      sync.Mutex
	closeOnce    sync.Once
	nextPacketID atomic.Uint32
}

type qSessionHandle struct {
	quic          *quicPreparedStream
	flow          *quicDatagramFlow
	flowID        wire.FlowID
	setupErr      error
	closed        atomic.Bool
	signalOnce    sync.Once
	done          chan struct{}
	readDeadline  *datagramDeadline
	writeDeadline *datagramDeadline
}

// preparedQUICDatagrams owns a downlink registration before the FlowHeader is
// committed. Close abandons only the local registration; Activate transfers it
// to a live qSessionHandle after READY.
type preparedQUICDatagrams struct {
	mu      sync.Mutex
	quic    *quicPreparedStream
	session *quicSessionMux
	flow    *quicDatagramFlow
	flowID  wire.FlowID
}

func newQSessionHandle(prep *quicPreparedStream, flow *quicDatagramFlow, flowID wire.FlowID, setupErr error) *qSessionHandle {
	return &qSessionHandle{
		quic:          prep,
		flow:          flow,
		flowID:        flowID,
		setupErr:      setupErr,
		done:          make(chan struct{}),
		readDeadline:  newDatagramDeadline(),
		writeDeadline: newDatagramDeadline(),
	}
}

func prepareQUICDatagrams(prep *quicPreparedStream, flowID wire.FlowID) (*preparedQUICDatagrams, error) {
	if prep == nil || prep.session == nil {
		return nil, errors.New("nowhere: nil quic session")
	}
	session, ok := prep.session.(*quicSessionMux)
	if !ok {
		return nil, errors.New("nowhere: quic session is not bundle managed")
	}
	flow, err := session.register(flowID)
	if err != nil {
		return nil, err
	}
	return &preparedQUICDatagrams{
		quic: prep, session: session, flow: flow, flowID: flowID,
	}, nil
}

func (p *preparedQUICDatagrams) Activate() (*qSessionHandle, error) {
	if p == nil {
		return nil, errors.New("nowhere: nil prepared QUIC UDP registration")
	}
	p.mu.Lock()
	if p.flow == nil || p.session == nil || p.quic == nil {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	flow, session, prep, flowID := p.flow, p.session, p.quic, p.flowID
	p.flow, p.session, p.quic = nil, nil, nil
	p.mu.Unlock()
	if !flow.markReady() {
		session.unregister(flowID, flow, net.ErrClosed)
		return nil, net.ErrClosed
	}
	return newQSessionHandle(prep, flow, flowID, nil), nil
}

func (p *preparedQUICDatagrams) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	flow, session, flowID := p.flow, p.session, p.flowID
	p.flow, p.session, p.quic = nil, nil, nil
	p.mu.Unlock()
	if flow != nil && session != nil {
		session.unregister(flowID, flow, net.ErrClosed)
	}
	return nil
}

func newQUICSendHandle(prep *quicPreparedStream, flowID wire.FlowID) *qSessionHandle {
	return newQSessionHandle(prep, nil, flowID, nil)
}

// datagramProber exposes the per-session DATAGRAM size prober when the handle
// rides on a bundle-managed mux. Other carriers keep the transport default.
func (h *qSessionHandle) datagramProber() *quic.DatagramProber {
	if h == nil || h.quic == nil {
		return nil
	}
	mux, ok := h.quic.session.(*quicSessionMux)
	if !ok || mux == nil {
		return nil
	}
	return mux.prober
}

func (h *qSessionHandle) recordUDPDrop(bytes int, direction, reason string) {
	if h == nil || h.quic == nil {
		return
	}
	mux, ok := h.quic.session.(*quicSessionMux)
	if !ok || mux == nil {
		return
	}
	mux.recordUDPDrop(h.flowID, bytes, direction, reason)
}

func newQUICPacketConn(handle *qSessionHandle, control net.Conn, target wire.Target) *quicPacketConn {
	flowID := wire.FlowID(0)
	if handle != nil {
		flowID = handle.flowID
	}
	return &quicPacketConn{
		session:     handle,
		control:     control,
		flowID:      flowID,
		destination: targetToAddr(target),
	}
}

func (c *quicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	payload, err := c.session.readPacket(context.Background())
	if err != nil {
		return 0, nil, err
	}
	return copy(p, payload), c.destination, nil
}

func (c *quicPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeQUICUDPPacket(c.session, c.flowID, &c.nextPacketID, p)
}

func writeQUICUDPPacket(session *qSessionHandle, flowID wire.FlowID, nextPacketID *atomic.Uint32, payload []byte) (int, error) {
	if err := session.stateError(); err != nil {
		return 0, err
	}
	prober := session.datagramProber()
	if prober == nil {
		prober = quic.NewDatagramProber(session.quic.MaxDatagramSize)
	}
	nextID := func() uint32 {
		packetID := nextPacketID.Add(1)
		if packetID == 0 {
			packetID = nextPacketID.Add(1)
		}
		return packetID
	}
	if err := quic.SendUDPData(context.Background(), session.sendDatagramContext, prober, flowID, nextID, payload); err != nil {
		// Align with Rust Vector: consecutive DatagramTooLarge after shrink+
		// resend drops only this packet. Keep the UDP flow and QUIC session.
		if errors.Is(err, quic.ErrDatagramMTUUnstable) {
			session.recordUDPDrop(len(payload), "uplink", "mtu_unstable")
			return len(payload), nil
		}
		return 0, err
	}
	return len(payload), nil
}

func (c *quicPacketConn) Close() (err error) {
	c.closeOnce.Do(func() {
		err = c.session.closePacket()
		if c.control != nil {
			err = errors.Join(err, c.control.Close())
		}
	})
	return err
}

func (c *quicPacketConn) LocalAddr() net.Addr {
	if c.session != nil && c.session.quic != nil {
		return c.session.quic.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *quicPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *quicPacketConn) SetReadDeadline(t time.Time) error {
	if err := c.session.setReadDeadline(t); err != nil {
		return err
	}
	if c.control != nil {
		return c.control.SetReadDeadline(t)
	}
	return nil
}

func (c *quicPacketConn) SetWriteDeadline(t time.Time) error {
	if err := c.session.setWriteDeadline(t); err != nil {
		return err
	}
	if c.control != nil {
		return c.control.SetWriteDeadline(t)
	}
	return nil
}

func (h *qSessionHandle) doneSignal() <-chan struct{} {
	h.signalOnce.Do(func() {
		if h.done == nil {
			h.done = make(chan struct{})
		}
		if h.closed.Load() {
			close(h.done)
		}
	})
	return h.done
}

func (h *qSessionHandle) markClosed() bool {
	if h == nil || h.closed.Swap(true) {
		return false
	}
	done := h.doneSignal()
	select {
	case <-done:
	default:
		close(h.done)
	}
	return true
}

func (h *qSessionHandle) setReadDeadline(t time.Time) error {
	if h == nil || h.closed.Load() {
		return net.ErrClosed
	}
	if err := h.readDeadline.set(t); err != nil {
		return err
	}
	if h.closed.Load() {
		h.readDeadline.close()
		return net.ErrClosed
	}
	return nil
}

func (h *qSessionHandle) setWriteDeadline(t time.Time) error {
	if h == nil || h.closed.Load() {
		return net.ErrClosed
	}
	if err := h.writeDeadline.set(t); err != nil {
		return err
	}
	if h.closed.Load() {
		h.writeDeadline.close()
		return net.ErrClosed
	}
	return nil
}

func (h *qSessionHandle) readPacket(ctx context.Context) ([]byte, error) {
	if h == nil {
		return nil, net.ErrClosed
	}
	if h.setupErr != nil {
		return nil, h.setupErr
	}
	if h.closed.Load() {
		return nil, net.ErrClosed
	}
	if h.flow == nil {
		return nil, errors.New("nowhere: quic udp flow is not registered")
	}
	return h.flow.readPacket(ctx, h.readDeadline)
}

func (h *qSessionHandle) stateError() error {
	if h == nil {
		return net.ErrClosed
	}
	if h.setupErr != nil {
		return h.setupErr
	}
	if h.closed.Load() {
		return net.ErrClosed
	}
	if h.flow != nil {
		select {
		case <-h.flow.done:
			return h.flow.closeCause()
		default:
		}
	}
	return nil
}

func (h *qSessionHandle) sendDatagramContext(ctx context.Context, frame []byte) error {
	if err := h.stateError(); err != nil {
		return err
	}
	if h.writeDeadline.expired() {
		return errDatagramDeadline
	}
	if h.quic == nil || h.quic.session == nil {
		return net.ErrClosed
	}
	if session, ok := h.quic.session.(*quicSessionMux); ok {
		return session.sendDatagram(ctx, h, frame, h.writeDeadline)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if at, _, _ := h.writeDeadline.snapshot(); !at.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, at)
		defer cancel()
	}
	if err := h.quic.SendDatagram(ctx, frame); err != nil {
		return err
	}
	if h.writeDeadline.expired() {
		return errDatagramDeadline
	}
	return nil
}

func (h *qSessionHandle) closePacket() error {
	if !h.markClosed() {
		return nil
	}
	h.readDeadline.close()
	h.writeDeadline.close()
	if h.flow != nil {
		h.flow.unregister(net.ErrClosed)
	}
	if h.quic == nil || h.quic.session == nil || h.flowID == 0 {
		return nil
	}
	if session, ok := h.quic.session.(*quicSessionMux); ok {
		return session.enqueueClose(h.flowID)
	}
	return nil
}

var _ net.PacketConn = (*quicPacketConn)(nil)

// flowIDer lets a prepared stream expose its flow id for datagram routing.
type flowIDer interface {
	flowID() wire.FlowID
}

var _ flowIDer = (*quicPreparedStream)(nil)
