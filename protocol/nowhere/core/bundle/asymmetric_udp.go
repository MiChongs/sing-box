package bundle

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

// --- asymmetric UDP packet conn ---

type asymmetricPacketConn struct {
	dest     wire.Target
	uplink   udpUplink
	downlink udpDownlink
	upCloser io.Closer
	dnCloser io.Closer
}

func (a *asymmetricPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := a.downlink.ReadPacket(p)
	if err != nil {
		return n, nil, err
	}
	return n, targetToAddr(a.dest), nil
}

func (a *asymmetricPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return a.uplink.WritePacket(p)
}

func (a *asymmetricPacketConn) Close() error {
	var errs []error
	errs = append(errs, a.uplink.ClosePacket())
	if a.upCloser != nil {
		errs = append(errs, a.upCloser.Close())
	}
	errs = append(errs, a.downlink.ClosePacket())
	if a.dnCloser != nil {
		errs = append(errs, a.dnCloser.Close())
	}
	return errors.Join(errs...)
}

func (a *asymmetricPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (a *asymmetricPacketConn) SetDeadline(t time.Time) error {
	if err := a.SetReadDeadline(t); err != nil {
		return err
	}
	return a.SetWriteDeadline(t)
}

func (a *asymmetricPacketConn) SetReadDeadline(t time.Time) error {
	if d, ok := a.downlink.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (a *asymmetricPacketConn) SetWriteDeadline(t time.Time) error {
	if d, ok := a.uplink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

var _ net.PacketConn = (*asymmetricPacketConn)(nil)

// --- UoT lanes ---

type uotLaneUplink struct {
	raw        net.Conn
	writerOnce sync.Once
	writer     *uotStreamWriter
}

func (u *uotLaneUplink) streamWriter() *uotStreamWriter {
	u.writerOnce.Do(func() {
		u.writer = &uotStreamWriter{conn: u.raw}
	})
	return u.writer
}

func (u *uotLaneUplink) WritePacket(p []byte) (int, error) {
	return u.streamWriter().WritePacket(p)
}

func (u *uotLaneUplink) ClosePacket() error { return u.streamWriter().Close() }

func (u *uotLaneUplink) SetWriteDeadline(t time.Time) error {
	return u.raw.SetWriteDeadline(t)
}

type uotLaneDownlink struct {
	raw net.Conn
	mu  sync.Mutex
}

func (d *uotLaneDownlink) ReadPacket(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	payload, err := wire.ReadUDPPacket(d.raw)
	if err != nil {
		return 0, err
	}
	if payload == nil {
		// clean EOF: peer half-closed.
		return 0, io.EOF
	}
	return copy(p, payload), nil
}

func (d *uotLaneDownlink) ClosePacket() error { return d.raw.Close() }

func (d *uotLaneDownlink) SetReadDeadline(t time.Time) error {
	return d.raw.SetReadDeadline(t)
}

// --- QUIC datagram lanes ---

type quicLaneUplink struct {
	prep   *qSessionHandle
	nextID atomic.Uint32
}

func (u *quicLaneUplink) WritePacket(p []byte) (int, error) {
	return writeQUICUDPPacket(u.prep, u.prep.flowID, &u.nextID, p)
}

func (u *quicLaneUplink) ClosePacket() error {
	return u.prep.closePacket()
}

func (u *quicLaneUplink) SetWriteDeadline(t time.Time) error {
	return u.prep.setWriteDeadline(t)
}

type quicLaneDownlink struct {
	prep *qSessionHandle
}

func (d *quicLaneDownlink) ReadPacket(p []byte) (int, error) {
	payload, err := d.prep.readPacket(context.Background())
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (d *quicLaneDownlink) ClosePacket() error {
	return d.prep.closePacket()
}

func (d *quicLaneDownlink) SetReadDeadline(t time.Time) error {
	return d.prep.setReadDeadline(t)
}
