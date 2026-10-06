//go:build with_quic

package quic

import (
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/morph"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
)

type packetConnBufferControl interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type packetConnWithBufferControl struct {
	net.PacketConn
	control packetConnBufferControl
}

// newQUICPacketConn adapts a connected UDP socket without inspecting QUIC payloads.
func newQUICPacketConn(conn net.Conn) net.PacketConn {
	packetConn := bufio.NewUnbindPacketConn(conn)
	control, loaded := common.Cast[packetConnBufferControl](conn)
	if !loaded {
		return packetConn
	}
	return &packetConnWithBufferControl{
		PacketConn: packetConn,
		control:    control,
	}
}

func (c *packetConnWithBufferControl) SetReadBuffer(size int) error {
	return c.control.SetReadBuffer(size)
}

func (c *packetConnWithBufferControl) SetWriteBuffer(size int) error {
	return c.control.SetWriteBuffer(size)
}

var _ net.PacketConn = (*packetConnWithBufferControl)(nil)

// morphPacketConn feeds a morph-sealed packet socket back through the
// connected net.Conn surface quic-go dials with. The underlying connected UDP
// socket preserves datagram boundaries, so every Read opens exactly one
// datagram and every Write seals exactly one.
type morphPacketConn struct {
	net.PacketConn
	raw net.Conn
}

// newMorphPacketConn XOR-transforms every datagram of a connected client UDP
// socket below QUIC: sends are sealed under udp c2s and receives opened under
// udp s2c. The shared key must match the Portal's morph setting.
func newMorphPacketConn(raw net.Conn, sharedKey []byte) net.Conn {
	packetConn := morph.WrapPacketConn(newQUICPacketConn(raw), morph.Derive(sharedKey), true)
	return &morphPacketConn{PacketConn: packetConn, raw: raw}
}

func (c *morphPacketConn) Read(payload []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(payload)
	return n, err
}

func (c *morphPacketConn) Write(payload []byte) (int, error) {
	return c.PacketConn.WriteTo(payload, c.raw.RemoteAddr())
}

func (c *morphPacketConn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

var _ net.Conn = (*morphPacketConn)(nil)
