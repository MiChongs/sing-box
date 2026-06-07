package interrupt

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type Conn struct {
	net.Conn
	group   *Group
	element *list.Element[*groupConnItem]
}

func (c *Conn) Close() error {
	c.group.access.Lock()
	c.group.connections.Remove(c.element)
	c.group.access.Unlock()
	return c.Conn.Close()
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.Conn
}

type PacketConn struct {
	net.PacketConn
	group   *Group
	element *list.Element[*groupConnItem]
}

// ReadPacket / WritePacket：当底层 PacketConn 已实现 sing 的 N.PacketReader/Writer
// 接口时走零拷贝路径（重要：bindPacketConn、hy2 udp 包装等都依赖这个断言链）。
// 否则降级到标准 net.PacketConn ReadFrom/WriteTo。
func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packetReader, ok := c.PacketConn.(N.PacketReader); ok {
		return packetReader.ReadPacket(buffer)
	}
	_, addr, err := buffer.ReadPacketFrom(c.PacketConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), err
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if packetWriter, ok := c.PacketConn.(N.PacketWriter); ok {
		return packetWriter.WritePacket(buffer, destination)
	}
	defer buffer.Release()
	_, err := c.PacketConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packetReader, ok := c.PacketConn.(N.PacketReader); ok {
		return packetReader.ReadPacket(buffer)
	}
	_, addr, err := buffer.ReadPacketFrom(c.PacketConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), err
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if packetWriter, ok := c.PacketConn.(N.PacketWriter); ok {
		return packetWriter.WritePacket(buffer, destination)
	}
	defer buffer.Release()
	_, err := c.PacketConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *PacketConn) Close() error {
	c.group.access.Lock()
	c.group.connections.Remove(c.element)
	c.group.access.Unlock()
	return c.PacketConn.Close()
}

func (c *PacketConn) ReaderReplaceable() bool {
	return true
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return bufio.NewPacketConn(c.PacketConn)
}
