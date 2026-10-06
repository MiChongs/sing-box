package nowhere

import (
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/morph"
)

// MorphSharedKey returns the hop password as a Morph key when enabled.
// An empty result leaves the TCP/QUIC carriers as bare TLS/QUIC (morph=0).
func MorphSharedKey(enabled bool, password string) []byte {
	if !enabled || password == "" {
		return nil
	}
	return []byte(password)
}

// WrapMorphPacketConn XOR-transforms every UDP datagram below QUIC. Client
// sockets seal under udp c2s and open under udp s2c; server sockets use the
// reverse pairing. Morph must be enabled on both ends of a hop.
func WrapMorphPacketConn(pc net.PacketConn, password string, client bool) net.PacketConn {
	if pc == nil || password == "" {
		return pc
	}
	return morph.WrapPacketConn(pc, morph.Derive([]byte(password)), client)
}

// WrapMorphTCPServer consumes the client Morph prelude and nonce, then
// XOR-transforms TLS bytes. An empty password leaves the connection as bare TLS.
// Morph must be enabled on both ends of a hop.
func WrapMorphTCPServer(conn net.Conn, password string) net.Conn {
	if conn == nil || password == "" {
		return conn
	}
	return morph.WrapTCPServer(conn, morph.Derive([]byte(password)))
}
