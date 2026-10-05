package encryption

import (
	"net"
	"reflect"
	"unsafe"

	_ "github.com/sagernet/sing-vmess/vless"
	N "github.com/sagernet/sing/common/network"
)

// visionTLSRegistry is the list of TLS-like connections XTLS Vision of
// sing-vmess can work on. Like Xray-core, Vision over VLESS Encryption uses the
// input and rawInput of CommonConn, and reads and writes the inner TLS records
// directly on the transport connection beneath it, so Vision works on every
// transport (XHTTP, WebSocket, gRPC, ...) once encryption is enabled.
//
//go:linkname visionTLSRegistry github.com/sagernet/sing-vmess/vless.tlsRegistry
var visionTLSRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	visionTLSRegistry = append(visionTLSRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		commonConn, loaded := N.CastReader[*CommonConn](conn)
		if !loaded {
			return
		}
		return true, commonConn.Conn, reflect.TypeOf(commonConn).Elem(), uintptr(unsafe.Pointer(commonConn))
	})
}
