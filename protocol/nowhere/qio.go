//go:build with_quic

package nowhere

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	quicpkg "github.com/sagernet/sing-box/protocol/nowhere/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// nowhereV3MaxDatagramSize matches the reference CLI: the vendored core only
// uses datagrams for UDP flows and never needs the path MTU.
const nowhereV3MaxDatagramSize = 1200

// qioStream adapts *quic.Stream to the vendored qio.Stream. quic-go's Close
// sends FIN and keeps the receive side open, which is exactly CloseWrite; a
// full Close additionally aborts the receive side, like the reference CLI.
type qioStream struct {
	*quic.Stream
}

func (s *qioStream) CloseWrite() error { return s.Stream.Close() }

func (s *qioStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func (s *qioStream) ID() uint64 { return uint64(s.Stream.StreamID()) }

// qioConn adapts *quic.Conn to the vendored qio.Conn.
type qioConn struct {
	conn *quic.Conn
}

var _ qio.Conn = (*qioConn)(nil)

func newQIOConn(conn *quic.Conn) *qioConn {
	return &qioConn{conn: conn}
}

func (c *qioConn) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *qioConn) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }

func (c *qioConn) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return (&state).ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
}

func (c *qioConn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &qioStream{Stream: stream}, nil
}

func (c *qioConn) OpenStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &qioStream{Stream: stream}, nil
}

func (c *qioConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *qioConn) SendDatagram(b []byte) error { return c.conn.SendDatagram(b) }

func (c *qioConn) MaxDatagramSize() int { return nowhereV3MaxDatagramSize }

func (c *qioConn) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *qioConn) Context() context.Context { return c.conn.Context() }
func (c *qioConn) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

// qioListener adapts *quic.Listener to the vendored qio.Listener.
type qioListener struct {
	listener          *quic.Listener
	congestionControl quicsettings.CongestionControl
}

var _ qio.Listener = (*qioListener)(nil)

func newQIOListener(listener *quic.Listener, congestionControl quicsettings.CongestionControl) *qioListener {
	return &qioListener{listener: listener, congestionControl: congestionControl}
}

func (l *qioListener) Accept(ctx context.Context) (qio.Conn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	conn.SetCongestionControl(quicpkg.NewCongestionController(ctx, conn, l.congestionControl))
	return newQIOConn(conn), nil
}

func (l *qioListener) Close() error { return l.listener.Close() }

// connectedPacketConn presents a connected UDP socket as a net.PacketConn so
// the Nowhere 3 Morph wrapper can seal it below QUIC.
type connectedPacketConn struct {
	net.Conn
	remote net.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

// dialNowhereV3QUICCarrier opens the QUIC carrier for the Vector/Egress client.
// Morph seals the packet socket below QUIC on the host side; the TLS config
// already pins TLS 1.3 and ALPN nw3 with session resumption disabled.
func dialNowhereV3QUICCarrier(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, tlsConfig *tls.Config, quicOptions option.QUICOptions, congestionControl quicsettings.CongestionControl, keys *morph.Keys) (qio.Conn, error) {
	conn, err := dialer.DialContext(ctx, "udp", destination)
	if err != nil {
		return nil, err
	}
	qtls.SetDesiredBufferSizes(conn)
	remote := conn.RemoteAddr()
	var packetConn net.PacketConn = &connectedPacketConn{Conn: conn, remote: remote}
	if keys != nil {
		packetConn = morph.WrapPacketConn(packetConn, *keys, true)
	}
	qconn, err := quic.Dial(ctx, packetConn, remote, tlsConfig, quicpkg.BuildQUICConfig(quicOptions))
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	qconn.SetCongestionControl(quicpkg.NewCongestionController(ctx, qconn, congestionControl))
	return newQIOConn(qconn), nil
}

// listenNowhereV3QUIC starts the non-Early QUIC listener for the Portal.
func listenNowhereV3QUIC(ctx context.Context, packetConn net.PacketConn, tlsConfig *tls.Config, quicOptions option.QUICOptions, congestionControl quicsettings.CongestionControl) (qio.Listener, error) {
	transport := &quic.Transport{
		Conn:                packetConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	// The transport is built here instead of through qtls, so apply the
	// listener's udp_gso policy the same way qtls.Listen does.
	listener, err := transport.Listen(tlsConfig, qtls.ConfigWithGSO(quicpkg.BuildQUICConfig(quicOptions), packetConn))
	if err != nil {
		return nil, err
	}
	return newQIOListener(listener, congestionControl), nil
}
