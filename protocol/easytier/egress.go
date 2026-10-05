package easytier

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

const (
	egressPacketQueueSize = 128
	proxyNATAcceptBacklog = 128
)

func (e *Endpoint) egressMetadata(network string, destination M.Socksaddr) adapter.InboundContext {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Network = network
	metadata.Destination = destination
	return metadata
}

// routeEgressConnection hands a TCP connection opened by the core towards a
// real destination to the sing-box router and returns the core's side.
func (e *Endpoint) routeEgressConnection(destination M.Socksaddr) net.Conn {
	ctx := log.ContextWithNewID(e.ctx)
	coreConn, routedConn := pipe.Pipe()
	e.logger.InfoContext(ctx, "inbound connection from EasyTier core to ", destination)
	go e.router.RouteConnectionEx(ctx, routedConn, e.egressMetadata(N.NetworkTCP, destination), func(error) {})
	return &streamConn{
		Conn:       coreConn,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero},
		remoteAddr: net.TCPAddrFromAddrPort(destination.AddrPort()),
	}
}

type egressPacket struct {
	buffer  *buf.Buffer
	address M.Socksaddr
}

// egressPacketConn is the UDP socket the core uses to reach real
// destinations. The first datagram opens a sing-box routed session; a new
// session is opened when the router closes the previous one, for example
// after the UDP timeout.
type egressPacketConn struct {
	endpoint     *Endpoint
	ctx          context.Context
	cancel       context.CancelFunc
	access       sync.Mutex
	session      *egressPacketSession
	responses    chan egressPacket
	readDeadline pipe.Deadline
}

func (e *Endpoint) newEgressPacketConn() *egressPacketConn {
	ctx, cancel := context.WithCancel(e.ctx)
	return &egressPacketConn{
		endpoint:     e,
		ctx:          ctx,
		cancel:       cancel,
		responses:    make(chan egressPacket, egressPacketQueueSize),
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *egressPacketConn) currentSession(destination M.Socksaddr) *egressPacketSession {
	c.access.Lock()
	defer c.access.Unlock()
	if c.ctx.Err() != nil {
		return nil
	}
	if c.session != nil && c.session.ctx.Err() == nil {
		return c.session
	}
	ctx, cancel := context.WithCancel(log.ContextWithNewID(c.ctx))
	session := &egressPacketSession{
		conn:         c,
		ctx:          ctx,
		cancel:       cancel,
		requests:     make(chan egressPacket, egressPacketQueueSize),
		readDeadline: pipe.MakeDeadline(),
	}
	c.session = session
	endpoint := c.endpoint
	endpoint.logger.InfoContext(ctx, "inbound packet connection from EasyTier core to ", destination)
	go endpoint.router.RoutePacketConnectionEx(ctx, session, endpoint.egressMetadata(N.NetworkUDP, destination), func(error) {
		cancel()
	})
	return session
}

func (c *egressPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr).Unwrap()
	session := c.currentSession(destination)
	if session == nil {
		return 0, net.ErrClosed
	}
	buffer := buf.NewSize(len(p))
	_, _ = buffer.Write(p)
	select {
	case session.requests <- egressPacket{buffer: buffer, address: destination}:
	default:
		// The routed session is gone or congested; drop like a full socket
		// buffer would.
		buffer.Release()
	}
	return len(p), nil
}

func (c *egressPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.responses:
		n := copy(p, packet.buffer.Bytes())
		packet.buffer.Release()
		return n, udpAddrFrom(packet.address.UDPAddr()), nil
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *egressPacketConn) deliver(packet egressPacket) error {
	select {
	case c.responses <- packet:
		return nil
	case <-c.ctx.Done():
		packet.buffer.Release()
		return net.ErrClosed
	default:
		packet.buffer.Release()
		return nil
	}
}

func (c *egressPacketConn) Close() error {
	c.cancel()
	for {
		select {
		case packet := <-c.responses:
			packet.buffer.Release()
		default:
			return nil
		}
	}
}

func (c *egressPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (c *egressPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *egressPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *egressPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

// egressPacketSession is the packet connection routed by sing-box: it reads
// the core's datagrams and writes the responses back to the core.
type egressPacketSession struct {
	conn         *egressPacketConn
	ctx          context.Context
	cancel       context.CancelFunc
	requests     chan egressPacket
	readDeadline pipe.Deadline
}

func (s *egressPacketSession) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-s.requests:
		_, err := buffer.ReadOnceFrom(packet.buffer)
		packet.buffer.Release()
		return packet.address, err
	case <-s.ctx.Done():
		return M.Socksaddr{}, net.ErrClosed
	case <-s.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (s *egressPacketSession) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if s.ctx.Err() != nil {
		buffer.Release()
		return net.ErrClosed
	}
	return s.conn.deliver(egressPacket{buffer: buffer, address: destination.Unwrap()})
}

func (s *egressPacketSession) Close() error {
	s.cancel()
	for {
		select {
		case packet := <-s.requests:
			packet.buffer.Release()
		default:
			return nil
		}
	}
}

func (s *egressPacketSession) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (s *egressPacketSession) SetDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *egressPacketSession) SetReadDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *egressPacketSession) SetWriteDeadline(time.Time) error {
	return nil
}

// proxyNATListener stands in for the host TCP listener of the core's own
// subnet proxy, which the core uses when an instance does not hand proxied
// traffic to sing-box (proxy_forward_by_system disabled, as configs from an
// EasyTier Web console may do). The core rewrites a proxied SYN to this
// listener's port on the instance's virtual address and recognizes the
// connection by its source address, so connections reaching that port
// through the internal stack are delivered here unchanged instead of being
// redirected to the host loopback. A loopback port is held so that no local
// service can use the same port.
type proxyNATListener struct {
	endpoint    *Endpoint
	reservation net.Listener
	port        uint16
	conns       chan net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
}

func (e *Endpoint) newProxyNATListener() (net.Listener, error) {
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(e.ctx)
	listener := &proxyNATListener{
		endpoint:    e,
		reservation: reservation,
		port:        uint16(reservation.Addr().(*net.TCPAddr).Port),
		conns:       make(chan net.Conn, proxyNATAcceptBacklog),
		ctx:         ctx,
		cancel:      cancel,
	}
	e.proxyNATAccess.Lock()
	e.proxyNATListeners[listener.port] = listener
	e.proxyNATAccess.Unlock()
	return listener, nil
}

func (e *Endpoint) proxyNATListenerFor(port uint16) *proxyNATListener {
	e.proxyNATAccess.Lock()
	defer e.proxyNATAccess.Unlock()
	return e.proxyNATListeners[port]
}

func (l *proxyNATListener) deliver(conn net.Conn) bool {
	select {
	case l.conns <- conn:
		return true
	case <-l.ctx.Done():
		return false
	default:
		return false
	}
}

func (l *proxyNATListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *proxyNATListener) Close() error {
	l.cancel()
	l.endpoint.proxyNATAccess.Lock()
	if l.endpoint.proxyNATListeners[l.port] == l {
		delete(l.endpoint.proxyNATListeners, l.port)
	}
	l.endpoint.proxyNATAccess.Unlock()
	for {
		select {
		case conn := <-l.conns:
			_ = conn.Close()
		default:
			return l.reservation.Close()
		}
	}
}

func (l *proxyNATListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: int(l.port)}
}

// proxyNATConn is a connection from the internal stack handed to the core's
// subnet proxy, reporting the peer's translated source as remote address.
//
// The core closes it from a host callback running inside the guest, where a
// panic would take down the whole embedded core, so Close must not panic.
type proxyNATConn struct {
	net.Conn
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
	onClose    N.CloseHandlerFunc
}

func (c *proxyNATConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *proxyNATConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *proxyNATConn) Close() error {
	err := c.Conn.Close()
	if c.onClose != nil {
		c.onClose(err)
	}
	return err
}

func (c *proxyNATConn) Upstream() any {
	return c.Conn
}
