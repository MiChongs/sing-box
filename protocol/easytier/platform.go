package easytier

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/easytier/easytier/easytier-go/platform"
	"github.com/miekg/dns"
)

var (
	_ platform.SocketFactory        = (*socketFactory)(nil)
	_ platform.DNSResolver          = (*dnsResolver)(nil)
	_ platform.ConnectorEnvironment = (*socketFactory)(nil)
)

// socketFactory creates the host sockets requested by the embedded EasyTier
// core. They fall into three groups:
//
//   - Underlay sockets carry the tunnel to other peers. Unbound ones go
//     through the configured dialer so that detour, bind_interface,
//     routing_mark and auto_detect_interface apply; those that must own a
//     local address are created with the default dialer's socket controls.
//   - Listener sockets (UDP tunnel listeners, port forwards, port leases)
//     accept local or remote clients and are bound without outbound controls;
//     they are only registered for eBPF self-bypass, so that local eBPF
//     interception does not redirect their replies back into sing-box.
//   - Egress sockets carry overlay traffic out to real destinations (the
//     core's own subnet proxy, its SOCKS5 portal and direct fallbacks of the
//     gateway data plane). They are routed by sing-box as connections
//     arriving at the endpoint.
type socketFactory struct {
	endpoint       *Endpoint
	dialer         N.Dialer
	defaultDialer  *dialer.DefaultDialer
	networkManager adapter.NetworkManager
	// listenerControl only registers listener sockets for eBPF self-bypass;
	// it carries no bind_interface, routing_mark or auto_detect_interface.
	listenerControl control.Func
}

func (f *socketFactory) ConnectTCP(ctx context.Context, options platform.TCPConnectOptions) (net.Conn, error) {
	if options.RemoteAddr == nil {
		return nil, E.New("missing TCP remote address")
	}
	destination := M.SocksaddrFromNet(options.RemoteAddr).Unwrap()
	switch options.Purpose {
	case platform.TCPConnectFake:
		return nil, E.New("FakeTCP is not supported")
	case platform.TCPConnectProxyNAT, platform.TCPConnectSocks5, platform.TCPConnectPortForward, platform.TCPConnectDataPlane:
		return f.endpoint.routeEgressConnection(destination), nil
	}
	var (
		conn net.Conn
		err  error
	)
	if tcpNeedsBind(options.Bind) {
		if f.defaultDialer == nil {
			return nil, E.New("binding a local TCP address is not supported with detour")
		}
		netDialer := f.defaultDialer.DialerForICMPDestination(destination.Addr)
		netDialer.LocalAddr = options.Bind.LocalAddr
		netDialer.Control = control.Append(netDialer.Control, reuseControl(options.Bind.ReuseAddr == nil || *options.Bind.ReuseAddr, options.Bind.ReusePort))
		network := N.NetworkTCP
		if options.Bind.OnlyV6 {
			network += "6"
		}
		conn, err = netDialer.DialContext(ctx, network, destination.String())
	} else {
		conn, err = f.dialer.DialContext(ctx, N.NetworkTCP, destination)
	}
	if err != nil {
		return nil, err
	}
	if options.Purpose == platform.TCPConnectSTUNProbe {
		if tcpConn, isTCPConn := common.Cast[*net.TCPConn](conn); isTCPConn {
			_ = tcpConn.SetLinger(0)
		}
	}
	return &streamConn{
		Conn:       conn,
		localAddr:  tcpAddrFrom(conn.LocalAddr()),
		remoteAddr: net.TCPAddrFromAddrPort(destination.AddrPort()),
	}, nil
}

func (f *socketFactory) BindUDP(ctx context.Context, options platform.UDPBindOptions) (net.PacketConn, error) {
	if options.Context.SocketMark != nil || options.Context.NetNS != nil || options.BindDevice != nil {
		return nil, E.New("socket mark, network namespace and bind device are configured by sing-box dialer options")
	}
	switch options.Purpose {
	case platform.UDPBindProxyNAT, platform.UDPBindSocks5:
		return f.endpoint.newEgressPacketConn(), nil
	case platform.UDPBindPortBoundListener, platform.UDPBindPortForward, platform.UDPBindPortLease:
		return f.listenUDP(ctx, f.listenerControl, options)
	}
	if f.defaultDialer == nil && !udpNeedsBind(options) {
		packetConn, err := f.dialer.ListenPacket(ctx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, err
		}
		return newDatagramConn(packetConn), nil
	}
	var listenControl control.Func
	if f.defaultDialer != nil {
		listenControl, _ = f.defaultDialer.UDPListenerControl()
	}
	return f.listenUDP(ctx, listenControl, options)
}

// listenUDP binds a host UDP socket with listenControl, which registers it for
// eBPF self-bypass when eBPF is enabled; the registration is released on Close
// when the kernel has no socket release hook.
func (f *socketFactory) listenUDP(ctx context.Context, listenControl control.Func, options platform.UDPBindOptions) (net.PacketConn, error) {
	listenConfig := net.ListenConfig{
		Control: control.Append(listenControl, reuseControl(options.ReuseAddr, options.ReusePort)),
	}
	var localAddress string
	if options.LocalAddr != nil {
		localAddress = options.LocalAddr.String()
	}
	packetConn, err := listenConfig.ListenPacket(ctx, udpNetwork(options), localAddress)
	if err != nil {
		return nil, err
	}
	conn := newDatagramConn(packetConn)
	if syscallConn, isSyscallConn := packetConn.(syscall.Conn); isSyscallConn {
		if rawConn, rawConnErr := syscallConn.SyscallConn(); rawConnErr == nil {
			conn.cleanup = dialer.EBPFSelfBypassCleanup(f.networkManager, rawConn)
		}
	}
	return conn, nil
}

func (f *socketFactory) ListenTCP(ctx context.Context, options platform.TCPListenOptions) (net.Listener, error) {
	if options.Bind.Context.SocketMark != nil || options.Bind.Context.NetNS != nil || options.Bind.BindDevice != nil {
		return nil, E.New("socket mark, network namespace and bind device are configured by sing-box dialer options")
	}
	if options.Purpose == platform.TCPListenProxyNAT {
		return f.endpoint.newProxyNATListener()
	}
	listenConfig := net.ListenConfig{
		Control: reuseControl(options.Bind.ReuseAddr == nil || *options.Bind.ReuseAddr, options.Bind.ReusePort),
	}
	network := N.NetworkTCP
	if options.Bind.OnlyV6 {
		network += "6"
	}
	var localAddress string
	if options.Bind.LocalAddr != nil {
		localAddress = options.Bind.LocalAddr.String()
	}
	return listenConfig.Listen(ctx, network, localAddress)
}

func (f *socketFactory) LocalAddrForRemote(ctx context.Context, remote *net.UDPAddr, socketContext platform.SocketContext) (net.Addr, error) {
	if socketContext.SocketMark != nil || socketContext.NetNS != nil {
		return nil, E.New("socket mark and network namespace are configured by sing-box dialer options")
	}
	if f.defaultDialer == nil {
		return nil, E.New("local address discovery is not supported with detour")
	}
	destination := M.SocksaddrFromNet(remote).Unwrap()
	netDialer := f.defaultDialer.DialerForICMPDestination(destination.Addr)
	conn, err := netDialer.DialContext(ctx, N.NetworkUDP, destination.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return udpAddrFrom(conn.LocalAddr()), nil
}

func tcpNeedsBind(options platform.TCPBindOptions) bool {
	return options.ReusePort || options.BindDevice != nil || options.LocalAddr != nil && !isUnspecifiedAddress(options.LocalAddr.IP, options.LocalAddr.Port)
}

func udpNeedsBind(options platform.UDPBindOptions) bool {
	return options.ReuseAddr || options.ReusePort || options.LocalAddr != nil && !isUnspecifiedAddress(options.LocalAddr.IP, options.LocalAddr.Port)
}

func isUnspecifiedAddress(ip net.IP, port int) bool {
	return port == 0 && (len(ip) == 0 || ip.IsUnspecified())
}

func udpNetwork(options platform.UDPBindOptions) string {
	if options.LocalAddr != nil && options.LocalAddr.IP.To4() != nil {
		return N.NetworkUDP + "4"
	}
	if options.OnlyV6 {
		return N.NetworkUDP + "6"
	}
	if options.LocalAddr != nil && len(options.LocalAddr.IP) != 0 {
		return N.NetworkUDP
	}
	if options.Context.IPVersion == platform.IPVersionV4 {
		return N.NetworkUDP + "4"
	}
	return N.NetworkUDP
}

func reuseControl(reuseAddr bool, reusePort bool) control.Func {
	if reusePort {
		return control.ReuseAddr()
	}
	if reuseAddr {
		return control.ReuseAddrOnly()
	}
	return nil
}

// streamConn reports socket addresses with the concrete types required by the
// EasyTier host ABI, independent of the connection returned by the dialer.
type streamConn struct {
	net.Conn
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
}

func (c *streamConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *streamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *streamConn) Upstream() any {
	return c.Conn
}

// datagramConn reports peer and local addresses as unmapped *net.UDPAddr,
// which is the only address type the EasyTier host ABI accepts.
type datagramConn struct {
	net.PacketConn
	localAddr *net.UDPAddr
	// cleanup releases the socket's eBPF self-bypass registration; nil when
	// the socket is not registered or the kernel releases it on close.
	cleanup func()
}

func newDatagramConn(packetConn net.PacketConn) *datagramConn {
	return &datagramConn{
		PacketConn: packetConn,
		localAddr:  udpAddrFrom(packetConn.LocalAddr()),
	}
}

func (c *datagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	if udpAddr, isUDPAddr := addr.(*net.UDPAddr); isUDPAddr {
		if ip4 := udpAddr.IP.To4(); ip4 != nil && len(udpAddr.IP) != net.IPv4len {
			return n, &net.UDPAddr{IP: ip4, Port: udpAddr.Port}, nil
		}
		return n, udpAddr, nil
	}
	return n, udpAddrFrom(addr), nil
}

func (c *datagramConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *datagramConn) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.PacketConn.Close()
}

func (c *datagramConn) Upstream() any {
	return c.PacketConn
}

func tcpAddrFrom(addr net.Addr) *net.TCPAddr {
	if tcpAddr, isTCPAddr := addr.(*net.TCPAddr); isTCPAddr {
		return tcpAddr
	}
	socksAddr := M.SocksaddrFromNet(addr).Unwrap()
	if !socksAddr.IsIP() {
		return &net.TCPAddr{IP: net.IPv4zero}
	}
	return net.TCPAddrFromAddrPort(socksAddr.AddrPort())
}

func udpAddrFrom(addr net.Addr) *net.UDPAddr {
	socksAddr := M.SocksaddrFromNet(addr).Unwrap()
	if !socksAddr.IsIP() {
		return &net.UDPAddr{IP: net.IPv4zero}
	}
	return net.UDPAddrFromAddrPort(socksAddr.AddrPort())
}

// dnsResolver resolves peer, STUN and discovery names through the sing-box
// DNS router.
type dnsResolver struct {
	router  adapter.DNSRouter
	options adapter.DNSQueryOptions
}

func (r *dnsResolver) LookupIP(ctx context.Context, query platform.DNSQuery) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(query.Host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	options := r.options
	switch query.IPVersion {
	case 4:
		options.Strategy = C.DomainStrategyIPv4Only
	case 6:
		options.Strategy = C.DomainStrategyIPv6Only
	}
	addresses, err := r.router.Lookup(ctx, query.Host, options)
	if err != nil {
		return nil, err
	}
	for i := range addresses {
		addresses[i] = addresses[i].Unmap()
	}
	return addresses, nil
}

func (r *dnsResolver) LookupTXT(ctx context.Context, query platform.DNSQuery) (string, error) {
	response, err := r.exchange(ctx, query.Host, dns.TypeTXT)
	if err != nil {
		return "", err
	}
	for _, record := range response.Answer {
		if txtRecord, isTXT := record.(*dns.TXT); isTXT {
			return strings.Join(txtRecord.Txt, ""), nil
		}
	}
	return "", E.New("DNS TXT query for ", query.Host, " returned no records")
}

func (r *dnsResolver) LookupSRV(ctx context.Context, query platform.DNSQuery) ([]*net.SRV, error) {
	response, err := r.exchange(ctx, query.Host, dns.TypeSRV)
	if err != nil {
		return nil, err
	}
	var records []*net.SRV
	for _, record := range response.Answer {
		if srvRecord, isSRV := record.(*dns.SRV); isSRV {
			records = append(records, &net.SRV{
				Target:   srvRecord.Target,
				Port:     srvRecord.Port,
				Priority: srvRecord.Priority,
				Weight:   srvRecord.Weight,
			})
		}
	}
	if len(records) == 0 {
		return nil, E.New("DNS SRV query for ", query.Host, " returned no records")
	}
	slices.SortStableFunc(records, func(a, b *net.SRV) int {
		if a.Priority != b.Priority {
			return int(a.Priority) - int(b.Priority)
		}
		return int(b.Weight) - int(a.Weight)
	})
	return records, nil
}

func (r *dnsResolver) exchange(ctx context.Context, name string, queryType uint16) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	response, err := r.router.Exchange(ctx, message, r.options)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, E.New("DNS ", dns.TypeToString[queryType], " query for ", name, ": ", dns.RcodeToString[response.Rcode])
	}
	return response, nil
}
