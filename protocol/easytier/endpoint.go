package easytier

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/easytier/easytier/easytier-go/platform"
)

// The core batches up to 32 concurrent packet submissions into one guest
// turn, so ingress uses the same number of submitters.
const packetIngressWorkers = 32

// hostAccess serializes creation of core hosts: compiling the embedded core
// peaks at about 100MB of heap, and wazero lazily initializes process-wide
// state without synchronization.
var hostAccess sync.Mutex

var (
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.FlowOutboundDomainResolver  = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.EasyTierEndpointOptions](registry, C.TypeEasyTier, NewEndpoint)
}

// Endpoint joins EasyTier networks through an embedded core. It runs the
// instance described by the local options and, when configured, every
// instance an EasyTier Web configuration server assigns to this machine. All
// instances share one device; packets are dispatched by address and route.
type Endpoint struct {
	endpoint.Adapter
	ctx                  context.Context
	cancel               context.CancelFunc
	router               adapter.Router
	logger               log.ContextLogger
	dnsRouter            adapter.DNSRouter
	innerDNSQueryOptions adapter.DNSQueryOptions
	services             platform.Services
	localName            string
	localConfig          string
	localAddress         addressConfig
	localMappings        []proxyMapping
	webOptions           *corehost.WebClientOptions
	mtu                  uint32
	deviceOptions        *device.Options
	device               device.Device
	stateAccess          sync.Mutex
	deviceStarted        atomic.Bool
	deviceAddresses      []netip.Prefix
	instances            []*attachedInstance
	snapshot             atomic.Pointer[routingSnapshot]
	ingress              chan ingressPacket
	ready                chan struct{}
	readyOnce            sync.Once
	readyErr             error
	done                 chan struct{}
	proxyNATAccess       sync.Mutex
	proxyNATListeners    map[uint16]*proxyNATListener
}

type ingressPacket struct {
	instance *attachedInstance
	buffer   *buf.Buffer
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EasyTierEndpointOptions) (adapter.Endpoint, error) {
	if options.NetworkName == "" && options.Web == nil {
		return nil, E.New("missing network_name or web")
	}
	address, err := parseAddress(options.Address)
	if err != nil {
		return nil, E.Cause(err, "parse address")
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	var (
		localConfig   string
		localMappings []proxyMapping
	)
	if options.NetworkName != "" {
		localConfig, err = buildConfig(options, address, mtu)
		if err != nil {
			return nil, err
		}
		localMappings, err = parseProxyNetworks(options.ProxyNetworks)
		if err != nil {
			return nil, err
		}
	} else if len(options.ProxyNetworks) > 0 || len(options.PortForwards) > 0 || len(options.Peers) > 0 || len(options.Listeners) > 0 || len(options.Address) > 0 {
		return nil, E.New("network options require network_name")
	}
	webOptions, err := newWebClientOptions(options, tag)
	if err != nil {
		return nil, err
	}
	innerDNSQueryOptions, err := dialer.NewInnerDNSQueryOptions(ctx, options.InnerDomainResolver)
	if err != nil {
		return nil, E.Cause(err, "inner domain resolver")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:   ctx,
		Options:   options.DialerOptions,
		NewDialer: true,
	})
	if err != nil {
		return nil, err
	}
	defaultDialer, _ := outboundDialer.(*dialer.DefaultDialer)
	underlayDNSQueryOptions, err := dialer.NewDNSQueryOptions(ctx, options.DomainResolver, true)
	if err != nil {
		return nil, err
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	ctx, cancel := context.WithCancel(ctx)
	ep := &Endpoint{
		Adapter:              endpoint.NewAdapterWithDialerOptions(C.TypeEasyTier, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:                  ctx,
		cancel:               cancel,
		router:               router,
		logger:               logger,
		dnsRouter:            dnsRouter,
		innerDNSQueryOptions: innerDNSQueryOptions,
		localName:            options.NetworkName,
		localConfig:          localConfig,
		localAddress:         address,
		localMappings:        localMappings,
		webOptions:           webOptions,
		mtu:                  mtu,
		ingress:              make(chan ingressPacket, packetIngressWorkers*4),
		ready:                make(chan struct{}),
		done:                 make(chan struct{}),
		proxyNATListeners:    make(map[uint16]*proxyNATListener),
	}
	sockets := &socketFactory{
		endpoint:      ep,
		dialer:        outboundDialer,
		defaultDialer: defaultDialer,
	}
	ep.services = platform.Services{
		Sockets: sockets,
		DNS: &dnsResolver{
			router:  dnsRouter,
			options: underlayDNSQueryOptions,
		},
		Environment: sockets,
	}
	ep.snapshot.Store(newRoutingSnapshot(nil))
	udpTimeout := time.Duration(options.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = C.UDPTimeout
	}
	gso := options.System
	if options.GSO != nil {
		gso = *options.GSO
	}
	ep.deviceOptions = &device.Options{
		Context:         ctx,
		Logger:          logger,
		System:          options.System,
		GSO:             gso,
		Handler:         ep,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		UDPMapping:      tun.NATMapping(options.UDPMapping),
		UDPFiltering:    tun.NATFiltering(options.UDPFiltering),
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: service.FromContext[adapter.NetworkManager](ctx).InterfaceFinder(),
		Name:            options.Name,
		NamePrefix:      "easytier",
		MTU:             mtu,
		SourceAddress: func(destination netip.Addr) netip.Addr {
			return ep.snapshot.Load().sourceAddress(destination)
		},
		Configuration: device.Configuration{
			MTU: mtu,
		},
	}
	return ep, nil
}

func (e *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		e.deviceOptions.MemoryPressure = oomkiller.MemoryPressure(e.ctx)
		tunnelDevice, err := device.New(*e.deviceOptions)
		if err != nil {
			return err
		}
		scope.Add(tunnelDevice.Close)
		tunnelDevice.SetPacketWriter(e.writePacketBuffers)
		e.device = tunnelDevice
		e.deviceOptions = nil
		if e.localAddress.inet4.IsValid() {
			// Start the device early so that L3 flows have their
			// addresses while the core is still being compiled.
			e.stateAccess.Lock()
			err = e.applyDeviceAddressesLocked(e.localAddress.prefixes())
			e.stateAccess.Unlock()
			if err != nil {
				return err
			}
		}
	case adapter.StartStatePostStart:
		// Compiling the embedded core takes seconds, so instances are
		// brought up in the background and outbound dials wait for them.
		go e.run()
		scope.Add(e.close)
	}
	return nil
}

func (e *Endpoint) close() error {
	e.cancel()
	<-e.done
	return nil
}

func (e *Endpoint) run() {
	defer close(e.done)
	err := e.runHost()
	if err != nil && e.ctx.Err() == nil {
		e.logger.Error(err)
	}
	if err == nil {
		err = net.ErrClosed
	}
	e.setReady(err)
	for {
		select {
		case packet := <-e.ingress:
			packet.buffer.Release()
		default:
			return
		}
	}
}

func (e *Endpoint) runHost() error {
	hostAccess.Lock()
	host, err := corehost.New(e.ctx, corehost.Options{Platform: e.services})
	hostAccess.Unlock()
	if err != nil {
		return E.Cause(err, "create EasyTier host")
	}
	defer closeWithTimeout(host.Close)

	workerCtx, workerCancel := context.WithCancel(e.ctx)
	var workers sync.WaitGroup
	defer func() {
		workerCancel()
		workers.Wait()
	}()
	for range packetIngressWorkers {
		workers.Go(func() {
			e.loopIngress(workerCtx)
		})
	}

	var local *attachedInstance
	if e.localConfig != "" {
		instance, startErr := e.startLocalInstance(host)
		if startErr != nil {
			if e.webOptions == nil {
				return startErr
			}
			e.logger.Error(startErr)
		} else {
			local = e.attachInstance(instance, e.localName, false, e.localAddress, e.localMappings)
			defer local.close()
		}
	}
	if e.webOptions != nil {
		var localInstance *corehost.Instance
		if local != nil {
			localInstance = local.instance
		}
		e.runWebClient(host, localInstance)
		return nil
	}
	select {
	case <-e.ctx.Done():
	case <-local.done:
	}
	return nil
}

func (e *Endpoint) startLocalInstance(host *corehost.Host) (*corehost.Instance, error) {
	instance, err := host.CreateInstanceTOML(e.ctx, e.Tag(), "", e.localConfig)
	if err != nil {
		return nil, E.Cause(err, "create EasyTier instance")
	}
	err = instance.Start(e.ctx)
	if err != nil {
		closeWithTimeout(instance.Close)
		return nil, E.Cause(err, "start EasyTier instance")
	}
	e.logger.Info("started network ", e.localName)
	return instance, nil
}

func closeWithTimeout(closer func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.StopTimeout)
	defer cancel()
	_ = closer(ctx)
}

func (e *Endpoint) detachInstance(instance *attachedInstance) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	e.instances = slices.DeleteFunc(e.instances, func(it *attachedInstance) bool {
		return it == instance
	})
	err := e.updateDeviceLocked()
	if err != nil {
		e.logger.Error(err)
	}
}

// updateDeviceLocked publishes a new routing snapshot and moves the device to
// the addresses of the configured instances.
func (e *Endpoint) updateDeviceLocked() error {
	snapshot := newRoutingSnapshot(e.instances)
	e.snapshot.Store(snapshot)
	if len(snapshot.instances) > 0 {
		e.setReady(nil)
	}
	if len(snapshot.localAddresses) == 0 {
		return nil
	}
	return e.applyDeviceAddressesLocked(snapshot.localAddresses)
}

func (e *Endpoint) applyDeviceAddressesLocked(addresses []netip.Prefix) error {
	if e.deviceStarted.Load() && slices.Equal(e.deviceAddresses, addresses) {
		return nil
	}
	err := e.device.UpdateConfiguration(device.Configuration{
		MTU:     e.mtu,
		Address: addresses,
	})
	if err != nil {
		return E.Cause(err, "update device configuration")
	}
	e.deviceAddresses = addresses
	if !e.deviceStarted.Load() {
		err = e.device.Start()
		if err != nil {
			return E.Cause(err, "start device")
		}
		e.deviceStarted.Store(true)
	}
	return nil
}

func (e *Endpoint) setReady(err error) {
	e.readyOnce.Do(func() {
		e.readyErr = err
		close(e.ready)
	})
}

func (e *Endpoint) waitReady(ctx context.Context) error {
	select {
	case <-e.ready:
	default:
		waitCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
		select {
		case <-e.ready:
		case <-waitCtx.Done():
			return E.New("EasyTier endpoint is not ready yet")
		}
	}
	if e.readyErr != nil {
		return e.readyErr
	}
	if len(e.snapshot.Load().instances) == 0 {
		return E.New("no EasyTier instance is running")
	}
	return nil
}

func (e *Endpoint) loopIngress(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-e.ingress:
			err := packet.instance.instance.SendPacket(ctx, packet.buffer.Bytes())
			packet.buffer.Release()
			if err != nil && ctx.Err() == nil {
				e.logger.Trace(E.Cause(err, packet.instance.logPrefix(), "send packet"))
			}
		}
	}
}

// writeInbound delivers packets received from an instance to the device.
func (e *Endpoint) writeInbound(packetBuffers []*buf.Buffer) {
	if !e.deviceStarted.Load() {
		buf.ReleaseMulti(packetBuffers)
		return
	}
	err := e.device.WriteInboundBuffers(packetBuffers)
	buf.ReleaseMulti(packetBuffers)
	if err != nil {
		e.logger.Trace(E.Cause(err, "write inbound packets"))
	}
}

// writePacketBuffers dispatches packets leaving the device to the instance
// owning their source or destination.
func (e *Endpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	snapshot := e.snapshot.Load()
	if len(snapshot.instances) == 0 {
		buf.ReleaseMulti(packetBuffers)
		return E.New("no EasyTier instance is running")
	}
	for i, packetBuffer := range packetBuffers {
		source, destination, valid := packetAddresses(packetBuffer.Bytes())
		var instance *attachedInstance
		if valid {
			instance = snapshot.outgoingInstance(source, destination)
		}
		if instance == nil {
			packetBuffer.Release()
			continue
		}
		select {
		case e.ingress <- ingressPacket{instance: instance, buffer: packetBuffer}:
		case <-e.done:
			buf.ReleaseMulti(packetBuffers[i:])
			return net.ErrClosed
		}
	}
	return nil
}

func (e *Endpoint) WritePackets(packets [][]byte) error {
	return e.writePacketBuffers(common.Map(packets, func(packet []byte) *buf.Buffer {
		packetBuffer := buf.NewSize(len(packet))
		common.Must1(packetBuffer.Write(packet))
		return packetBuffer
	}))
}

func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return e.device.PortAddresses()
}

func (e *Endpoint) PortMTU() uint32 {
	return e.device.PortMTU()
}

func (e *Endpoint) AttachReturn(returnPath tun.Return) error {
	return e.device.AttachReturn(returnPath)
}

func (e *Endpoint) DetachReturn(returnPath tun.Return) error {
	return e.device.DetachReturn(returnPath)
}

// PreMatchFlow forwards flows at L3 only towards destinations of the primary
// instance: L3 flows are translated to the device's primary addresses, which
// other instances do not own.
func (e *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	snapshot := e.snapshot.Load()
	if len(snapshot.instances) > 1 && snapshot.destinationInstance(destination) != snapshot.primary() {
		return adapter.PreMatchContinue
	}
	return adapter.PreMatchFlow
}

func (e *Endpoint) FlowDomainResolveOptions() adapter.DNSQueryOptions {
	return e.innerDNSQueryOptions
}

func (e *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	snapshot := e.snapshot.Load()
	if snapshot.isLocalAddress(destination.Addr()) {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	metadata := adapter.InboundContext{Inbound: e.Tag(), InboundType: e.Type()}
	if realAddress, mapped := snapshot.translateMapped(destination.Addr()); mapped {
		realDestination := netip.AddrPortFrom(realAddress, destination.Port())
		verdict := adapter.JudgeFlow(e.router, metadata, network, source, realDestination, firstPacket)
		if verdict.Action == tun.ActionFlow && !verdict.Destination.IsValid() {
			verdict.Destination = realDestination
		}
		return verdict
	}
	return adapter.JudgeFlow(e.router, metadata, network, source, destination, firstPacket)
}

func (e *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(e.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	e.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	e.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

// rewriteInboundDestination returns the destination to route for traffic
// arriving from a peer: the loopback address for this node's own addresses
// and the real address for a mapped proxy network.
func (e *Endpoint) rewriteInboundDestination(destination M.Socksaddr) (M.Socksaddr, bool) {
	snapshot := e.snapshot.Load()
	if snapshot.isLocalAddress(destination.Addr) {
		destination.Addr = loopbackAddressFor(destination.Addr)
		return destination, true
	}
	if realAddress, mapped := snapshot.translateMapped(destination.Addr); mapped {
		destination.Addr = realAddress
		return destination, true
	}
	return destination, false
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if e.snapshot.Load().isLocalAddress(destination.Addr) {
		if listener := e.proxyNATListenerFor(destination.Port); listener != nil {
			proxyConn := &proxyNATConn{
				Conn:       conn,
				localAddr:  net.TCPAddrFromAddrPort(destination.Unwrap().AddrPort()),
				remoteAddr: net.TCPAddrFromAddrPort(source.Unwrap().AddrPort()),
			}
			if onClose != nil {
				proxyConn.onClose = N.OnceClose(onClose)
			}
			if !listener.deliver(proxyConn) {
				_ = proxyConn.Close()
			}
			return
		}
	}
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	if rewritten, changed := e.rewriteInboundDestination(destination); changed {
		metadata.OriginDestination = destination
		destination = rewritten
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound connection from ", source)
	e.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	if rewritten, changed := e.rewriteInboundDestination(destination); changed {
		metadata.OriginDestination = destination
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), destination, rewritten)
		destination = rewritten
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	err := e.waitReady(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		destinationAddresses, lookupErr := e.dnsRouter.Lookup(ctx, destination.Fqdn, e.innerDNSQueryOptions)
		if lookupErr != nil {
			return nil, lookupErr
		}
		return N.DialSerial(ctx, e.device, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	err := e.waitReady(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		destinationAddresses, lookupErr := e.dnsRouter.Lookup(ctx, destination.Fqdn, e.innerDNSQueryOptions)
		if lookupErr != nil {
			return nil, netip.Addr{}, lookupErr
		}
		packetConn, destinationAddress, listenErr := N.ListenSerial(ctx, e.device, destination, destinationAddresses)
		if listenErr != nil {
			return nil, netip.Addr{}, listenErr
		}
		return iponly.NewPacketConn(e.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := e.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(e.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(e.logger, packetConn), netip.Addr{}, nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := e.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (e *Endpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

// PreferredAddress reports destinations inside the EasyTier networks: virtual
// subnets, peers and the proxy networks they advertise. The local subnets are
// known before the core is up, so early connections wait for it instead of
// taking another route.
func (e *Endpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if e.snapshot.Load().preferred(address) {
		return true
	}
	return slices.ContainsFunc(e.localAddress.prefixes(), func(prefix netip.Prefix) bool {
		return prefix.Masked().Contains(address)
	})
}
