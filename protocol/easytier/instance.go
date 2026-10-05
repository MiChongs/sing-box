package easytier

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	corehost "github.com/easytier/easytier/easytier-go"
	etcommon "github.com/easytier/easytier/easytier-go/proto/common"
)

const (
	packetEgressBatch      = 32
	unassignedPollInterval = time.Second
	statusPollInterval     = 5 * time.Second
)

// attachedInstance connects one EasyTier instance to the endpoint's device.
type attachedInstance struct {
	endpoint *Endpoint
	instance *corehost.Instance
	web      bool
	// static holds the addresses known from the local configuration. Web
	// instances and DHCP report theirs through node info.
	static       addressConfig
	name         string
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	statusUpdate chan struct{}
	state        common.TypedValue[*instanceState]
}

type instanceState struct {
	configured bool
	addresses  []netip.Prefix
	routes     []netip.Prefix
	mappings   []proxyMapping
	dnsZone    string
	dnsHosts   []magicDNSHost
}

func (s *instanceState) equal(other *instanceState) bool {
	return s.configured == other.configured &&
		slices.Equal(s.addresses, other.addresses) &&
		slices.Equal(s.routes, other.routes) &&
		slices.Equal(s.mappings, other.mappings) &&
		s.dnsZone == other.dnsZone &&
		slices.EqualFunc(s.dnsHosts, other.dnsHosts, magicDNSHost.equal)
}

func (e *Endpoint) attachInstance(instance *corehost.Instance, name string, web bool, static addressConfig, mappings []proxyMapping) *attachedInstance {
	ctx, cancel := context.WithCancel(e.ctx)
	attached := &attachedInstance{
		endpoint:     e,
		instance:     instance,
		web:          web,
		static:       static,
		name:         name,
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		statusUpdate: make(chan struct{}, 1),
	}
	state := &instanceState{mappings: mappings, dnsZone: defaultDNSZone}
	if !web {
		state.dnsZone = e.localDNSZone
	}
	if static.inet4.IsValid() {
		state.configured = true
		state.addresses = static.prefixes()
		state.routes = routePrefixes(state.addresses, nil)
	}
	attached.state.Store(state)
	e.stateAccess.Lock()
	e.instances = append(e.instances, attached)
	err := e.updateDeviceLocked()
	e.stateAccess.Unlock()
	if err != nil {
		e.logger.Error(err)
	}
	if web {
		e.logger.Info("attached EasyTier Web instance ", name)
	}
	go attached.run()
	return attached
}

func (a *attachedInstance) run() {
	defer close(a.done)
	var group sync.WaitGroup
	group.Go(a.loopEgress)
	group.Go(a.loopEvents)
	group.Go(a.loopStatus)
	err := a.instance.Wait(a.ctx)
	closedByEndpoint := a.ctx.Err() != nil
	a.cancel()
	group.Wait()
	a.endpoint.detachInstance(a)
	switch {
	case closedByEndpoint:
	case a.web:
		// The Web console deleted or replaced the instance.
		a.endpoint.logger.Info("detached EasyTier Web instance ", a.name)
	case err != nil:
		a.endpoint.logger.Error(E.Cause(err, a.logPrefix(), "EasyTier instance stopped"))
	default:
		a.endpoint.logger.Error(a.logPrefix(), "EasyTier instance stopped")
	}
}

func (a *attachedInstance) close() {
	a.cancel()
	<-a.done
}

func (a *attachedInstance) logPrefix() string {
	return a.name + ": "
}

func (a *attachedInstance) loopEgress() {
	// A cancelled context makes ReceivePacket return only already queued
	// packets, which lets one wakeup drain a batch.
	drainCtx, drainCancel := context.WithCancel(a.ctx)
	drainCancel()
	for {
		packet, err := a.instance.ReceivePacket(a.ctx)
		if err != nil {
			if a.ctx.Err() == nil {
				a.endpoint.logger.Debug(E.Cause(err, a.logPrefix(), "receive packet"))
			}
			return
		}
		packetBuffers := make([]*buf.Buffer, 1, packetEgressBatch)
		packetBuffers[0] = buf.As(packet)
		for len(packetBuffers) < packetEgressBatch {
			packet, err = a.instance.ReceivePacket(drainCtx)
			if err != nil {
				break
			}
			packetBuffers = append(packetBuffers, buf.As(packet))
		}
		a.endpoint.writeInbound(packetBuffers)
	}
}

func (a *attachedInstance) loopEvents() {
	events := a.instance.Events()
	for {
		select {
		case <-a.ctx.Done():
			return
		case event, loaded := <-events:
			if !loaded {
				return
			}
			logger := a.endpoint.logger
			switch event.Kind {
			case "peer_added":
				logger.Info(a.logPrefix(), "peer ", eventArgument(event.Message), " added")
			case "peer_removed":
				logger.Info(a.logPrefix(), "peer ", eventArgument(event.Message), " removed")
			case "listener_plan_failed", "listener_add_failed":
				logger.Warn(a.logPrefix(), event.Kind, ": ", event.Message)
			default:
				logger.Debug(a.logPrefix(), event.Kind, ": ", event.Message)
			}
			switch event.Kind {
			case "peer_added", "peer_removed", "proxy_cidrs_updated", "public_ipv6_lease_changed", "public_ipv6_routes_changed":
				a.requestStatusUpdate()
			}
		}
	}
}

func (a *attachedInstance) requestStatusUpdate() {
	select {
	case a.statusUpdate <- struct{}{}:
	default:
	}
}

// eventArgument extracts the payload of a tuple-variant event message such as
// "PeerAdded(1234)".
func eventArgument(message string) string {
	start := strings.IndexByte(message, '(')
	if start < 0 || !strings.HasSuffix(message, ")") {
		return message
	}
	return message[start+1 : len(message)-1]
}

func (a *attachedInstance) loopStatus() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-timer.C:
		case <-a.statusUpdate:
		}
		a.refreshStatus()
		if a.state.Load().configured {
			timer.Reset(statusPollInterval)
		} else {
			timer.Reset(unassignedPollInterval)
		}
	}
}

// refreshStatus reads the instance's addresses, its own mapped proxy
// networks and the routes of its network.
func (a *attachedInstance) refreshStatus() {
	queryCtx, cancel := context.WithTimeout(a.ctx, C.DNSTimeout)
	defer cancel()
	logger := a.endpoint.logger
	nodeInfo, err := a.instance.ShowNodeInfo(queryCtx)
	if err != nil {
		if a.ctx.Err() == nil {
			logger.Debug(E.Cause(err, a.logPrefix(), "query node info"))
		}
		return
	}
	previous := a.state.Load()
	state := &instanceState{
		mappings: parseNodeProxyCIDRs(nodeInfo.GetProxyCidrs()),
		dnsZone:  a.dnsZone(nodeInfo),
	}
	if a.static.inet4.IsValid() {
		state.addresses = a.static.prefixes()
	} else if inet4Address, loaded := parseNodeAddress(nodeInfo.GetIpv4Addr()); loaded {
		state.addresses = append(state.addresses, inet4Address)
		inet6Address := a.static.inet6
		if a.web {
			inet6Address, _ = netip.ParsePrefix(tomlString(nodeInfo.GetConfig(), "", "ipv6"))
		}
		if inet6Address.IsValid() {
			state.addresses = append(state.addresses, inet6Address)
		}
	}
	state.configured = len(state.addresses) > 0
	routes, err := a.instance.ListRoute(queryCtx)
	if err == nil {
		state.routes = routePrefixes(state.addresses, routes)
		state.dnsHosts = magicDNSHosts(state.dnsZone, nodeInfo.GetHostname(), state.addresses, routes)
	} else {
		if a.ctx.Err() == nil {
			logger.Debug(E.Cause(err, a.logPrefix(), "query routes"))
		}
		state.routes = previous.routes
		state.dnsHosts = previous.dnsHosts
	}
	if previous.equal(state) {
		return
	}
	if !slices.Equal(previous.addresses, state.addresses) && state.configured {
		logger.Info(a.logPrefix(), "assigned ", strings.Join(common.Map(state.addresses, netip.Prefix.String), " "))
	}
	if !slices.Equal(previous.routes, state.routes) {
		logger.Debug(a.logPrefix(), "routes: ", strings.Join(common.Map(state.routes, netip.Prefix.String), " "))
	}
	if !slices.EqualFunc(previous.dnsHosts, state.dnsHosts, magicDNSHost.equal) {
		logger.Debug(a.logPrefix(), "magic DNS: ", strings.Join(common.Map(state.dnsHosts, func(host magicDNSHost) string {
			return strings.TrimSuffix(host.name, ".")
		}), " "))
	}
	a.state.Store(state)
	a.endpoint.stateAccess.Lock()
	err = a.endpoint.updateDeviceLocked()
	a.endpoint.stateAccess.Unlock()
	if err != nil {
		logger.Error(err)
	}
}

// dnsZone returns the Magic DNS zone of the instance: the endpoint option for
// the local network and the tld_dns_zone flag of a Web instance's config.
func (a *attachedInstance) dnsZone(nodeInfo *corehost.NodeInfo) string {
	if !a.web {
		return a.endpoint.localDNSZone
	}
	zone, err := parseDNSZone(tomlString(nodeInfo.GetConfig(), "flags", "tld_dns_zone"))
	if err != nil {
		a.endpoint.logger.Warn(E.Cause(err, a.logPrefix(), "magic DNS"))
		return defaultDNSZone
	}
	return zone
}

func parseNodeAddress(address string) (netip.Prefix, bool) {
	if address == "" {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(address)
	if err == nil {
		if prefix.Addr().IsUnspecified() {
			return netip.Prefix{}, false
		}
		return prefix, true
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.IsUnspecified() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// routePrefixes collects the destinations reachable through an instance: its
// virtual subnets, every peer address and every proxy network advertised by
// a peer.
func routePrefixes(localAddresses []netip.Prefix, routes []*corehost.Route) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, localAddress := range localAddresses {
		prefixes = append(prefixes, localAddress.Masked())
	}
	for _, route := range routes {
		if inet4Address := route.GetIpv4Addr().GetAddress(); inet4Address != nil {
			prefixes = append(prefixes, netip.PrefixFrom(inet4AddrFrom(inet4Address), 32))
		}
		if inet6Address := route.GetIpv6Addr().GetAddress(); inet6Address != nil {
			prefixes = append(prefixes, netip.PrefixFrom(inet6AddrFrom(inet6Address), 128))
		}
		for _, proxyCIDR := range route.GetProxyCidrs() {
			prefix, err := parseCoreCIDR(proxyCIDR)
			if err == nil {
				prefixes = append(prefixes, prefix.Masked())
			}
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if compare := a.Addr().Compare(b.Addr()); compare != 0 {
			return compare
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(prefixes)
}

func inet4AddrFrom(address *etcommon.Ipv4Addr) netip.Addr {
	value := address.GetAddr()
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func inet6AddrFrom(address *etcommon.Ipv6Addr) netip.Addr {
	var bytes [16]byte
	for i, part := range []uint32{address.GetPart1(), address.GetPart2(), address.GetPart3(), address.GetPart4()} {
		bytes[i*4] = byte(part >> 24)
		bytes[i*4+1] = byte(part >> 16)
		bytes[i*4+2] = byte(part >> 8)
		bytes[i*4+3] = byte(part)
	}
	return netip.AddrFrom16(bytes)
}
