package easytier

import (
	"net/netip"
	"slices"
)

// routingSnapshot is the immutable view of the attached instances used on the
// packet path. Several instances share the endpoint's device; each one owns
// its virtual addresses and the destinations reachable through its network.
type routingSnapshot struct {
	// instances are the configured instances in attach order. The first one
	// provides the device's primary addresses.
	instances      []*attachedInstance
	localAddresses []netip.Prefix
	mappings       []proxyMapping
	// routes are sorted by descending prefix length, so the first match is
	// the longest one.
	routes []instanceRoute
}

type instanceRoute struct {
	prefix   netip.Prefix
	instance *attachedInstance
}

func newRoutingSnapshot(instances []*attachedInstance) *routingSnapshot {
	snapshot := &routingSnapshot{}
	for _, instance := range instances {
		state := instance.state.Load()
		if !state.configured {
			continue
		}
		snapshot.instances = append(snapshot.instances, instance)
		snapshot.localAddresses = append(snapshot.localAddresses, state.addresses...)
		snapshot.mappings = append(snapshot.mappings, state.mappings...)
		for _, prefix := range state.routes {
			snapshot.routes = append(snapshot.routes, instanceRoute{prefix: prefix, instance: instance})
		}
	}
	slices.SortStableFunc(snapshot.routes, func(a, b instanceRoute) int {
		return b.prefix.Bits() - a.prefix.Bits()
	})
	return snapshot
}

func (s *routingSnapshot) primary() *attachedInstance {
	if len(s.instances) == 0 {
		return nil
	}
	return s.instances[0]
}

func (s *routingSnapshot) isLocalAddress(address netip.Addr) bool {
	return isLocalAddress(s.localAddresses, address)
}

func (s *routingSnapshot) instanceByAddress(address netip.Addr) *attachedInstance {
	for _, instance := range s.instances {
		if isLocalAddress(instance.state.Load().addresses, address) {
			return instance
		}
	}
	return nil
}

func (s *routingSnapshot) instanceByRoute(address netip.Addr) *attachedInstance {
	for _, route := range s.routes {
		if route.prefix.Contains(address) {
			return route.instance
		}
	}
	return nil
}

// destinationInstance returns the instance that reaches destination, or the
// primary instance, which also carries traffic to its exit nodes.
func (s *routingSnapshot) destinationInstance(destination netip.Addr) *attachedInstance {
	if len(s.instances) == 1 {
		return s.instances[0]
	}
	if instance := s.instanceByRoute(destination); instance != nil {
		return instance
	}
	return s.primary()
}

// outgoingInstance selects the instance for a packet leaving the device. A
// packet sourced from an instance's own address belongs to that instance;
// other packets, such as replies from proxied networks, follow the route to
// their destination.
func (s *routingSnapshot) outgoingInstance(source netip.Addr, destination netip.Addr) *attachedInstance {
	if len(s.instances) == 1 {
		return s.instances[0]
	}
	if instance := s.instanceByAddress(source); instance != nil {
		return instance
	}
	return s.destinationInstance(destination)
}

// sourceAddress selects the local address for a connection the internal
// stack opens to destination.
func (s *routingSnapshot) sourceAddress(destination netip.Addr) netip.Addr {
	instance := s.destinationInstance(destination)
	if instance == nil {
		return netip.Addr{}
	}
	for _, address := range instance.state.Load().addresses {
		if address.Addr().Is4() == destination.Is4() {
			return address.Addr()
		}
	}
	return netip.Addr{}
}

func (s *routingSnapshot) preferred(address netip.Addr) bool {
	return s.instanceByRoute(address) != nil
}

// translateMapped returns the real address behind a mapped proxy network.
func (s *routingSnapshot) translateMapped(address netip.Addr) (netip.Addr, bool) {
	for _, mapping := range s.mappings {
		if realAddress, translated := mapping.translate(address); translated {
			return realAddress, true
		}
	}
	return netip.Addr{}, false
}

func isLocalAddress(localAddresses []netip.Prefix, address netip.Addr) bool {
	return slices.ContainsFunc(localAddresses, func(localPrefix netip.Prefix) bool {
		return address == localPrefix.Addr()
	})
}

func loopbackAddressFor(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.AddrFrom4([4]uint8{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

// packetAddresses parses the source and destination of an IP packet.
func packetAddresses(packet []byte) (netip.Addr, netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}
