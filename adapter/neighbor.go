package adapter

import (
	"net"
	"net/netip"
)

// NeighborEntry is what a NeighborResolver surfaces about a single
// LAN neighbour. The MAC/hostname pair drives rule_item_mac /
// rule_item_hostname matching added in upstream 2cf78e1df.
type NeighborEntry struct {
	Address    netip.Addr
	MACAddress net.HardwareAddr
	Hostname   string
}

type NeighborResolver interface {
	LookupMAC(address netip.Addr) (net.HardwareAddr, bool)
	LookupHostname(address netip.Addr) (string, bool)
	Start() error
	Close() error
}

// NeighborUpdateListener is xiaobaf14g's extension for change-
// driven consumers (e.g. a Clash API neighbour-view endpoint). Not
// in upstream; kept here because existing local code registers
// callbacks through it.
type NeighborUpdateListener interface {
	UpdateNeighborTable(entries []NeighborEntry)
}
