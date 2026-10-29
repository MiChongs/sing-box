package smart

import "time"

// Network separates TCP and UDP evidence; a node good for one may be broken
// for the other.
type Network uint8

const (
	NetworkTCP Network = iota
	NetworkUDP
)

func (n Network) String() string {
	if n == NetworkUDP {
		return "udp"
	}
	return "tcp"
}

// Family is the business target's address family, independent of the
// family used to reach the proxy server.
type Family uint8

const (
	FamilyNone Family = iota
	FamilyIPv4
	FamilyIPv6
)

// Outcome is how one business attempt ended.
type Outcome uint8

const (
	// OutcomeSuccess: the attempt carried traffic in both directions, or
	// ended cleanly after a response.
	OutcomeSuccess Outcome = iota
	// OutcomeFailure: the node or the path failed the attempt.
	OutcomeFailure
	// OutcomeCancelled: the client went away or the process is shutting
	// down; the attempt says nothing about the node.
	OutcomeCancelled
)

// FailureScope says which evidence a failure opens hard failure state on.
type FailureScope uint8

const (
	// ScopeNode: dial, proxy, authentication or carrier failures. The node
	// is failing for every target.
	ScopeNode FailureScope = iota
	// ScopeTarget: the node worked but this target did not answer through
	// it (stalled, refused, reset after setup). Only the exact target and
	// its site open hard state; parent layers keep the numeric outcome.
	ScopeTarget
)

// Finish describes one settled business attempt.
type Finish struct {
	Outcome Outcome
	Scope   FailureScope
	SetupOK bool
	TX, RX  int64
	RXAt    Mono

	SetupLatency    time.Duration
	ResponseLatency time.Duration
	Duration        time.Duration
	MaxUpRate       float64 // KB/s
	MaxDownRate     float64 // KB/s

	// TCP retransmission counters of the carrier socket, when readable.
	Sent    uint64
	Retrans uint64
	// Window loss rate judged over the connection, 0 when unknown.
	LossRate float64

	// Quality is the per-connection quality weight (scene formula or
	// LightGBM), 0 when not computed.
	Quality float64
}
