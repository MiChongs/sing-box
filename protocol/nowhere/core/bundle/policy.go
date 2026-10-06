package bundle

import (
	"errors"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// DefaultMixFallbackTimeout is the primary mix-route preparation budget.
// Failure or timeout starts the other allowed route once with a new flow ID.
const DefaultMixFallbackTimeout = time.Second

// CarrierMode is the client-side up/down policy. Mix resolves locally to a
// concrete TT, TQ, QT, or QQ pair before any FlowHeader is written.
type CarrierMode uint8

const (
	// ModeTCP always selects TLS/TCP for that direction.
	ModeTCP CarrierMode = iota
	// ModeUDP always selects QUIC/UDP for that direction.
	ModeUDP
	// ModeMix randomly selects TLS/TCP or QUIC/UDP for that direction.
	ModeMix
)

// ParseCarrierMode accepts tcp, udp, or mix. Empty and unknown values fail;
// hosts apply their own URL default before calling this.
func ParseCarrierMode(value string) (CarrierMode, error) {
	switch value {
	case "tcp":
		return ModeTCP, nil
	case "udp":
		return ModeUDP, nil
	case "mix":
		return ModeMix, nil
	default:
		return 0, errors.New("nowhere: carrier mode must be tcp, udp, or mix")
	}
}

// IsMix reports whether the policy is resolved per flow.
func (m CarrierMode) IsMix() bool { return m == ModeMix }

func (m CarrierMode) String() string {
	switch m {
	case ModeTCP:
		return "tcp"
	case ModeUDP:
		return "udp"
	case ModeMix:
		return "mix"
	default:
		return "invalid"
	}
}

// Selectors maps a policy onto the BundleOptions carrier fields. Mix returns
// a zero carrier and mix=true; the concrete pair is chosen at open time.
func (m CarrierMode) Selectors() (carrier wire.Carrier, mix bool) {
	switch m {
	case ModeTCP:
		return wire.CarrierTLSTCP, false
	case ModeUDP:
		return wire.CarrierQUIC, false
	case ModeMix:
		return 0, true
	default:
		return 0, false
	}
}

func carrierMode(carrier wire.Carrier, mix bool) (CarrierMode, error) {
	if mix {
		return ModeMix, nil
	}
	switch carrier {
	case wire.CarrierTLSTCP:
		return ModeTCP, nil
	case wire.CarrierQUIC:
		return ModeUDP, nil
	default:
		return 0, errors.New("nowhere: invalid carrier selector")
	}
}
