package bundle

import (
	"errors"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

// CarrierMode is the client-side up/down policy.
type CarrierMode uint8

const (
	// ModeTCP always selects TLS/TCP for that direction.
	ModeTCP CarrierMode = iota
	// ModeUDP always selects QUIC/UDP for that direction.
	ModeUDP
)

// ParseCarrierMode accepts tcp or udp. Empty and unknown values fail;
// hosts apply their own URL default before calling this.
func ParseCarrierMode(value string) (CarrierMode, error) {
	switch value {
	case "tcp":
		return ModeTCP, nil
	case "udp":
		return ModeUDP, nil
	default:
		return 0, errors.New("nowhere: carrier mode must be tcp or udp")
	}
}

func (m CarrierMode) String() string {
	switch m {
	case ModeTCP:
		return "tcp"
	case ModeUDP:
		return "udp"
	default:
		return "invalid"
	}
}

// Selectors maps a policy onto the BundleOptions carrier fields.
func (m CarrierMode) Selectors() wire.Carrier {
	switch m {
	case ModeTCP:
		return wire.CarrierTLSTCP
	case ModeUDP:
		return wire.CarrierQUIC
	default:
		return 0
	}
}

func carrierMode(carrier wire.Carrier) (CarrierMode, error) {
	switch carrier {
	case wire.CarrierTLSTCP:
		return ModeTCP, nil
	case wire.CarrierQUIC:
		return ModeUDP, nil
	default:
		return 0, errors.New("nowhere: invalid carrier selector")
	}
}
