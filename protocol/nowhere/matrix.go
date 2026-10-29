package nowhere

import (
	"fmt"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

const (
	DefaultUp       = "udp"
	DefaultDown     = "udp"
	DefaultPoolSize = 5
	MaxPoolSize     = tcptls.MaxPoolSize
)

// MatrixInputs is the host-facing carrier/mux/pool policy before it is mapped
// onto a nw2 core bundle.BundleOptions.
type MatrixInputs struct {
	Up   string
	Down string
	Pool *int
	Mux  *int
}

// Matrix is the resolved Nowhere 2.2.1 client route: concrete carriers, TLS Mux,
// and the dedicated tcp/tcp warm pool.
type Matrix struct {
	Up, Down   string
	Pool       int
	Mux        bundle.MuxMode
	Asymmetric bool
	NeedsQUIC  bool
	NeedsTCP   bool
	warnings   []string
}

// ResolveMatrix applies Nowhere 2.2.1 outbound defaults and pool/mux rules.
//
// Carriers default to udp/udp and must be tcp or udp; mix is not a carrier.
// mux=1 enables TLS Mux when TCP is possible; udp/udp&mux=1 canonicalizes to 0.
// The warm pool applies only to dedicated (mux=0) tcp/tcp.
func ResolveMatrix(in MatrixInputs) (Matrix, error) {
	up, down := in.Up, in.Down
	if up == "" && down == "" {
		up, down = DefaultUp, DefaultDown
	}
	if (up == "") != (down == "") {
		return Matrix{}, fmt.Errorf("nowhere: up and down must both be set or both omitted")
	}
	if up == "mix" || down == "mix" {
		return Matrix{}, fmt.Errorf("nowhere: mix is not a carrier; up and down must be tcp or udp")
	}
	if !isCarrierMode(up) || !isCarrierMode(down) {
		return Matrix{}, fmt.Errorf("nowhere: invalid carrier selector up=%q down=%q", up, down)
	}

	needsTCP := up != "udp" || down != "udp"
	needsQUIC := up != "tcp" || down != "tcp"
	mux := bundle.MuxDisabled
	if in.Mux != nil {
		switch *in.Mux {
		case 0:
			mux = bundle.MuxDisabled
		case 1:
			mux = bundle.MuxEnabled
		default:
			return Matrix{}, fmt.Errorf("nowhere: mux must be 0 or 1")
		}
	}

	m := Matrix{
		Up: up, Down: down,
		Mux:        mux,
		Asymmetric: up != down,
		NeedsQUIC:  needsQUIC,
		NeedsTCP:   needsTCP,
	}
	if mux == bundle.MuxEnabled && !needsTCP {
		m.warnings = append(m.warnings, "nowhere: mux=1 is canonicalized to 0 for udp/udp")
		m.Mux = bundle.MuxDisabled
	}

	switch {
	case needsQUIC:
		if in.Pool != nil && *in.Pool != 0 {
			m.warnings = append(m.warnings, fmt.Sprintf("nowhere: pool is only effective for dedicated tcp/tcp; ignoring configured value %d", *in.Pool))
		}
	case m.Mux == bundle.MuxEnabled:
		if in.Pool != nil && *in.Pool != 0 {
			m.warnings = append(m.warnings, fmt.Sprintf("nowhere: pool must be zero when TLS mux is enabled; ignoring configured value %d", *in.Pool))
		}
	default:
		if in.Pool == nil {
			m.Pool = DefaultPoolSize
		} else if *in.Pool < 0 {
			return Matrix{}, fmt.Errorf("nowhere: pool must be >= 0")
		} else if *in.Pool > MaxPoolSize {
			m.Pool = MaxPoolSize
			m.warnings = append(m.warnings, fmt.Sprintf("nowhere: pool %d exceeds maximum %d; using %d", *in.Pool, MaxPoolSize, MaxPoolSize))
		} else {
			m.Pool = *in.Pool
		}
	}
	return m, nil
}

// Warnings returns non-fatal canonicalization messages.
func (m Matrix) Warnings() []string { return m.warnings }

// UpCarrier is the bundle uplink selector.
func (m Matrix) UpCarrier() wire.Carrier {
	if m.Up == "tcp" {
		return wire.CarrierTLSTCP
	}
	return wire.CarrierQUIC
}

// DownCarrier is the bundle downlink selector.
func (m Matrix) DownCarrier() wire.Carrier {
	if m.Down == "tcp" {
		return wire.CarrierTLSTCP
	}
	return wire.CarrierQUIC
}

func isCarrierMode(s string) bool {
	return s == "tcp" || s == "udp"
}

// RequiresFlowEnvelope reports whether asymmetric FLOW_OPEN/FLOW_ATTACH must be used.
func (m Matrix) RequiresFlowEnvelope() bool { return m.Asymmetric }

// FlowKindForNetwork maps a user flow to wire.FlowKind.
func FlowKindForNetwork(network string) (wire.FlowKind, error) {
	switch network {
	case "tcp":
		return wire.FlowKindTCP, nil
	case "udp":
		return wire.FlowKindUDP, nil
	default:
		return 0, fmt.Errorf("nowhere: invalid flow kind %q", network)
	}
}
