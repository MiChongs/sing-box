package quicsettings

import E "github.com/sagernet/sing/common/exceptions"

// CongestionControl selects the host-side QUIC congestion controller.
// It deliberately has no dependency on a QUIC implementation so TCP-only
// builds can still validate the public option.
type CongestionControl uint8

const (
	CongestionControlBBR CongestionControl = iota
	CongestionControlBBRStandard
	CongestionControlBBR2
	CongestionControlBBR2Variant
	CongestionControlCubic
	CongestionControlReno
)

func (c CongestionControl) String() string {
	switch c {
	case CongestionControlBBRStandard:
		return "bbr_standard"
	case CongestionControlBBR2:
		return "bbr2"
	case CongestionControlBBR2Variant:
		return "bbr2_variant"
	case CongestionControlCubic:
		return "cubic"
	case CongestionControlReno:
		return "reno"
	default:
		return "bbr"
	}
}

// ParseCongestionControl validates the public Nowhere option. Empty defaults
// to BBR and values are intentionally case-sensitive.
func ParseCongestionControl(value string) (CongestionControl, error) {
	switch value {
	case "", "bbr":
		return CongestionControlBBR, nil
	case "bbr_standard":
		return CongestionControlBBRStandard, nil
	case "bbr2":
		return CongestionControlBBR2, nil
	case "bbr2_variant":
		return CongestionControlBBR2Variant, nil
	case "cubic":
		return CongestionControlCubic, nil
	case "reno":
		return CongestionControlReno, nil
	default:
		return 0, E.New("unknown quic congestion control: ", value)
	}
}
