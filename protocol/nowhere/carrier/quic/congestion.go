//go:build with_quic

package quic

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

type CongestionControl = quicsettings.CongestionControl

const (
	CongestionControlBBR         = quicsettings.CongestionControlBBR
	CongestionControlBBRStandard = quicsettings.CongestionControlBBRStandard
	CongestionControlBBR2        = quicsettings.CongestionControlBBR2
	CongestionControlBBR2Variant = quicsettings.CongestionControlBBR2Variant
	CongestionControlCubic       = quicsettings.CongestionControlCubic
	CongestionControlReno        = quicsettings.CongestionControlReno
)

var ParseCongestionControl = quicsettings.ParseCongestionControl

// NewCongestionController constructs the selected controller for one QUIC connection.
//
// sing-quic v0.7 dropped the standalone BBR1/BBR2 packages. Public option names
// are unchanged: bbr/bbr_standard use the standard BBR profile, bbr2 uses
// conservative, and bbr2_variant uses aggressive.
func NewCongestionController(ctx context.Context, connection *quic.Conn, selected CongestionControl) congestion.CongestionControl {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	packetSize := connection.InitialPacketSize()
	switch selected {
	case CongestionControlBBR2:
		return congestion_meta2.NewBbrSenderWithProfile(packetSize, congestion_meta2.ProfileConservative)
	case CongestionControlBBR2Variant:
		return congestion_meta2.NewBbrSenderWithProfile(packetSize, congestion_meta2.ProfileAggressive)
	case CongestionControlCubic:
		return congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			packetSize,
			false,
		)
	case CongestionControlReno:
		return congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			packetSize,
			true,
		)
	case CongestionControlBBR, CongestionControlBBRStandard:
		fallthrough
	default:
		return congestion_meta2.NewBbrSenderWithProfile(packetSize, congestion_meta2.ProfileStandard)
	}
}
