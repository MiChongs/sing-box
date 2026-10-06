//go:build with_quic

package quicx

import (
	"context"

	"github.com/sagernet/quic-go"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseBBRProfile(profile string) (congestion_meta2.Profile, error) {
	if profile == "" {
		return congestion_meta2.ProfileConservative, nil
	}
	parsed, err := congestion_meta2.ParseProfile(profile)
	if err != nil {
		return congestion_meta2.Profile{}, E.Cause(err, "parse BBR profile")
	}
	return parsed, nil
}

func setCongestion(ctx context.Context, connection *quic.Conn, profile congestion_meta2.Profile) {
	connection.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
		connection.InitialPacketSize(),
		profile,
	))
}
