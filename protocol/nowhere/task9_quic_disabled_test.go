//go:build !with_quic

package nowhere

import (
	"context"
	"errors"
	"testing"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func TestQUICDisabledTCPOnlyConstruction(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	outbound, err := NewOutbound(context.Background(), nil, logger, "nw-out", tcpOnlyOutboundOptions())
	if err != nil {
		t.Fatalf("TCP-only outbound: %v", err)
	}
	if err := outbound.(*Outbound).Close(); err != nil {
		t.Fatal(err)
	}

	keyPEM, certificatePEM, err := boxTLS.GenerateCertificate(nil, nil, time.Now, "example.org", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := NewInbound(context.Background(), nil, logger, "nw-in", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled: true, Certificate: badoption.Listable[string]{string(certificatePEM)}, Key: badoption.Listable[string]{string(keyPEM)},
			},
		},
	})
	if err != nil {
		t.Fatalf("TCP-only inbound: %v", err)
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQUICDisabledUDPMatrixReturnsQUICNotIncluded(t *testing.T) {
	for _, matrix := range [][2]string{{"udp", "udp"}, {"tcp", "udp"}, {"udp", "tcp"}} {
		options := tcpOnlyOutboundOptions()
		options.Up, options.Down = matrix[0], matrix[1]
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "nw", options)
		if !errors.Is(err, C.ErrQUICNotIncluded) {
			t.Fatalf("matrix %s/%s error = %v, want ErrQUICNotIncluded", matrix[0], matrix[1], err)
		}
	}
}
