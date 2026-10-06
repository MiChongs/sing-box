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

func TestQUICDisabledAllowsTCPOnlyOutbound(t *testing.T) {
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "nw", tcpOnlyOutboundOptions())
	if err != nil {
		t.Fatal(err)
	}
	_ = outbound.(*Outbound).Close()
}

func TestQUICDisabledRejectsUDPOutbound(t *testing.T) {
	options := tcpOnlyOutboundOptions()
	options.Up = "udp"
	options.Down = "udp"
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "nw", options)
	if !errors.Is(err, C.ErrQUICNotIncluded) {
		t.Fatalf("NewOutbound error = %v, want ErrQUICNotIncluded", err)
	}
}

func TestQUICDisabledAllowsTCPOnlyInbound(t *testing.T) {
	keyPEM, certificatePEM, err := boxTLS.GenerateCertificate(nil, nil, time.Now, "example.org", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled: true, Certificate: badoption.Listable[string]{string(certificatePEM)}, Key: badoption.Listable[string]{string(keyPEM)},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = inbound.Close()
}

func TestQUICDisabledRejectsUDPInbound(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkUDP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true},
		},
	})
	if !errors.Is(err, C.ErrQUICNotIncluded) {
		t.Fatalf("NewInbound error = %v, want ErrQUICNotIncluded", err)
	}
}

func tcpOnlyOutboundOptions() option.NowhereOutboundOptions {
	pool := 0
	return option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          &pool,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true, Insecure: true, ALPN: badoption.Listable[string]{"nw2"},
			},
		},
	}
}
