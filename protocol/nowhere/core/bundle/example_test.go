package bundle_test

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type exampleTCPDialer struct{}

func (exampleTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("example dialer is not connected")
}

type exampleTLSDialer struct{}

func (exampleTLSDialer) DialTLSConn(context.Context, net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{}, errors.New("example TLS dialer is not connected")
}

func ExampleNewCarrierBundle() {
	credentials, err := wire.NewCredentials("example-shared-key")
	if err != nil {
		panic(err)
	}
	tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address:   "portal.example:443",
		Dialer:    exampleTCPDialer{},
		TLSDialer: exampleTLSDialer{},
	})
	if err != nil {
		panic(err)
	}

	b, err := bundle.NewCarrierBundle(bundle.BundleOptions{
		TCP:         tcp,
		Credentials: credentials,
		PoolSize:    tcptls.DefaultPoolSize,
		Up:          wire.CarrierTLSTCP,
		Down:        wire.CarrierTLSTCP,
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = b.Close() }()

	fmt.Printf("symmetric tcp bundle: %t\n", !b.Asymmetric())
	// Output:
	// symmetric tcp bundle: true
}
