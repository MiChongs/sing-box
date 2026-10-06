package bundle

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type muxTestDialer struct{}

func (muxTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("mux test dialer is not connected")
}

type muxTestTLSDialer struct{}

func (muxTestTLSDialer) DialTLSConn(context.Context, net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{}, errors.New("mux test TLS dialer is not connected")
}

func newMuxTestTCP(t *testing.T) *tcptls.Config {
	t.Helper()
	cfg, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:2077", Dialer: muxTestDialer{}, TLSDialer: muxTestTLSDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestMuxModeRejectsInvalidValue(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), Credentials: credentials,
		Up: wire.CarrierTLSTCP, Down: wire.CarrierTLSTCP, Mux: 2,
	})
	if err == nil {
		t.Fatal("expected invalid mux mode to fail")
	}
}

func TestMuxEnabledRejectsDedicatedPool(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), Credentials: credentials,
		PoolSize: 5, Up: wire.CarrierTLSTCP, Down: wire.CarrierTLSTCP, Mux: MuxEnabled,
	})
	if err == nil {
		t.Fatal("expected mux+pool to fail")
	}
}

func TestMuxEnabledConstructsWithoutPool(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), Credentials: credentials,
		Up: wire.CarrierTLSTCP, Down: wire.CarrierTLSTCP, Mux: MuxEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.cfg.mux != MuxEnabled {
		t.Fatalf("mux=%d", b.cfg.mux)
	}
}
