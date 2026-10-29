package bundle

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func TestUDPUDPMuxCanonicalizesToDisabled(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		QUIC: &closingBackend{}, Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC, Mux: MuxEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.cfg.mux != MuxDisabled {
		t.Fatalf("mux=%d", b.cfg.mux)
	}
}

func TestNewCarrierBundleRequiresMatchingBackends(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err == nil {
		t.Fatal("expected udp/udp without QUIC to fail")
	}
	_, err = NewCarrierBundle(BundleOptions{
		QUIC: &closingBackend{}, Credentials: credentials,
		Up: wire.CarrierTLSTCP, Down: wire.CarrierTLSTCP,
	})
	if err == nil {
		t.Fatal("expected tcp/tcp without TCP to fail")
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		Up: wire.CarrierTLSTCP, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.UpCarrier() != wire.CarrierTLSTCP || b.DownCarrier() != wire.CarrierQUIC {
		t.Fatalf("carriers = %d/%d", b.UpCarrier(), b.DownCarrier())
	}
	if b.UpMode() != ModeTCP || b.DownMode() != ModeUDP {
		t.Fatalf("modes = %s/%s", b.UpMode(), b.DownMode())
	}
	if !b.Asymmetric() {
		t.Fatal("tcp/udp is asymmetric")
	}
}

func TestNewCarrierBundleRejectsPoolWithQUICRoute(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		PoolSize: 5, Up: wire.CarrierQUIC, Down: wire.CarrierTLSTCP,
	})
	if err == nil {
		t.Fatal("expected pool with QUIC route to fail")
	}
}

func TestCarrierModeSelectors(t *testing.T) {
	if carrier := ModeTCP.Selectors(); carrier != wire.CarrierTLSTCP {
		t.Fatalf("tcp selector = %d", carrier)
	}
	if carrier := ModeUDP.Selectors(); carrier != wire.CarrierQUIC {
		t.Fatalf("udp selector = %d", carrier)
	}
}
