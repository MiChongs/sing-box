package bundle

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestNewCarrierBundleMixRequiresBothBackends(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	tcp := newMuxTestTCP(t)
	_, err = NewCarrierBundle(BundleOptions{
		TCP: tcp, Credentials: credentials,
		MixUp: true, MixDown: true,
	})
	if err == nil {
		t.Fatal("expected mix without QUIC to fail")
	}
	_, err = NewCarrierBundle(BundleOptions{
		QUIC: &closingBackend{}, Credentials: credentials,
		MixUp: true, Down: wire.CarrierQUIC,
	})
	if err == nil {
		t.Fatal("expected mix without TCP to fail")
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: tcp, QUIC: &closingBackend{}, Credentials: credentials,
		MixUp: true, MixDown: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.MixEnabled() || b.UpMode() != ModeMix || b.DownMode() != ModeMix {
		t.Fatalf("modes up=%s down=%s mix=%t", b.UpMode(), b.DownMode(), b.MixEnabled())
	}
	if b.Asymmetric() {
		t.Fatal("mix/mix is not asymmetric")
	}
	if b.UpCarrier() != 0 || b.DownCarrier() != 0 {
		t.Fatalf("mix carriers = %d/%d, want 0/0", b.UpCarrier(), b.DownCarrier())
	}
}

func TestNewCarrierBundleCanonicalizesOnlyMixedCarrier(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		Up: wire.CarrierQUIC, MixUp: true, Down: wire.CarrierTLSTCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.UpCarrier() != 0 || b.DownCarrier() != wire.CarrierTLSTCP {
		t.Fatalf("carriers = %d/%d", b.UpCarrier(), b.DownCarrier())
	}
	if b.UpMode() != ModeMix || b.DownMode() != ModeTCP {
		t.Fatalf("modes = %s/%s", b.UpMode(), b.DownMode())
	}
}

func TestNewCarrierBundleMixRejectsDedicatedPool(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		PoolSize: 5, MixUp: true, Down: wire.CarrierTLSTCP,
	})
	if err == nil {
		t.Fatal("expected mix+pool to fail")
	}
}

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

func TestMixKeepsMuxEnabled(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		MixUp: true, MixDown: true, Mux: MuxEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.cfg.mux != MuxEnabled {
		t.Fatalf("mux=%d", b.cfg.mux)
	}
}

func TestNegativeMixFallbackTimeout(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCarrierBundle(BundleOptions{
		TCP: newMuxTestTCP(t), QUIC: &closingBackend{}, Credentials: credentials,
		MixUp: true, MixDown: true, MixFallbackTimeout: -time.Second,
	})
	if err == nil {
		t.Fatal("expected negative timeout to fail")
	}
}

func TestCarrierModeSelectors(t *testing.T) {
	carrier, mix := ModeMix.Selectors()
	if carrier != 0 || !mix {
		t.Fatalf("mix selectors = %d %t", carrier, mix)
	}
	carrier, mix = ModeTCP.Selectors()
	if carrier != wire.CarrierTLSTCP || mix {
		t.Fatalf("tcp selectors = %d %t", carrier, mix)
	}
}
