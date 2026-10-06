package bundle

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestReadSetupResultExposesCode(t *testing.T) {
	for code := wire.SetupResultInvalidRequest; code <= wire.SetupResultInternalError; code++ {
		frame, err := wire.EncodeSetupResult(code)
		if err != nil {
			t.Fatal(err)
		}
		err = readSetupResult(bytes.NewReader(frame[:]))
		var resultErr *SetupResultError
		if !errors.As(err, &resultErr) || resultErr.Code != code {
			t.Fatalf("code %d error = %v", code, err)
		}
		wrapped := fmtError("setup phase", err)
		if !errors.As(wrapped, &resultErr) || resultErr.Code != code {
			t.Fatalf("wrapped code %d error = %v", code, wrapped)
		}
	}
}

type closingBackend struct {
	err error
}

func (*closingBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("unused")
}
func (*closingBackend) InvalidateSession(carrier.QuicSession) {}
func (b *closingBackend) Close() error                        { return b.err }

func TestCarrierBundleCloseDoesNotInitializeAndMemoizesErrors(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("backend close")
	backend := &closingBackend{err: closeErr}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: backend, Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Close before first use must not invoke lazy resource construction.
	if err := bundle.Close(); err != nil {
		t.Fatalf("uninitialized close = %v", err)
	}

	bundle, err = NewCarrierBundle(BundleOptions{
		QUIC: backend, Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.quicClient(); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("close = %v", err)
	}
	if err := bundle.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("memoized close = %v", err)
	}
}
