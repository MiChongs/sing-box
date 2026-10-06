package server

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestSetupFailureCodeMatrix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want wire.SetupResult
	}{
		{"explicit ready", &setupResultError{code: wire.SetupResultReady}, wire.SetupResultReady},
		{"physical carrier mismatch", ErrCarrierMismatch, wire.SetupResultInvalidRequest},
		{"invalid frame", wire.ErrInvalidFrame, wire.SetupResultInvalidRequest},
		{"metadata conflict", ErrMetadataConflict, wire.SetupResultMetadataConflict},
		{"duplicate half", ErrDuplicateHalf, wire.SetupResultMetadataConflict},
		{"pair timeout", ErrPairTimeout, wire.SetupResultPairTimeout},
		{"flow limit", ErrPairLimit, wire.SetupResultFlowLimit},
		{"session limit", ErrSessionLimit, wire.SetupResultFlowLimit},
		{"explicit dial failure", &setupResultError{code: wire.SetupResultDialFailed}, wire.SetupResultDialFailed},
		{"session replaced", ErrClosed, wire.SetupResultSessionReplaced},
		{"network closed", net.ErrClosed, wire.SetupResultSessionReplaced},
		{"context canceled", context.Canceled, wire.SetupResultSessionReplaced},
		{"internal handler", ErrInvalidHandler, wire.SetupResultInternalError},
		{"internal upstream", ErrUpstreamNotConfigured, wire.SetupResultInternalError},
		{"ordinary dial error", errors.New("dial refused"), wire.SetupResultDialFailed},
	}
	seen := make(map[wire.SetupResult]bool)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := setupFailureCode(tc.err)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			seen[got] = true
		})
	}
	for code := wire.SetupResultReady; code <= wire.SetupResultInternalError; code++ {
		if !seen[code] {
			t.Fatalf("result code %d is not covered", code)
		}
	}
}

func TestMetadataErrorIdentity(t *testing.T) {
	if !errors.Is(ErrDuplicateHalf, ErrMetadataConflict) {
		t.Fatal("duplicate half is not a metadata conflict")
	}
	if errors.Is(ErrCarrierMismatch, ErrMetadataConflict) {
		t.Fatal("physical mismatch aliases metadata conflict")
	}
}
