package wire

import (
	"fmt"
	"io"
)

// SetupResultLen is the fixed setup-result frame length.
const SetupResultLen = 1

// SetupResult is the direct wire representation of a flow setup outcome.
type SetupResult uint8

const (
	// SetupResultReady indicates that the target path is established.
	SetupResultReady SetupResult = 0
	// SetupResultInvalidRequest rejects malformed flow metadata.
	SetupResultInvalidRequest SetupResult = 1
	// SetupResultMetadataConflict rejects incompatible OPEN and ATTACH halves.
	SetupResultMetadataConflict SetupResult = 2
	// SetupResultPairTimeout indicates that the matching split half did not arrive.
	SetupResultPairTimeout SetupResult = 3
	// SetupResultFlowLimit indicates that a flow or pairing limit was reached.
	SetupResultFlowLimit SetupResult = 4
	// SetupResultDialFailed indicates that Portal could not establish the target path.
	SetupResultDialFailed SetupResult = 5
	// SetupResultSessionReplaced indicates that a newer QUIC carrier replaced the session.
	SetupResultSessionReplaced SetupResult = 6
	// SetupResultInternalError indicates an internal setup failure.
	SetupResultInternalError SetupResult = 7
)

// SetupResult values 0..7; used for validation.
const setupResultMax = 7

// IsReady reports whether the result indicates a successful setup.
func (r SetupResult) IsReady() bool { return r == SetupResultReady }

// Validate rejects values that are not defined by the one-byte v1 result
// space.
func (r SetupResult) Validate() error {
	if r > setupResultMax {
		return ErrInvalidSetupResult
	}
	return nil
}

// String returns a stable human label for diagnostics.
func (r SetupResult) String() string {
	switch r {
	case SetupResultReady:
		return "ready"
	case SetupResultInvalidRequest:
		return "invalid request"
	case SetupResultMetadataConflict:
		return "metadata conflict"
	case SetupResultPairTimeout:
		return "pair timeout"
	case SetupResultFlowLimit:
		return "flow limit"
	case SetupResultDialFailed:
		return "dial failed"
	case SetupResultSessionReplaced:
		return "session replaced"
	case SetupResultInternalError:
		return "internal error"
	default:
		return "unknown"
	}
}

// EncodeSetupResult encodes a setup result as a single byte.
func EncodeSetupResult(r SetupResult) ([SetupResultLen]byte, error) {
	if err := r.Validate(); err != nil {
		return [SetupResultLen]byte{}, err
	}
	return [SetupResultLen]byte{byte(r)}, nil
}

// DecodeSetupResult decodes exactly one byte into a setup result.
func DecodeSetupResult(b []byte) (SetupResult, error) {
	if len(b) != SetupResultLen {
		return 0, ErrInvalidSetupResult
	}
	return parseSetupResult(b[0])
}

func parseSetupResult(v byte) (SetupResult, error) {
	if v > setupResultMax {
		return 0, ErrInvalidSetupResult
	}
	return SetupResult(v), nil
}

// WriteSetupResult writes a single-byte setup result.
func WriteSetupResult(w io.Writer, r SetupResult) error {
	frame, err := EncodeSetupResult(r)
	if err != nil {
		return err
	}
	if err := WriteFull(w, frame[:]); err != nil {
		return fmt.Errorf("nowhere: write setup result: %w", err)
	}
	return nil
}

// ReadSetupResult reads a single-byte setup result.
func ReadSetupResult(r io.Reader) (SetupResult, error) {
	var b [SetupResultLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return parseSetupResult(b[0])
}
