package wire

import (
	"errors"
	"io"
)

// SetupResult is the one-byte flow setup outcome.
type SetupResult uint8

const (
	// SetupReady means the target path is established.
	SetupReady SetupResult = 0
	// SetupInvalidRequest rejects a malformed flow.
	SetupInvalidRequest SetupResult = 1
	// SetupFlowLimit is resource exhaustion.
	SetupFlowLimit SetupResult = 2
	// SetupDialFailed is target or offline-egress failure.
	SetupDialFailed SetupResult = 3
	// SetupInternalError is an internal setup failure.
	SetupInternalError SetupResult = 4
)

// RegistrationResult is the one-byte Egress registration outcome.
type RegistrationResult uint8

const (
	// RegistrationAccepted claims the vacant slot.
	RegistrationAccepted RegistrationResult = 0
	// RegistrationBusy leaves the current owner in place.
	RegistrationBusy RegistrationResult = 1
)

// ParseSetupResult rejects values outside 0..4.
func ParseSetupResult(b byte) (SetupResult, error) {
	if b > byte(SetupInternalError) {
		return 0, errors.New("nw3: invalid setup result")
	}
	return SetupResult(b), nil
}

// ReadSetupResult reads one setup byte.
func ReadSetupResult(r io.Reader) (SetupResult, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return ParseSetupResult(b[0])
}

// WriteSetupResult writes one setup byte.
func WriteSetupResult(w io.Writer, result SetupResult) error {
	if _, err := ParseSetupResult(byte(result)); err != nil {
		return err
	}
	_, err := w.Write([]byte{byte(result)})
	return err
}

// ParseRegistrationResult rejects values other than ACCEPTED or BUSY.
func ParseRegistrationResult(b byte) (RegistrationResult, error) {
	switch RegistrationResult(b) {
	case RegistrationAccepted, RegistrationBusy:
		return RegistrationResult(b), nil
	default:
		return 0, errors.New("nw3: invalid registration result")
	}
}

// WriteRegistrationResult writes ACCEPTED or BUSY.
func WriteRegistrationResult(w io.Writer, result RegistrationResult) error {
	if _, err := ParseRegistrationResult(byte(result)); err != nil {
		return err
	}
	_, err := w.Write([]byte{byte(result)})
	return err
}

// ReadRegistrationResult reads one registration byte.
func ReadRegistrationResult(r io.Reader) (RegistrationResult, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return ParseRegistrationResult(b[0])
}

func (r SetupResult) Error() string {
	switch r {
	case SetupReady:
		return "ready"
	case SetupInvalidRequest:
		return "invalid request"
	case SetupFlowLimit:
		return "flow limit"
	case SetupDialFailed:
		return "dial failed"
	case SetupInternalError:
		return "internal error"
	default:
		return "invalid setup result"
	}
}

// SetupError is a rejected setup result returned to callers.
type SetupError struct{ Result SetupResult }

func (e SetupError) Error() string { return "nw3: " + e.Result.Error() }
