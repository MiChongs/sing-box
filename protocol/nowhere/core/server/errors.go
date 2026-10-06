package server

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidConfig identifies rejected configuration input.
	ErrInvalidConfig = errors.New("nowhere: invalid server config")
	// ErrInvalidHandler identifies an unusable or nil handler dependency.
	ErrInvalidHandler = errors.New("nowhere: invalid handler")
	// ErrPairTimeout identifies an asymmetric half that was not paired in time.
	ErrPairTimeout = errors.New("nowhere: flow pair timeout")
	// ErrPairLimit identifies an exhausted pending-pair budget.
	ErrPairLimit = errors.New("nowhere: pending flow pair limit reached")
	// ErrCarrierMismatch identifies a FLOW header that disagrees with the
	// physical carrier it arrived on.
	ErrCarrierMismatch = errors.New("nowhere: flow physical carrier mismatch")
	// ErrMetadataConflict identifies incompatible OPEN/ATTACH flow metadata.
	ErrMetadataConflict = errors.New("nowhere: flow metadata conflict")
	// ErrDuplicateHalf identifies two halves claiming the same role.
	ErrDuplicateHalf = fmt.Errorf("%w: duplicate flow half", ErrMetadataConflict)
	// ErrSessionLimit identifies an exhausted active-session budget.
	ErrSessionLimit = errors.New("nowhere: active session limit reached")
	// ErrAdmissionLimit identifies an exhausted pre-authentication admission budget.
	ErrAdmissionLimit = errors.New("nowhere: unauthenticated connection limit exceeded")
	// ErrUpstreamNotConfigured identifies a missing flow destination.
	ErrUpstreamNotConfigured = errors.New("nowhere: upstream not configured")
	// ErrDraining identifies work rejected after the server has closed flow
	// admission but before final transport cleanup.
	ErrDraining = errors.New("nowhere: server draining")
	// ErrClosed identifies operations attempted after manager shutdown.
	ErrClosed = errors.New("nowhere: manager closed")
	// ErrQUICNotConfigured identifies an enabled UDP carrier without a listener.
	ErrQUICNotConfigured = errors.New("nowhere: QUIC enabled but no QuicListener injected")
	// ErrTLSNotConfigured identifies an enabled TCP carrier without a handshaker.
	ErrTLSNotConfigured = errors.New("nowhere: TCP enabled but no TLS handshaker configured")
	// ErrUnsupportedFlow identifies a valid frame unsupported by this endpoint.
	ErrUnsupportedFlow = errors.New("nowhere: unsupported flow")
	// ErrPortalHopLimit identifies a native Portal forwarding attempt whose
	// remaining HOPS budget is one and therefore cannot be forwarded again.
	ErrPortalHopLimit = errors.New("nowhere: native Portal forwarding hop limit reached")
)

// ReportedError marks an error that the protocol core already emitted to Observer.
// Host adapters should avoid logging the same failure again.
type ReportedError struct {
	Err error
}

func (e *ReportedError) Error() string {
	if e == nil || e.Err == nil {
		return "nowhere: reported error"
	}
	return e.Err.Error()
}

func (e *ReportedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsReported reports whether err (or any wrapped error) was already observed.
func IsReported(err error) bool {
	var reported *ReportedError
	return errors.As(err, &reported)
}

// report wraps err as ReportedError when non-nil.
func report(err error) error {
	if err == nil {
		return nil
	}
	if IsReported(err) {
		return err
	}
	return &ReportedError{Err: err}
}
