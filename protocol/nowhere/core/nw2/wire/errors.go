package wire

import "errors"

// Codec errors. They are intentionally coarse: Nowhere 2 closes a connection
// on any protocol violation and never distinguishes failure causes to the peer.
var (
	ErrInvalidTarget        = errors.New("nowhere: invalid target address")
	ErrInvalidFrame         = errors.New("nowhere: invalid frame")
	ErrInvalidFlowHeader    = errors.New("nowhere: invalid flow header")
	ErrInvalidMuxHeader     = errors.New("nowhere: invalid mux header")
	ErrInvalidAuthFrame     = errors.New("nowhere: invalid authentication frame")
	ErrInvalidAuthTransport = errors.New("nowhere: invalid authentication transport")
	ErrMissingCredentials   = errors.New("nowhere: missing credentials")
	ErrInvalidSetupResult   = errors.New("nowhere: invalid setup result")
	ErrTruncated            = errors.New("nowhere: truncated input")
)
