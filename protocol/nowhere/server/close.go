package server

import (
	"errors"
	"net"
)

// WithoutErrClosed drops net.ErrClosed from a close result. The inbound
// listener and the QUIC server share one UDP socket, and both release it on
// shutdown: whichever of them closes it second observes the socket already
// closed, which is not a shutdown failure.
func WithoutErrClosed(err error) error {
	if err == nil {
		return nil
	}
	if joined, isJoined := err.(interface{ Unwrap() []error }); isJoined {
		var kept []error
		for _, inner := range joined.Unwrap() {
			if inner = WithoutErrClosed(inner); inner != nil {
				kept = append(kept, inner)
			}
		}
		return errors.Join(kept...)
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
