package quic

import "context"

// AcceptStream is a host-provided QUIC bidirectional stream.
type AcceptStream interface {
	context.Context
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}
