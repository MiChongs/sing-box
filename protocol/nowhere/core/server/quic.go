package server

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// QuicStream is one bidirectional QUIC stream.
type QuicStream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	CancelRead(code uint64)
	CancelWrite(code uint64)
}

// QuicConn is one authenticated (or pre-auth) QUIC connection.
// Hosts adapt quic-go / sing-quic to this interface; nowhere-go never imports quic-go.
//
// CloseWithError is the physical abort boundary used by server cleanup. It must
// return promptly without waiting for concurrent SendDatagram, ReceiveDatagram,
// or AcceptStream calls, and it must promptly cause all such blocked calls to
// return. Core may then synchronously join those calls; implementations must not
// create a CloseWithError <-> operation wait cycle. Host conformance is enforced
// by adapters separately from this interface contract.
type QuicConn interface {
	TLSHandshakeInfo() (wire.TLSHandshakeInfo, error)
	AcceptStream(ctx context.Context) (QuicStream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(ctx context.Context, b []byte) error
	CloseWithError(code uint64, message string) error
	Close() error
	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// QuicAuthenticationNotifier is an optional host capability. A QUIC adapter
// that enforces its own pre-auth stream gate implements it and starts admitting
// flow streams once the core reports successful authentication (after session
// registration in the current core implementation).
//
// MarkAuthenticated must be non-blocking and idempotent. It is deliberately
// separate from QuicConn: not every host has a transport-specific stream gate.
type QuicAuthenticationNotifier interface {
	MarkAuthenticated()
}

// QuicListener accepts QuicConn connections.
type QuicListener interface {
	Accept(ctx context.Context) (QuicConn, error)
	Close() error
}
