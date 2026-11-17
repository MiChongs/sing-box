package sniff

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type (
	StreamSniffer = func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error
	PacketSniffer = func(ctx context.Context, metadata *adapter.InboundContext, packet []byte) error
)

var ErrNeedMoreData = E.New("need more data")

func Skip(metadata *adapter.InboundContext) bool {
	// skip server first protocols
	switch metadata.Destination.Port {
	case 25, 465, 587:
		// SMTP
		return true
	case 143, 993:
		// IMAP
		return true
	case 110, 995:
		// POP3
		return true
	}
	return false
}

// PeekStream sniffs the first payload of conn. buffers hold payload already
// read from conn by an earlier sniff; newly read payload is appended to buffer.
//
// Payload in buffers is sniffed before conn is read again: a client that sent
// its whole first flight is waiting for the server, so another read would only
// time out and lose the result. conn is read further only when a sniffer
// reports ErrNeedMoreData.
func PeekStream(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn, buffers []*buf.Buffer, buffer *buf.Buffer, timeout time.Duration, sniffers ...StreamSniffer) error {
	if timeout == 0 {
		timeout = C.ReadPayloadTimeout
	}
	var sniffError error
	buffered := len(buffers) > 0
	if buffered {
		sniffError = sniffStream(ctx, metadata, buffers, sniffers)
		if sniffError == nil || !errors.Is(sniffError, ErrNeedMoreData) {
			return sniffError
		}
	}
	deadline := time.Now().Add(timeout)
	for i := 0; ; i++ {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return E.Cause(err, "set read deadline")
		}
		_, err = buffer.ReadOnceFrom(conn)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			if i > 0 || buffered {
				break
			}
			return E.Cause(err, "read payload")
		}
		sniffError = sniffStream(ctx, metadata, append(buffers, buffer), sniffers)
		if sniffError == nil || !errors.Is(sniffError, ErrNeedMoreData) {
			break
		}
	}
	return sniffError
}

func sniffStream(ctx context.Context, metadata *adapter.InboundContext, buffers []*buf.Buffer, sniffers []StreamSniffer) error {
	var sniffError error
	for _, sniffer := range sniffers {
		reader := io.MultiReader(common.Map(buffers, func(it *buf.Buffer) io.Reader {
			return bytes.NewReader(it.Bytes())
		})...)
		err := sniffer(ctx, metadata, reader)
		if err == nil {
			return nil
		}
		sniffError = E.Errors(sniffError, err)
	}
	return sniffError
}

func PeekPacket(ctx context.Context, metadata *adapter.InboundContext, packet []byte, sniffers ...PacketSniffer) error {
	var sniffError []error
	for _, sniffer := range sniffers {
		err := sniffer(ctx, metadata, packet)
		if err == nil {
			return nil
		}
		sniffError = append(sniffError, err)
	}
	return E.Errors(sniffError...)
}
