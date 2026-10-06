package diagnostic

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
)

// ClassifyClose maps a close/read/write error into result + error_class.
func ClassifyClose(err error) (result, class string) {
	if err == nil {
		return ResultOK, ""
	}
	if errors.Is(err, context.Canceled) {
		return ResultCanceled, ErrorClassLocalCancel
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ResultTimeout, ErrorClassNetwork
	}
	// Normal peer EOF is a successful close, not a canceled flow.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ResultOK, ErrorClassRemoteClose
	}
	if errors.Is(err, net.ErrClosed) {
		return ResultCanceled, ErrorClassRemoteClose
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "canceled by local"),
		strings.Contains(msg, "cancelled by local"),
		strings.Contains(msg, "stream canceled"),
		strings.Contains(msg, "stream cancelled"):
		return ResultCanceled, ErrorClassLocalCancel
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "timeout"):
		return ResultFailed, ErrorClassNetwork
	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "use of closed network connection"):
		return ResultCanceled, ErrorClassRemoteClose
	default:
		return ResultFailed, ErrorClassProtocol
	}
}

// IsBenignClose reports whether err is a normal peer/local close (not a fault).
func IsBenignClose(err error) bool {
	_, class := ClassifyClose(err)
	return class == ErrorClassRemoteClose || class == ErrorClassLocalCancel || class == ErrorClassProbeClose
}
