package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"
)

// closedError 表示隧道正常结束: 对端取消请求、以无错误码重置流或关闭连接，
// 或本端拆除了底层连接。XHTTP 没有自己的关闭消息，两端都靠这些方式结束隧道。
// 它匹配 net.ErrClosed，路由层据此按正常关闭处理而不记 ERROR，同时保留原始
// 错误供日志与 errors.As 使用。
//
// 包装类型本身也挡住了 x/net http2 对 StreamError 的直接类型断言，内层协议
// 是 HTTP/2 时不会把它当成自己的流错误。
type closedError struct {
	err error
}

func (e *closedError) Error() string {
	return e.err.Error()
}

func (e *closedError) Unwrap() []error {
	return []error{net.ErrClosed, e.err}
}

// wrapError 归类 HTTP body 读写返回的错误: 正常结束隧道的改为 closedError；
// 其余 HTTP/2 协议错误按 sing 的惯例包装，避免泄漏到内层 HTTP/2 framer。
func wrapError(err error) error {
	if err == nil || E.IsClosedOrCanceled(err) {
		return err
	}
	if isTunnelClosed(err) {
		return &closedError{err}
	}
	return baderror.WrapH2(err)
}

func isTunnelClosed(err error) bool {
	// HTTP/1.1 chunked body 在对端断开时以 unexpected EOF 结束。
	if errors.Is(err, io.ErrUnexpectedEOF) || isH3Closed(err) {
		return true
	}
	// net/http 用自己内部的一份 http2 收发 HTTP/2，错误类型无法引用，只能按消息匹配。
	message := err.Error()
	if strings.Contains(message, "stream error: ") {
		// RST_STREAM(NO_ERROR / CANCEL)
		return strings.Contains(message, "; NO_ERROR") || strings.Contains(message, "; CANCEL")
	}
	return strings.Contains(message, "http2: server sent GOAWAY") && strings.Contains(message, "ErrCode=NO_ERROR") ||
		strings.Contains(message, "client disconnected") ||
		strings.Contains(message, "body closed by handler") ||
		strings.Contains(message, "http2: response body closed") ||
		strings.Contains(message, "http2: client connection lost") ||
		strings.Contains(message, "http2: client connection force closed")
}
