//go:build with_quic

package v2rayxhttp

import (
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestWrapErrorHTTP3(t *testing.T) {
	for _, testCase := range []struct {
		err     error
		message string
	}{
		{&http3.Error{Remote: true, ErrorCode: 0}, "H3 error (0x0)"},
		{&http3.Error{Remote: false, ErrorCode: 0}, "H3 error (0x0) (local)"},
		{&http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestCanceled}, "H3_REQUEST_CANCELLED"},
		{&http3.Error{Remote: false, ErrorCode: http3.ErrCodeRequestCanceled}, "H3_REQUEST_CANCELLED (local)"},
		{&http3.Error{Remote: true, ErrorCode: http3.ErrCodeNoError, ErrorMessage: "idle timeout"}, "H3_NO_ERROR: idle timeout"},
	} {
		if testCase.err.Error() != testCase.message {
			t.Fatalf("want %q, got %q", testCase.message, testCase.err)
		}
		requireClosed(t, testCase.err)
	}
	for _, err := range []error{
		&quic.StreamError{StreamID: 3, ErrorCode: 0, Remote: true},
		&quic.StreamError{StreamID: 3, ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled)},
		&quic.ApplicationError{ErrorCode: 0},
		&quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError), Remote: true},
		&quic.StatelessResetError{},
		quic.ErrServerClosed,
		quic.ErrTransportClosed,
		E.Cause(&http3.Error{ErrorCode: 0}, "xhttp: failed to send upload"),
	} {
		requireClosed(t, err)
	}
	for _, err := range []error{
		&http3.Error{Remote: true, ErrorCode: http3.ErrCodeInternalError},
		&http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestIncomplete},
		&http3.Error{Remote: true, ErrorCode: http3.ErrCodeFrameError},
		&quic.StreamError{StreamID: 3, ErrorCode: quic.StreamErrorCode(http3.ErrCodeMessageError)},
	} {
		requireNotClosed(t, err)
	}
}
