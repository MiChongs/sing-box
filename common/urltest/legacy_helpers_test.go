package urltest

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Legacy helpers retained for test coverage. Not used in production code.

const (
	bufioSize       = 2048
	maxResidualBody = 64 * 1024
)

var readerPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, bufioSize) },
}

var errBodyTooLarge = errors.New("urltest: response body exceeds safety limit")

func isHEADRejected(err error) bool {
	if err == nil {
		return false
	}
	if hs, ok := err.(*httpStatusError); ok {
		return hs.code == http.StatusMethodNotAllowed
	}
	return false
}

func measureRequest(conn net.Conn, reader *bufio.Reader, reqBytes []byte, req *http.Request, peekDeadline time.Time, req204 bool, matcher *StatusMatcher) (time.Duration, error) {
	_ = conn.SetReadDeadline(peekDeadline)
	defer conn.SetReadDeadline(time.Time{})

	writeStart := time.Now()
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, err
	}
	if _, err := reader.Peek(1); err != nil {
		return 0, err
	}
	rtt := time.Since(writeStart)
	if err := drainResponse(reader, req, req204, matcher); err != nil {
		return rtt, err
	}
	return rtt, nil
}

func drainResponse(reader *bufio.Reader, req *http.Request, require204 bool, matcher *StatusMatcher) error {
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if cl := resp.ContentLength; cl > 0 {
		if cl > maxResidualBody {
			return errBodyTooLarge
		}
		if _, err = io.CopyN(io.Discard, reader, cl); err != nil {
			return err
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if matcher != nil {
		if matcher.Match(resp.StatusCode) {
			return nil
		}
		return errors.New("urltest: status " + strconv.Itoa(resp.StatusCode) +
			" not in expected-status=" + matcher.String())
	}
	if require204 && resp.StatusCode != 204 {
		return errors.New("urltest: captive-portal or hijack detected (expected 204, got " + strconv.Itoa(resp.StatusCode) + ")")
	}
	if resp.StatusCode >= 400 {
		return &httpStatusError{resp.StatusCode}
	}
	return nil
}
