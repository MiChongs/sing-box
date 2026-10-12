package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type tcpConcurrentTestConn struct {
	net.Conn
}

func (c *tcpConcurrentTestConn) Close() error {
	return nil
}

func TestDNSTCPConcurrent(t *testing.T) {
	t.Parallel()

	tcpConcurrent, err := dialer.NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true, MaxConcurrent: 4})
	require.NoError(t, err)
	refused, accepted := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	_, err = tcpConcurrent.Dial(context.Background(), M.ParseSocksaddrHostPort("example.com", 443), []netip.Addr{refused, accepted}, false, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
		if address == refused {
			return nil, net.ErrClosed
		}
		return &tcpConcurrentTestConn{}, nil
	})
	require.NoError(t, err)

	handler := dnsRouter(nil, tcpConcurrent)
	request := func(method string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/tcp-concurrent", nil))
		return response
	}
	get := func() tcpConcurrentStatus {
		response := request(http.MethodGet)
		require.Equal(t, http.StatusOK, response.Code)
		var status tcpConcurrentStatus
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &status))
		return status
	}

	require.Eventually(t, func() bool { return len(get().Failures) == 1 }, time.Second, 5*time.Millisecond)
	status := get()
	require.True(t, status.Enabled)
	require.True(t, status.Adaptive)
	require.Equal(t, 4, status.MaxConcurrent)
	require.Equal(t, uint64(1), status.Statistics.Races)
	require.Equal(t, uint64(2), status.Statistics.Attempts)
	require.Len(t, status.Statistics.Wins, 4)
	require.Len(t, status.Destinations, 1)
	require.Equal(t, "example.com", status.Destinations[0].Host)
	require.Equal(t, uint16(443), status.Destinations[0].Port)
	require.Equal(t, accepted.String(), status.Destinations[0].Address)
	require.Equal(t, "192.0.2.1:443", status.Failures[0].Address)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(request(http.MethodGet).Body.Bytes(), &raw))
	for _, key := range []string{"enabled", "adaptive", "attemptDelay", "maxConcurrent", "statistics", "destinations", "failures"} {
		require.Contains(t, raw, key)
	}

	require.Equal(t, http.StatusNoContent, request(http.MethodDelete).Code)
	status = get()
	require.Empty(t, status.Destinations)
	require.Empty(t, status.Failures)
	require.Equal(t, uint64(1), status.Statistics.Races)
}

func TestDNSTCPConcurrentUnavailable(t *testing.T) {
	t.Parallel()

	handler := dnsRouter(nil, nil)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/tcp-concurrent", nil))
		require.Equal(t, http.StatusNotFound, response.Code)
	}
}
