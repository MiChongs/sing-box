package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type testReloadRouter struct {
	adapter.Router
	reloaded int
}

func (r *testReloadRouter) Reload() {
	r.reloaded++
}

type testConfigChecker struct {
	err     error
	checked int
}

func (c *testConfigChecker) CheckConfig() error {
	c.checked++
	return c.err
}

func TestReloadConfigs(t *testing.T) {
	t.Parallel()

	newTestServer := func(checker adapter.ConfigChecker) (http.Handler, *testReloadRouter) {
		ctx := service.ContextWith[adapter.ConfigChecker](context.Background(), checker)
		router := &testReloadRouter{}
		server := &Server{
			ctx:    ctx,
			router: router,
			logger: log.NewNOPFactory().NewLogger("clash-api"),
		}
		return configRouter(server, log.NewNOPFactory()), router
	}
	put := func(handler http.Handler, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	errorMessage := func(t *testing.T, response *httptest.ResponseRecorder) string {
		var httpError HTTPError
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &httpError))
		return httpError.Message
	}

	t.Run("reload not supported", func(t *testing.T) {
		t.Parallel()
		handler, router := newTestServer(nil)
		response := put(handler, "")
		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
		require.Zero(t, router.reloaded)
	})

	for _, body := range []string{"", " ", "{}", `{"path":"","payload":""}`} {
		t.Run("reload with body "+body, func(t *testing.T) {
			t.Parallel()
			checker := &testConfigChecker{}
			handler, router := newTestServer(checker)
			response := put(handler, body)
			require.Equal(t, http.StatusNoContent, response.Code)
			require.Equal(t, 1, checker.checked)
			require.Equal(t, 1, router.reloaded)
		})
	}

	t.Run("invalid body", func(t *testing.T) {
		t.Parallel()
		checker := &testConfigChecker{}
		handler, router := newTestServer(checker)
		response := put(handler, "{")
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, ErrBadRequest.Message, errorMessage(t, response))
		require.Zero(t, checker.checked)
		require.Zero(t, router.reloaded)
	})

	for _, body := range []string{`{"path":"/etc/sing-box/other.json"}`, `{"payload":"{}"}`} {
		t.Run("unsupported "+body, func(t *testing.T) {
			t.Parallel()
			checker := &testConfigChecker{}
			handler, router := newTestServer(checker)
			response := put(handler, body)
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.NotEmpty(t, errorMessage(t, response))
			require.Zero(t, checker.checked)
			require.Zero(t, router.reloaded)
		})
	}

	t.Run("check failed", func(t *testing.T) {
		t.Parallel()
		checker := &testConfigChecker{err: E.New("invalid configuration")}
		handler, router := newTestServer(checker)
		response := put(handler, "")
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, "invalid configuration", errorMessage(t, response))
		require.Equal(t, 1, checker.checked)
		require.Zero(t, router.reloaded)
	})
}

func TestConfigsTCPConcurrent(t *testing.T) {
	t.Parallel()

	newTestServer := func(tcpConcurrent *dialer.TCPConcurrent) (http.Handler, *clashmode.Manager) {
		ctx := context.Background()
		if tcpConcurrent != nil {
			ctx = service.ContextWithPtr(ctx, tcpConcurrent)
		}
		clashMode := clashmode.NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Rule", "Global"})
		server := &Server{
			ctx:       ctx,
			clashMode: clashMode,
			logger:    log.NewNOPFactory().NewLogger("clash-api"),
		}
		return configRouter(server, log.NewNOPFactory()), clashMode
	}
	request := func(handler http.Handler, method string, body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/", strings.NewReader(body)))
		return response
	}
	getTCPConcurrent := func(t *testing.T, handler http.Handler) bool {
		response := request(handler, http.MethodGet, "")
		require.Equal(t, http.StatusOK, response.Code)
		var configs map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &configs))
		enabled, loaded := configs["tcp-concurrent"].(bool)
		require.True(t, loaded, "GET /configs must report tcp-concurrent like mihomo")
		return enabled
	}

	t.Run("toggle at runtime", func(t *testing.T) {
		tcpConcurrent, err := dialer.NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), nil)
		require.NoError(t, err)
		handler, _ := newTestServer(tcpConcurrent)
		require.False(t, getTCPConcurrent(t, handler))

		require.Equal(t, http.StatusNoContent, request(handler, http.MethodPatch, `{"tcp-concurrent": true}`).Code)
		require.True(t, tcpConcurrent.Enabled())
		require.True(t, getTCPConcurrent(t, handler))

		require.Equal(t, http.StatusNoContent, request(handler, http.MethodPatch, `{"mode": "Rule"}`).Code)
		require.True(t, tcpConcurrent.Enabled(), "a PATCH without the field keeps it")

		require.Equal(t, http.StatusNoContent, request(handler, http.MethodPatch, `{"tcp-concurrent": false}`).Code)
		require.False(t, tcpConcurrent.Enabled())
	})

	t.Run("unavailable rejects the whole patch", func(t *testing.T) {
		handler, clashMode := newTestServer(nil)
		require.False(t, getTCPConcurrent(t, handler))
		response := request(handler, http.MethodPatch, `{"mode": "Global", "tcp-concurrent": true}`)
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, "Rule", clashMode.Mode())
	})
}
