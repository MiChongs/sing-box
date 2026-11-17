package route

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type bypassTestDNSRouter struct{ adapter.DNSRouter }

func (*bypassTestDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }

func newBypassTestRule(t *testing.T, content string) adapter.HeadlessRule {
	t.Helper()
	options, err := json.UnmarshalExtended[option.HeadlessRule]([]byte(content))
	require.NoError(t, err)
	rule, err := R.NewHeadlessRule(context.Background(), options)
	require.NoError(t, err)
	return rule
}

func newBypassTestRouter() *Router {
	return &Router{
		ctx:          context.Background(),
		logger:       log.NewNOPFactory().Logger(),
		dnsTransport: &preMatchQUICDNSManager{},
		dns:          &bypassTestDNSRouter{},
		outbound:     &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}},
	}
}

func TestPreRouteBypass(t *testing.T) {
	t.Parallel()
	direct := &testFlowOutbound{tag: "ebpf-bypass", outboundType: C.TypeDirect}
	next := &preMatchQUICRule{action: &R.RuleActionRoute{Outbound: "proxy"}}
	newMetadata := func(rule adapter.HeadlessRule, lookup func(netip.Addr) (string, bool)) adapter.InboundContext {
		return adapter.InboundContext{
			Network:     N.NetworkTCP,
			Source:      M.ParseSocksaddr("10.0.0.2:40000"),
			Destination: M.ParseSocksaddr("192.0.2.10:443"),
			PreRouteBypass: &adapter.PreRouteBypass{
				Rule: rule, Outbound: direct, Description: "local.bypass_rule_set",
				NeedDomain: true, LookupDomain: lookup,
			},
		}
	}
	t.Run("learned domain matches", func(t *testing.T) {
		router := newBypassTestRouter()
		router.rules = []adapter.Rule{next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["example.com"], "port": [443]}`), func(address netip.Addr) (string, bool) {
			return "www.example.com", address == netip.MustParseAddr("192.0.2.10")
		})
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		selected, _, buffers, _, err := router.matchRule(context.Background(), &metadata, server, nil)
		require.NoError(t, err)
		require.Nil(t, selected)
		require.Empty(t, buffers)
		require.True(t, metadata.PreRouteBypassMatched)
		require.Empty(t, metadata.Domain, "the learned domain stays on the probe")
	})
	t.Run("miss falls through to route rules", func(t *testing.T) {
		router := newBypassTestRouter()
		router.rules = []adapter.Rule{next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["example.com"], "port": [80]}`), func(netip.Addr) (string, bool) {
			return "www.example.com", true
		})
		selected, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, &bypassTestPacketConn{})
		require.NoError(t, err)
		require.Same(t, next, selected)
		require.False(t, metadata.PreRouteBypassMatched)
	})
	t.Run("sniffed host overrides a learned domain", func(t *testing.T) {
		router := newBypassTestRouter()
		router.rules = []adapter.Rule{next}
		// The address was learned for a bypassed site, but this connection
		// names another site on the same CDN edge: it must not bypass.
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["cn.example"]}`), func(netip.Addr) (string, bool) {
			return "www.cn.example", true
		})
		metadata.Destination = M.ParseSocksaddr("104.21.4.123:8080")
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go client.Write([]byte("GET / HTTP/1.1\r\nHost: video.foreign.example\r\n\r\n"))
		selected, _, buffers, _, err := router.matchRule(context.Background(), &metadata, server, nil)
		require.NoError(t, err)
		require.Same(t, next, selected)
		require.False(t, metadata.PreRouteBypassMatched)
		buf.ReleaseMulti(buffers)
	})
	t.Run("sniffed payload is replayed", func(t *testing.T) {
		router := newBypassTestRouter()
		router.rules = []adapter.Rule{next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain": ["sniff.example"]}`), nil)
		metadata.Destination = M.ParseSocksaddr("192.0.2.10:8080")
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		request := []byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n")
		go client.Write(request)
		selected, _, buffers, _, err := router.matchRule(context.Background(), &metadata, server, nil)
		require.NoError(t, err)
		require.Nil(t, selected)
		require.True(t, metadata.PreRouteBypassMatched)
		require.Empty(t, metadata.Protocol, "route rules did not ask for sniffing")
		require.Len(t, buffers, 1)
		require.Equal(t, request, buffers[0].Bytes())
		buf.ReleaseMulti(buffers)
	})
}

// bypassTestPacketConn has no datagram to sniff.
type bypassTestPacketConn struct{ N.PacketConn }

func (*bypassTestPacketConn) SetReadDeadline(time.Time) error { return nil }

func (*bypassTestPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, os.ErrDeadlineExceeded
}
