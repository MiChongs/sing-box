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

	mDNS "github.com/miekg/dns"
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
	t.Run("route sniff rule reuses the payload after a miss", func(t *testing.T) {
		// The client sent its whole first flight and now waits for the
		// server: the route's own sniff rule must get the host from the
		// payload the bypass already read, not from another read.
		router := newBypassTestRouter()
		sniffRule := &preMatchQUICRule{action: &R.RuleActionSniff{}}
		router.rules = []adapter.Rule{sniffRule, next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["cn.example"]}`), nil)
		metadata.Destination = M.ParseSocksaddr("192.0.2.10:8080")
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		request := []byte("GET / HTTP/1.1\r\nHost: www.google.example\r\n\r\n")
		go client.Write(request)
		start := time.Now()
		selected, _, buffers, _, err := router.matchRule(context.Background(), &metadata, server, nil)
		require.NoError(t, err)
		require.Same(t, next, selected)
		require.False(t, metadata.PreRouteBypassMatched)
		require.Equal(t, "www.google.example", metadata.SniffHost, "domain rules need the sniffed host")
		require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
		require.NoError(t, metadata.SniffError)
		require.Less(t, time.Since(start), C.ReadPayloadTimeout, "no second read of the connection")
		require.Len(t, buffers, 1, "payload is replayed once")
		require.Equal(t, request, buffers[0].Bytes())
		buf.ReleaseMulti(buffers)
	})
	t.Run("silent connection is not waited for twice", func(t *testing.T) {
		router := newBypassTestRouter()
		sniffRule := &preMatchQUICRule{action: &R.RuleActionSniff{}}
		router.rules = []adapter.Rule{sniffRule, next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["cn.example"]}`), nil)
		metadata.Destination = M.ParseSocksaddr("192.0.2.10:8080")
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		start := time.Now()
		selected, _, buffers, _, err := router.matchRule(context.Background(), &metadata, server, nil)
		require.NoError(t, err)
		require.Same(t, next, selected)
		require.Empty(t, buffers)
		require.Error(t, metadata.SniffError)
		require.Less(t, time.Since(start), 2*C.ReadPayloadTimeout-50*time.Millisecond)
	})
	t.Run("route sniff rule reuses the datagram after a miss", func(t *testing.T) {
		router := newBypassTestRouter()
		sniffRule := &preMatchQUICRule{action: &R.RuleActionSniff{}}
		router.rules = []adapter.Rule{sniffRule, next}
		metadata := newMetadata(newBypassTestRule(t, `{"domain_suffix": ["cn.example"]}`), nil)
		metadata.Network = N.NetworkUDP
		metadata.Destination = M.ParseSocksaddr("192.0.2.10:5353")
		query := new(mDNS.Msg)
		query.SetQuestion("www.google.example.", mDNS.TypeA)
		payload, err := query.Pack()
		require.NoError(t, err)
		packetConn := &bypassTestQueuedPacketConn{packets: [][]byte{payload}, destination: metadata.Destination}
		selected, _, _, packetBuffers, err := router.matchRule(context.Background(), &metadata, nil, packetConn)
		require.NoError(t, err)
		require.Same(t, next, selected)
		require.False(t, metadata.PreRouteBypassMatched)
		require.Equal(t, C.ProtocolDNS, metadata.Protocol, "the route sniff rule sniffed the buffered datagram")
		require.Equal(t, 1, packetConn.reads, "the datagram is read once")
		require.Len(t, packetBuffers, 1, "the datagram is replayed once")
		require.Equal(t, payload, packetBuffers[0].Buffer.Bytes())
		N.ReleaseMultiPacketBuffer(packetBuffers)
	})
}

// bypassTestQueuedPacketConn delivers its queued datagrams, then times out.
type bypassTestQueuedPacketConn struct {
	N.PacketConn
	packets     [][]byte
	destination M.Socksaddr
	reads       int
}

func (*bypassTestQueuedPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *bypassTestQueuedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.reads++
	if len(c.packets) == 0 {
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
	_, err := buffer.Write(c.packets[0])
	c.packets = c.packets[1:]
	return c.destination, err
}

// bypassTestPacketConn has no datagram to sniff.
type bypassTestPacketConn struct{ N.PacketConn }

func (*bypassTestPacketConn) SetReadDeadline(time.Time) error { return nil }

func (*bypassTestPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, os.ErrDeadlineExceeded
}
