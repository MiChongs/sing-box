package dns

import (
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeIPTypeTransport struct{ fakeDNSTransport }

func (t *fakeIPTypeTransport) Type() string { return C.DNSTypeFakeIP }

func TestRouterResponseObservers(t *testing.T) {
	t.Parallel()
	router := &Router{}
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{Name: "example.com.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	var first, second int
	unregisterFirst := router.RegisterDNSResponseObserver(func(*mDNS.Msg, *mDNS.Msg) { first++ })
	router.RegisterDNSResponseObserver(func(got, reply *mDNS.Msg) {
		require.Same(t, message, got)
		require.Same(t, response, reply)
		second++
	})
	router.recordReverseMapping(message, response, &fakeDNSTransport{})
	require.Equal(t, 1, first)
	require.Equal(t, 1, second)

	router.recordReverseMapping(message, response, &fakeIPTypeTransport{})
	require.Equal(t, 1, second, "FakeIP answers are not real addresses")
	router.recordReverseMapping(message, new(mDNS.Msg), nil)
	require.Equal(t, 1, second, "an empty answer is not reported")

	unregisterFirst()
	unregisterFirst()
	router.recordReverseMapping(message, response, nil)
	require.Equal(t, 1, first)
	require.Equal(t, 2, second)
}
