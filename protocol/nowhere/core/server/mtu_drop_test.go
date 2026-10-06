package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	carrierquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestNowuFlowMTUDiscardReportsObserverAndKeepsFlow(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{Credentials: credentials, Networks: []Network{NetworkUDP}})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan diagnostic.Event, 1)
	handler, err := NewHandler(HandlerOptions{
		Config:   config,
		Upstream: v15DiscardUpstream{},
		Observer: diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
			if event.Code == "udp_queue_drop_total" {
				events <- event
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := newMTUDropQUICConn(
		[]int{20, 18, 20},
		[]error{
			&carrierquic.DatagramTooLargeError{MaxDatagramSize: 18, Cause: errors.New("first too large")},
			&carrierquic.DatagramTooLargeError{MaxDatagramSize: 16, Cause: errors.New("second too large")},
		},
	)
	session := newPortalSession(wire.SessionID{3}, raw, handler, raw.RemoteAddr())
	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	flow := newNowuFlow(session, 9, target)
	defer flow.shutdown(net.ErrClosed)
	session.mu.Lock()
	session.flows[flow.flowID] = flow
	session.mu.Unlock()

	dropped := []byte("this packet is accepted and dropped")
	if written, err := flow.WriteTo(dropped, nil); err != nil || written != len(dropped) {
		t.Fatalf("dropped write = (%d, %v), want (%d, nil)", written, err, len(dropped))
	}
	select {
	case <-flow.done:
		t.Fatal("MTU drop closed the flow")
	default:
	}
	accepted := []byte("next packet survives")
	if written, err := flow.WriteTo(accepted, nil); err != nil || written != len(accepted) {
		t.Fatalf("next write = (%d, %v), want (%d, nil)", written, err, len(accepted))
	}
	session.flushUDPDrop()
	select {
	case event := <-events:
		if event.FlowID != 9 || event.State != "downlink" || event.Outcome != "mtu_unstable" {
			t.Fatalf("event = %+v", event)
		}
		if event.Count != 1 || event.Bytes != uint64(len(dropped)) {
			t.Fatalf("event count/bytes = %d/%d", event.Count, event.Bytes)
		}
	default:
		t.Fatal("MTU drop observer event was not emitted")
	}
}

type mtuDropQUICConn struct {
	*v15QUICConn
	mu        sync.Mutex
	maxima    []int
	errors    []error
	sendCalls int
}

func newMTUDropQUICConn(maxima []int, sendErrors []error) *mtuDropQUICConn {
	return &mtuDropQUICConn{
		v15QUICConn: newV15QUICConn(wire.TLSExporter{}, &v15QuicStream{}),
		maxima:      maxima,
		errors:      sendErrors,
	}
}

func (c *mtuDropQUICConn) CurrentMaxDatagramSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.maxima) == 0 {
		return 1200
	}
	index := c.sendCalls
	if index >= len(c.maxima) {
		index = len(c.maxima) - 1
	}
	return c.maxima[index]
}

func (c *mtuDropQUICConn) SendDatagram(context.Context, []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.sendCalls
	c.sendCalls++
	if index < len(c.errors) {
		return c.errors[index]
	}
	return nil
}

var _ QuicConn = (*mtuDropQUICConn)(nil)
