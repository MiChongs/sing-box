package bundle

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	nquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestQUICUDPUplinkRefreshesAndRetries(t *testing.T) {
	session := &v15PMTUSession{
		maxima: []int{20, 18},
		errors: []error{&nquic.DatagramTooLargeError{MaxDatagramSize: 18, Cause: errors.New("pmtu changed")}},
	}
	handle := newQSessionHandle(&quicPreparedStream{session: session}, nil, 1, nil)
	var next atomic.Uint32
	payload := []byte("a packet that requires fragments")
	if written, err := writeQUICUDPPacket(handle, 1, &next, payload); err != nil || written != len(payload) {
		t.Fatalf("writeQUICUDPPacket = (%d, %v), want (%d, nil)", written, err, len(payload))
	}
	if session.sendCalls < 2 {
		t.Fatalf("SendDatagram calls = %d, want retry after PMTU refresh", session.sendCalls)
	}
	assertV15Datagrams(t, session.frames)
}

func TestQUICUDPUplinkSecondTooLargeDropsPacketKeepsFlow(t *testing.T) {
	session := &v15PMTUSession{
		maxima: []int{20, 18, 20},
		errors: []error{
			&nquic.DatagramTooLargeError{MaxDatagramSize: 18, Cause: errors.New("first too large")},
			&nquic.DatagramTooLargeError{MaxDatagramSize: 16, Cause: errors.New("second too large")},
		},
	}
	handle := newQSessionHandle(&quicPreparedStream{session: session}, nil, 1, nil)
	var next atomic.Uint32
	dropped := []byte("this packet is dropped after the second PMTU error")
	if written, err := writeQUICUDPPacket(handle, 1, &next, dropped); err != nil || written != len(dropped) {
		t.Fatalf("second-too-large write = (%d, %v), want (%d, nil) accepted drop", written, err, len(dropped))
	}
	accepted := []byte("next packet survives")
	if written, err := writeQUICUDPPacket(handle, 1, &next, accepted); err != nil || written != len(accepted) {
		t.Fatalf("next write = (%d, %v), want (%d, nil)", written, err, len(accepted))
	}
	if len(session.frames) == 0 {
		t.Fatal("next packet did not reach the QUIC backend")
	}
	assertV15Datagrams(t, session.frames)
}

func TestQUICUDPMTUDiscardReportsObserver(t *testing.T) {
	raw := &v15PMTUSession{
		maxima: []int{20, 18},
		errors: []error{
			&nquic.DatagramTooLargeError{MaxDatagramSize: 18, Cause: errors.New("first too large")},
			&nquic.DatagramTooLargeError{MaxDatagramSize: 16, Cause: errors.New("second too large")},
		},
	}
	events := make(chan diagnostic.Event, 1)
	backend := &quicMuxBackend{
		maxUDPQueueBytes: DefaultMaxUDPQueueBytes,
		maxPendingCloses: DefaultMaxPendingCloses,
		observer: diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
			if event.Code == "udp_queue_drop_total" {
				events <- event
			}
		}),
		sessions: make(map[carrier.QuicSession]*quicSessionMux),
	}
	mux, err := newQUICSessionMux(backend, raw, wire.AuthFrame{1})
	if err != nil {
		t.Fatal(err)
	}
	handle := newQSessionHandle(&quicPreparedStream{session: mux}, nil, 7, nil)
	var next atomic.Uint32
	payload := []byte("observer-visible MTU drop")
	if written, err := writeQUICUDPPacket(handle, 7, &next, payload); err != nil || written != len(payload) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", written, err, len(payload))
	}
	mux.flushUDPDrop()
	select {
	case event := <-events:
		if event.FlowID != 7 || event.State != "uplink" || event.Outcome != "mtu_unstable" {
			t.Fatalf("event = %+v", event)
		}
		if event.Count != 1 || event.Bytes != uint64(len(payload)) {
			t.Fatalf("event count/bytes = %d/%d", event.Count, event.Bytes)
		}
	default:
		t.Fatal("MTU drop observer event was not emitted")
	}
	mux.close(net.ErrClosed)
	<-mux.sendLoopDone
}

func assertV15Datagrams(t *testing.T, frames [][]byte) {
	t.Helper()
	for _, encoded := range frames {
		frame, err := wire.DecodeUDPFrame(encoded)
		if err != nil {
			t.Fatalf("DecodeUDPFrame(%x): %v", encoded, err)
		}
		if frame.FlowID != 1 {
			t.Fatalf("flow ID = %d, want 1", frame.FlowID)
		}
	}
}

type v15PMTUSession struct {
	maxima    []int
	errors    []error
	sendCalls int
	frames    [][]byte
}

func (s *v15PMTUSession) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return wire.TLSHandshakeInfo{
		TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN,
	}, nil
}

func (s *v15PMTUSession) PrepareStream(context.Context) (nquic.PreparedStream, error) {
	return nil, errors.New("unused")
}

func (s *v15PMTUSession) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}

func (s *v15PMTUSession) CurrentMaxDatagramSize() int {
	if len(s.maxima) == 0 {
		return 1200
	}
	index := s.sendCalls
	if index >= len(s.maxima) {
		index = len(s.maxima) - 1
	}
	return s.maxima[index]
}

func (s *v15PMTUSession) SendDatagram(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	index := s.sendCalls
	s.sendCalls++
	if index < len(s.errors) {
		return s.errors[index]
	}
	return nil
}
func (*v15PMTUSession) LocalAddr() net.Addr { return &net.UDPAddr{} }

var _ carrier.QuicSession = (*v15PMTUSession)(nil)
