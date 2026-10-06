package tcptls

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestPreparedFlowHalfCommitWithPayloadCoalescesOpening(t *testing.T) {
	target, err := wire.NewDomainTarget("payload.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 41, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
	}
	setup, err := encodeFlowSetup(header, target)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		auth    []byte
		warm    bool
		payload []byte
	}{
		{name: "fresh", auth: []byte("pending-auth"), payload: []byte("initial payload")},
		{name: "warm", warm: true, payload: []byte("initial payload")},
		{name: "fresh_empty", auth: []byte("pending-auth")},
		{name: "warm_empty", warm: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &recordingPayloadConn{}
			ci := newCarrierInfo(nil)
			if test.warm {
				ci.transition(stateAuthenticatedIdle)
			}
			ci.transition(stateBorrowed)
			half := &PreparedFlowHalf{
				cfg:        boundTestConfig(t, testTCPDialer{}),
				conn:       raw,
				ci:         ci,
				target:     target,
				header:     header,
				auth:       append([]byte(nil), test.auth...),
				warmBorrow: test.warm,
			}
			payload := append([]byte(nil), test.payload...)
			conn, err := half.CommitWithPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) > 0 {
				payload[0] = 'X'
			}
			want := append(append(append([]byte(nil), test.auth...), setup...), test.payload...)
			if got := raw.written.Bytes(); !bytes.Equal(got, want) {
				t.Fatalf("opening = %x, want %x", got, want)
			}
			if _, err := half.Commit(); err == nil {
				t.Fatal("second commit succeeded")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparedFlowHalfCommitWithPayloadPartialWriteCloses(t *testing.T) {
	target, err := wire.NewDomainTarget("payload.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 42, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
	}
	raw := &partialFailurePayloadConn{}
	ci := newCarrierInfo(nil)
	ci.transition(stateBorrowed)
	half := &PreparedFlowHalf{
		cfg:    boundTestConfig(t, testTCPDialer{}),
		conn:   raw,
		ci:     ci,
		target: target,
		header: header,
		auth:   []byte("pending-auth"),
	}
	conn, err := half.CommitWithPayload([]byte("initial payload"))
	if err == nil || conn != nil {
		t.Fatalf("CommitWithPayload = (%v, %v), want nil, error", conn, err)
	}
	if !raw.closed {
		t.Fatal("partial opening write failure did not close carrier")
	}
}

type recordingPayloadConn struct {
	written bytes.Buffer
	closed  bool
}

type partialFailurePayloadConn struct {
	recordingPayloadConn
	failed bool
}

func (c *partialFailurePayloadConn) Write(p []byte) (int, error) {
	if c.failed {
		return 0, io.ErrClosedPipe
	}
	c.failed = true
	n := 3
	if len(p) < n {
		n = len(p)
	}
	_, _ = c.written.Write(p[:n])
	return n, io.ErrClosedPipe
}

func (*recordingPayloadConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingPayloadConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}

func (c *recordingPayloadConn) Close() error {
	c.closed = true
	return nil
}
func (*recordingPayloadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*recordingPayloadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*recordingPayloadConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPayloadConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPayloadConn) SetWriteDeadline(time.Time) error { return nil }
