package bundle

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestOpenTCPWithPayloadCoalescesPrefixAndWritesTailAfterReady(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	relay := &readyRecordingConn{}
	raw := &v15AuthSession{}
	raw.stream.conn = relay
	backend := &v15AuthBackend{session: raw}
	b := newV15QUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	target, err := wire.NewDomainTarget("payload.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, initialTCPPayloadCoalesceLimit+17)
	conn, err := b.OpenTCPWithPayload(context.Background(), target, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	raw.stream.mu.Lock()
	opening := append([]byte(nil), raw.stream.setup...)
	finishWrite := raw.stream.finishWrite
	raw.stream.mu.Unlock()
	if finishWrite {
		t.Fatal("duplex QUIC opening unexpectedly sent FIN")
	}
	if len(opening) < wire.AuthFrameLen+wire.FlowHeaderLen {
		t.Fatalf("opening too short: %d", len(opening))
	}
	header, err := wire.ReadFlowHeader(bytes.NewReader(opening[wire.AuthFrameLen:]))
	if err != nil {
		t.Fatal(err)
	}
	if header.Role != wire.FlowRoleDuplex || header.Kind != wire.FlowKindTCP {
		t.Fatalf("header = %+v", header)
	}
	targetOffset := wire.AuthFrameLen + wire.FlowHeaderLen
	gotTarget, consumed, err := wire.DecodeTarget(opening[targetOffset:])
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target {
		t.Fatalf("target = %+v, want %+v", gotTarget, target)
	}
	prefixOffset := targetOffset + consumed
	if got := opening[prefixOffset:]; !bytes.Equal(got, payload[:initialTCPPayloadCoalesceLimit]) {
		t.Fatalf("coalesced prefix length = %d, want %d", len(got), initialTCPPayloadCoalesceLimit)
	}
	if got := relay.Written(); !bytes.Equal(got, payload[initialTCPPayloadCoalesceLimit:]) {
		t.Fatalf("post-READY tail = %x, want %x", got, payload[initialTCPPayloadCoalesceLimit:])
	}

	payload[0] ^= 0xff
	if opening[prefixOffset] != 0x5a {
		t.Fatal("opening retained caller payload buffer")
	}
}

func TestOpenTCPWithPayloadClosesFlowWhenTailWriteFails(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	relay := &readyRecordingConn{writeErr: io.ErrClosedPipe}
	raw := &v15AuthSession{}
	raw.stream.conn = relay
	b := newV15QUICOnlyBundle(t, credentials, &v15AuthBackend{session: raw})
	defer b.Close()

	target, err := wire.NewDomainTarget("payload.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, initialTCPPayloadCoalesceLimit+1)
	conn, err := b.OpenTCPWithPayload(context.Background(), target, payload)
	if err == nil || conn != nil {
		t.Fatalf("OpenTCPWithPayload = (%v, %v), want nil error result", conn, err)
	}
	if !relay.Closed() {
		t.Fatal("tail write failure did not close flow")
	}
}

func TestOpenTCPWithPayloadEmptyAndExactBoundary(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
	}{
		{name: "empty"},
		{name: "64KiB", size: initialTCPPayloadCoalesceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials, err := wire.NewCredentials("secret")
			if err != nil {
				t.Fatal(err)
			}
			relay := &readyRecordingConn{}
			raw := &v15AuthSession{}
			raw.stream.conn = relay
			b := newV15QUICOnlyBundle(t, credentials, &v15AuthBackend{session: raw})
			defer b.Close()
			target, err := wire.NewDomainTarget("boundary.example", 443)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0x6b}, test.size)
			conn, err := b.OpenTCPWithPayload(context.Background(), target, payload)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()

			raw.stream.mu.Lock()
			opening := append([]byte(nil), raw.stream.setup...)
			raw.stream.mu.Unlock()
			targetOffset := wire.AuthFrameLen + wire.FlowHeaderLen
			_, consumed, err := wire.DecodeTarget(opening[targetOffset:])
			if err != nil {
				t.Fatal(err)
			}
			if got := opening[targetOffset+consumed:]; !bytes.Equal(got, payload) {
				t.Fatalf("coalesced payload length = %d, want %d", len(got), len(payload))
			}
			if got := relay.Written(); len(got) != 0 {
				t.Fatalf("exact-boundary tail = %x, want empty", got)
			}
		})
	}
}

type readyRecordingConn struct {
	mu       sync.Mutex
	ready    bool
	written  bytes.Buffer
	writeErr error
	closed   bool
}

func (c *readyRecordingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ready {
		return 0, io.EOF
	}
	c.ready = true
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = byte(wire.SetupResultReady)
	return 1, nil
}

func (c *readyRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.written.Write(p)
}

func (c *readyRecordingConn) Written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

func (c *readyRecordingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *readyRecordingConn) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (*readyRecordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*readyRecordingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*readyRecordingConn) SetDeadline(time.Time) error      { return nil }
func (*readyRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*readyRecordingConn) SetWriteDeadline(time.Time) error { return nil }
