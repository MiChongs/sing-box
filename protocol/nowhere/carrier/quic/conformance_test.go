//go:build with_quic

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic/conformance"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestOutboundSessionConformance(t *testing.T) {
	cfg := &QUICConfig{}
	session := NewSession(cfg)
	recorder := &fullConformanceRecorder{blockAfter: 3, shutdown: session.lifetimeDone}
	session.openStream = recorder.Open
	session.handshakeInfo = func() (wire.TLSHandshakeInfo, error) {
		return wire.TLSHandshakeInfo{
			TLSVersion:     tls.VersionTLS13,
			NegotiatedALPN: wire.DefaultALPN,
		}, nil
	}
	var roundTrip atomic.Bool
	datagrams := make(chan []byte, 1)
	session.sendDatagram = func(ctx context.Context, payload []byte) error {
		if roundTrip.Load() {
			select {
			case datagrams <- bytes.Clone(payload):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	session.receiveDatagram = func(ctx context.Context) ([]byte, error) {
		if roundTrip.Load() {
			select {
			case payload := <-datagrams:
				return payload, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	session.finishReady(nil)

	client := NewClient(cfg)
	client.session = session
	blockedSession := NewSession(cfg)
	blockedSession.mu.Lock()
	blockedSession.dialStarted = true
	blockedSession.mu.Unlock()
	blockedClient := NewClient(cfg)
	blockedClient.session = blockedSession
	base := conformance.Harness{
		ExpectedALPN:     wire.DefaultALPN,
		TLSHandshakeInfo: session.TLSHandshakeInfo,
		Send: func(ctx context.Context) error {
			return session.SendDatagram(ctx, []byte("test"))
		},
		Receive: func(ctx context.Context) error {
			_, err := session.ReceiveDatagram(ctx)
			return err
		},
		Shutdown: func() error {
			client.InvalidateSession(session)
			return nil
		},
	}
	err := conformance.CheckFull(conformance.FullHarness{
		Harness: base,
		Prepared: &conformance.PreparedStreamHarness{
			Session:       session,
			OpenedStreams: recorder.Count,
			SetupBytes:    recorder.Bytes,
			WriteFinished: recorder.WriteFinished,
			ReadCanceled:  recorder.ReadCanceled,
		},
		DatagramRoundTrip: func(ctx context.Context, payload []byte) ([]byte, error) {
			roundTrip.Store(true)
			defer roundTrip.Store(false)
			if err := session.SendDatagram(ctx, payload); err != nil {
				return nil, err
			}
			return session.ReceiveDatagram(ctx)
		},
		BlockingOperations: []conformance.Operation{
			{Name: "AcquireSession", Run: func(ctx context.Context) error {
				_, err := blockedClient.AcquireSession(ctx)
				return err
			}},
			{Name: "PrepareStream", Run: func(ctx context.Context) error {
				_, err := session.PrepareStream(ctx)
				return err
			}},
		},
		Invalidate: func() error {
			client.InvalidateSession(session)
			return blockedClient.Close()
		},
		Close: func() error {
			return errors.Join(client.Close(), blockedClient.Close())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fullConformanceRecorder struct {
	mu         sync.Mutex
	streams    []*fullConformanceStream
	blockAfter int
	shutdown   <-chan struct{}
}

func (r *fullConformanceRecorder) Open(ctx context.Context) (stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.blockAfter > 0 && len(r.streams) >= r.blockAfter {
		shutdown := r.shutdown
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-shutdown:
			return nil, errSessionClosed
		}
	}
	opened := &fullConformanceStream{}
	r.streams = append(r.streams, opened)
	r.mu.Unlock()
	return opened, nil
}

func (r *fullConformanceRecorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

func (r *fullConformanceRecorder) stream(index int) *fullConformanceStream {
	r.mu.Lock()
	defer r.mu.Unlock()
	if index < 0 || index >= len(r.streams) {
		return nil
	}
	return r.streams[index]
}

func (r *fullConformanceRecorder) Bytes(index int) []byte {
	if opened := r.stream(index); opened != nil {
		return opened.Bytes()
	}
	return nil
}

func (r *fullConformanceRecorder) WriteFinished(index int) bool {
	opened := r.stream(index)
	return opened != nil && opened.Finished()
}

func (r *fullConformanceRecorder) ReadCanceled(index int) bool {
	opened := r.stream(index)
	return opened != nil && opened.ReadWasCanceled()
}

type fullConformanceStream struct {
	mu            sync.Mutex
	written       bytes.Buffer
	readDeadline  time.Time
	writeDeadline time.Time
	finished      bool
	readCanceled  bool
}

func (s *fullConformanceStream) Read([]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readCanceled {
		return 0, net.ErrClosed
	}
	if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	return 0, io.EOF
}

func (s *fullConformanceStream) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	return s.written.Write(payload)
}

func (s *fullConformanceStream) Close() error {
	s.mu.Lock()
	s.finished = true
	s.mu.Unlock()
	return nil
}

func (s *fullConformanceStream) CancelRead(quic.StreamErrorCode) {
	s.mu.Lock()
	s.readCanceled = true
	s.mu.Unlock()
}

func (*fullConformanceStream) CancelWrite(quic.StreamErrorCode) {}

func (s *fullConformanceStream) SetDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.readDeadline = deadline
	s.writeDeadline = deadline
	s.mu.Unlock()
	return nil
}

func (s *fullConformanceStream) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.readDeadline = deadline
	s.mu.Unlock()
	return nil
}

func (s *fullConformanceStream) SetWriteDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.writeDeadline = deadline
	s.mu.Unlock()
	return nil
}

func (s *fullConformanceStream) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.written.Bytes())
}

func (s *fullConformanceStream) Finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished
}

func (s *fullConformanceStream) ReadWasCanceled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readCanceled
}
