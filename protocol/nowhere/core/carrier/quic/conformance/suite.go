// Package conformance provides host-neutral checks for QUIC adapters.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	nquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const operationTimeout = time.Second

// Harness describes one disposable, instrumented QUIC adapter. Send, Receive,
// and optional Accept must block until their context ends or Shutdown closes
// the physical session.
type Harness struct {
	ExpectedALPN string

	TLSHandshakeInfo func() (wire.TLSHandshakeInfo, error)
	Send             func(context.Context) error
	Receive          func(context.Context) error
	Accept           func(context.Context) error
	Shutdown         func() error

	MarkAuthenticated func()
	Authenticated     func() bool
}

// Operation is a context-bound call that must remain blocked until it is
// canceled, invalidated, or closed.
type Operation struct {
	Name string
	Run  func(context.Context) error
}

// PreparedStreamHarness exposes peer-side observations for streams opened by
// Session. The recorder indexes streams in PrepareStream open order.
type PreparedStreamHarness struct {
	Session nquic.Session

	OpenedStreams func() int
	SetupBytes    func(index int) []byte
	WriteFinished func(index int) bool
	ReadCanceled  func(index int) bool
}

// FullHarness extends Harness with prepared-stream, DATAGRAM roundtrip, and
// invalidation/close probes. Prepared is required for outbound adapters
// (Harness.Accept == nil) and omitted for inbound-only adapters.
type FullHarness struct {
	Harness
	Prepared          *PreparedStreamHarness
	DatagramRoundTrip func(context.Context, []byte) ([]byte, error)

	// BlockingOperations adds host-specific Acquire, Prepare, Send, Receive, or
	// Accept calls that invalidation/close must unblock.
	BlockingOperations []Operation
	Invalidate         func() error
	Close              func() error
}

// Check exercises the common outbound Session and inbound QuicConn contracts.
func Check(h Harness) error {
	if err := checkBasics(h); err != nil {
		return err
	}
	return checkShutdown(h, nil, nil)
}

// CheckFull runs the public QUIC adapter conformance suite. It preserves Check
// compatibility while additionally exercising stream setup/FIN semantics,
// half-close, stream deadlines, atomic DATAGRAM roundtrips, and host-supplied
// blocking operations during concurrent invalidate/close.
func CheckFull(h FullHarness) error {
	if err := checkBasics(h.Harness); err != nil {
		return err
	}
	if h.DatagramRoundTrip == nil {
		return errors.New("nowhere: full QUIC harness lacks DATAGRAM roundtrip")
	}
	if h.Accept == nil && h.Prepared == nil {
		return errors.New("nowhere: outbound full QUIC harness lacks prepared-stream probe")
	}
	if h.Prepared != nil {
		if err := checkPreparedStreams(*h.Prepared); err != nil {
			return err
		}
		required := map[string]bool{"AcquireSession": false, "PrepareStream": false}
		for _, operation := range h.BlockingOperations {
			if _, ok := required[operation.Name]; ok {
				required[operation.Name] = true
			}
		}
		for name, present := range required {
			if !present {
				return fmt.Errorf("nowhere: outbound full QUIC harness lacks %s shutdown probe", name)
			}
		}
	}
	for _, payload := range [][]byte{nil, []byte("nowhere-datagram-roundtrip")} {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		got, err := h.DatagramRoundTrip(ctx, payload)
		cancel()
		if err != nil {
			return fmt.Errorf("DATAGRAM roundtrip (%d bytes): %w", len(payload), err)
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("DATAGRAM roundtrip = %x, want %x", got, payload)
		}
	}
	shutdowns := []func() error{h.Invalidate, h.Close}
	return checkShutdown(h.Harness, h.BlockingOperations, shutdowns)
}

func checkBasics(h Harness) error {
	if h.TLSHandshakeInfo == nil || h.Send == nil || h.Receive == nil || h.Shutdown == nil {
		return errors.New("nowhere: incomplete QUIC conformance harness")
	}
	info, err := h.TLSHandshakeInfo()
	if err != nil {
		return fmt.Errorf("handshake info: %w", err)
	}
	if err := info.Validate(h.ExpectedALPN); err != nil {
		return fmt.Errorf("handshake validation: %w", err)
	}

	if err := checkCanceled("SendDatagram", h.Send); err != nil {
		return err
	}
	if err := checkInProgressCanceled("SendDatagram", h.Send); err != nil {
		return err
	}
	if err := checkInProgressCanceled("ReceiveDatagram", h.Receive); err != nil {
		return err
	}
	if h.Accept != nil {
		if err := checkInProgressCanceled("AcceptStream", h.Accept); err != nil {
			return err
		}
	}
	if err := checkDeadline("SendDatagram", h.Send); err != nil {
		return err
	}
	if err := checkDeadline("ReceiveDatagram", h.Receive); err != nil {
		return err
	}

	if h.MarkAuthenticated != nil || h.Authenticated != nil {
		if h.MarkAuthenticated == nil || h.Authenticated == nil {
			return errors.New("nowhere: incomplete authentication notification harness")
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.MarkAuthenticated()
			}()
		}
		wg.Wait()
		if !h.Authenticated() {
			return errors.New("nowhere: authentication notification was not retained")
		}
	}
	return nil
}

func checkShutdown(h Harness, extra []Operation, shutdowns []func() error) error {
	operations := []Operation{
		{Name: "SendDatagram", Run: h.Send},
		{Name: "ReceiveDatagram", Run: h.Receive},
	}
	if h.Accept != nil {
		operations = append(operations, Operation{Name: "AcceptStream", Run: h.Accept})
	}
	for _, operation := range extra {
		if operation.Name == "" || operation.Run == nil {
			return errors.New("nowhere: invalid blocking QUIC operation")
		}
		operations = append(operations, operation)
	}
	results := make(chan operationResult, len(operations))
	for _, operation := range operations {
		operation := operation
		go func() {
			results <- operationResult{name: operation.Name, err: operation.Run(context.Background())}
		}()
	}

	allShutdowns := make([]func() error, 0, 1+len(shutdowns))
	allShutdowns = append(allShutdowns, h.Shutdown)
	for _, shutdown := range shutdowns {
		if shutdown != nil {
			allShutdowns = append(allShutdowns, shutdown)
		}
	}
	const concurrentCalls = 16
	shutdownResults := make(chan error, concurrentCalls*len(allShutdowns))
	for _, shutdown := range allShutdowns {
		shutdown := shutdown
		for i := 0; i < concurrentCalls; i++ {
			go func() { shutdownResults <- shutdown() }()
		}
	}
	deadline := time.NewTimer(operationTimeout)
	defer deadline.Stop()
	for range operations {
		select {
		case result := <-results:
			if result.err == nil {
				return fmt.Errorf("%s returned nil after shutdown", result.name)
			}
		case <-deadline.C:
			return errors.New("nowhere: QUIC shutdown did not unblock all operations")
		}
	}
	for i := 0; i < cap(shutdownResults); i++ {
		select {
		case err := <-shutdownResults:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("concurrent shutdown: %w", err)
			}
		case <-deadline.C:
			return errors.New("nowhere: concurrent QUIC shutdown deadlocked")
		}
	}
	return nil
}

func checkPreparedStreams(h PreparedStreamHarness) error {
	if h.Session == nil || h.OpenedStreams == nil || h.SetupBytes == nil ||
		h.WriteFinished == nil || h.ReadCanceled == nil {
		return errors.New("nowhere: incomplete prepared-stream conformance harness")
	}
	if got := h.OpenedStreams(); got != 0 {
		return fmt.Errorf("acquire opened %d QUIC streams, want 0", got)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Session.PrepareStream(canceled); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("PrepareStream canceled error = %v, want context.Canceled", err)
	}
	if got := h.OpenedStreams(); got != 0 {
		return fmt.Errorf("canceled PrepareStream opened %d QUIC streams, want 0", got)
	}

	const (
		firstSetup  = "opaque\x00setup"
		secondSetup = "finish-write-setup"
	)
	first, err := h.Session.PrepareStream(context.Background())
	if err != nil {
		return fmt.Errorf("PrepareStream: %w", err)
	}
	if got := h.OpenedStreams(); got != 1 {
		_ = first.Close()
		return fmt.Errorf("first PrepareStream opened %d streams, want 1", got)
	}
	conn, err := first.Commit(context.Background(), []byte(firstSetup), false)
	if err != nil {
		return fmt.Errorf("commit finishWrite=false: %w", err)
	}
	if got := h.SetupBytes(0); !bytes.Equal(got, []byte(firstSetup)) {
		_ = conn.Close()
		return fmt.Errorf("setup bytes = %x, want %x", got, []byte(firstSetup))
	}
	if h.WriteFinished(0) {
		_ = conn.Close()
		return errors.New("finishWrite=false sent FIN")
	}
	closeRead, ok := conn.(interface{ CloseRead() error })
	if !ok {
		_ = conn.Close()
		return errors.New("committed QUIC stream lacks CloseRead")
	}
	closeWrite, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		_ = conn.Close()
		return errors.New("committed QUIC stream lacks CloseWrite")
	}
	if err := closeRead.CloseRead(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("CloseRead: %w", err)
	}
	if !h.ReadCanceled(0) {
		_ = conn.Close()
		return errors.New("CloseRead did not cancel peer read direction")
	}
	if _, err := conn.Write([]byte("after-close-read")); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write after CloseRead: %w", err)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("CloseWrite: %w", err)
	}
	if !h.WriteFinished(0) {
		_ = conn.Close()
		return errors.New("CloseWrite did not send FIN")
	}
	_ = conn.Close()

	second, err := h.Session.PrepareStream(context.Background())
	if err != nil {
		return fmt.Errorf("second PrepareStream: %w", err)
	}
	conn, err = second.Commit(context.Background(), []byte(secondSetup), true)
	if err != nil {
		return fmt.Errorf("commit finishWrite=true: %w", err)
	}
	if got := h.SetupBytes(1); !bytes.Equal(got, []byte(secondSetup)) {
		_ = conn.Close()
		return fmt.Errorf("second setup bytes = %x, want %x", got, []byte(secondSetup))
	}
	if !h.WriteFinished(1) {
		_ = conn.Close()
		return errors.New("finishWrite=true did not send FIN")
	}
	_ = conn.Close()

	deadlineStream, err := h.Session.PrepareStream(context.Background())
	if err != nil {
		return fmt.Errorf("deadline PrepareStream: %w", err)
	}
	conn, err = deadlineStream.Commit(context.Background(), []byte("deadline"), false)
	if err != nil {
		return fmt.Errorf("deadline Commit: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		_ = conn.Close()
		return fmt.Errorf("SetReadDeadline: %w", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !isTimeout(err) {
		_ = conn.Close()
		return fmt.Errorf("read deadline error = %v, want timeout", err)
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		_ = conn.Close()
		return fmt.Errorf("SetWriteDeadline: %w", err)
	}
	if _, err := conn.Write([]byte("deadline")); !isTimeout(err) {
		_ = conn.Close()
		return fmt.Errorf("write deadline error = %v, want timeout", err)
	}
	_ = conn.Close()
	return nil
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type operationResult struct {
	name string
	err  error
}

func checkCanceled(name string, operation func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := operation(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s canceled error = %v, want context.Canceled", name, err)
	}
	return nil
}

func checkInProgressCanceled(name string, operation func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		result <- operation(ctx)
	}()
	<-started
	timer := time.NewTimer(10 * time.Millisecond)
	<-timer.C
	cancel()
	timer.Reset(operationTimeout)
	defer timer.Stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			return fmt.Errorf("%s in-progress cancellation error = %v, want context.Canceled", name, err)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("%s in-progress cancellation did not unblock", name)
	}
}

func checkDeadline(name string, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := operation(ctx); !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s deadline error = %v, want context.DeadlineExceeded", name, err)
	}
	return nil
}
