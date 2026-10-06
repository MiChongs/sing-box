package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func (r *claimRegistry) setObserver(observer diagnostic.Observer) {
	r.mu.Lock()
	r.observer = observer
	r.mu.Unlock()
}

func (r *claimRegistry) RejectFlowSetup(sessionID wire.SessionID, flowID wire.FlowID, code wire.SetupResult) {
	r.Reject(sessionID, flowID, r.CurrentGeneration(sessionID), &setupResultError{code: code})
}

// SubmitTCP caches or pairs a TCP half.
func (r *claimRegistry) SubmitTCP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target wire.Target, conn net.Conn) (net.Conn, error) {
	return r.SubmitTCPWithSource(ctx, sessionID, header, target, conn, nil)
}

// SubmitTCPWithSource is SubmitTCP with optional source for diagnostics.
func (r *claimRegistry) SubmitTCPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target wire.Target, conn net.Conn, source net.Addr) (net.Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil tcp half", ErrInvalidHandler)
	}
	if err := validatePairHeader(header, wire.FlowKindTCP); err != nil {
		return nil, err
	}
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
		target = wire.Target{}
	}
	active, err := r.Submit(ctx, flowClaim{
		SessionID: sessionID, FlowID: header.FlowID, Generation: r.CurrentGeneration(sessionID),
		Role: header.Role, Carrier: carrier,
		Metadata: claimMetadata{Kind: header.Kind, Uplink: header.Uplink, Downlink: header.Downlink, Hops: header.Hops},
		Target:   target, Stream: conn, Source: source,
	})
	if err != nil || active == nil {
		return nil, err
	}
	if active.Open == nil || active.Attach == nil {
		err := fmt.Errorf("%w: incomplete TCP pair", ErrInvalidHandler)
		closeClaimedFlow(active, err)
		active.Release()
		return nil, err
	}
	return &splicedConn{
		reader: active.Open.Stream, writer: active.Attach.Stream,
		closer: []io.Closer{active.Open.Stream, active.Attach.Stream},
		remote: active.Open.Stream.RemoteAddr(), local: active.Open.Stream.LocalAddr(),
		target: active.Target, resultWriter: active.Selected.Stream,
		onClose: active.Release,
	}, nil
}

func validatePairHeader(header wire.FlowHeader, kind wire.FlowKind) error {
	if header.Kind != kind || header.FlowID == 0 {
		return fmt.Errorf("%w: invalid flow header", ErrUnsupportedFlow)
	}
	if header.Role != wire.FlowRoleOpen && header.Role != wire.FlowRoleAttach {
		return fmt.Errorf("%w: invalid role", ErrUnsupportedFlow)
	}
	if header.Uplink == header.Downlink ||
		(header.Uplink != wire.CarrierTLSTCP && header.Uplink != wire.CarrierQUIC) ||
		(header.Downlink != wire.CarrierTLSTCP && header.Downlink != wire.CarrierQUIC) {
		return fmt.Errorf("%w: invalid carriers", ErrCarrierMismatch)
	}
	return nil
}

func carrierTransportName(c wire.Carrier) string {
	if c == wire.CarrierQUIC {
		return "quic"
	}
	return "tcp"
}

func flowRoleName(role wire.FlowRole) string {
	switch role {
	case wire.FlowRoleOpen:
		return "open"
	case wire.FlowRoleAttach:
		return "attach"
	case wire.FlowRoleDuplex:
		return "duplex"
	default:
		return "unknown"
	}
}

type splicedConn struct {
	reader       io.Reader
	writer       io.Writer
	closer       []io.Closer
	remote       net.Addr
	local        net.Addr
	target       wire.Target
	resultWriter net.Conn
	onClose      func()
	once         sync.Once
	readOnce     sync.Once
	readErr      error
	writeOnce    sync.Once
	writeErr     error
}

func (c *splicedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *splicedConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *splicedConn) CloseRead() error {
	c.readOnce.Do(func() {
		c.readErr = closeReadSide(c.reader)
	})
	return c.readErr
}

func (c *splicedConn) CloseWrite() error {
	c.writeOnce.Do(func() {
		c.writeErr = closeWriteSide(c.writer)
	})
	return c.writeErr
}

func (c *splicedConn) Close() (err error) {
	c.once.Do(func() {
		var errs []error
		for _, closer := range c.closer {
			if closeErr := closer.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				errs = append(errs, closeErr)
			}
		}
		err = errors.Join(errs...)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *splicedConn) closeWithError(cause error) {
	c.once.Do(func() {
		for _, closer := range c.closer {
			if conn, ok := closer.(net.Conn); ok {
				closeConnWithError(conn, cause)
			} else {
				_ = closer.Close()
			}
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func (c *splicedConn) LocalAddr() net.Addr  { return c.local }
func (c *splicedConn) RemoteAddr() net.Addr { return c.remote }
func (c *splicedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *splicedConn) SetReadDeadline(t time.Time) error {
	if deadline, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(t)
	}
	return nil
}

func (c *splicedConn) SetWriteDeadline(t time.Time) error {
	if deadline, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*splicedConn)(nil)

func closeReadSide(value any) error {
	if closer, ok := value.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	if closer, ok := value.(io.Closer); ok {
		return closer.Close()
	}
	return errors.New("nowhere: read side does not support close")
}

func closeWriteSide(value any) error {
	if closer, ok := value.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := value.(io.Closer); ok {
		return closer.Close()
	}
	return errors.New("nowhere: write side does not support close")
}
