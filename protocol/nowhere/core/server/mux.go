package server

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	carriermux "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/mux"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func withoutTaskOwnership(ctx context.Context) context.Context {
	return context.WithValue(ctx, taskOwnershipContextKey{}, (*taskOwnership)(nil))
}

func (h *Handler) handleMuxTCP(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID) error {
	handle, incoming, err := carriermux.Start(conn, carriermux.DefaultConfig())
	if err != nil {
		closeConnWithError(conn, err)
		return err
	}
	defer handle.Close()
	defer incoming.Discard()

	go func() {
		if handle.IdleFor(ctx, carriermux.IdleTimeout) {
			handle.Close()
		}
	}()

	streamCtx := withoutTaskOwnership(ctx)
	for {
		stream, err := incoming.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if handle.IsClosed() {
				return nil
			}
			return err
		}
		go h.serveMuxStream(streamCtx, stream, source, sessionID)
	}
}

func (h *Handler) serveMuxStream(ctx context.Context, stream *carriermux.Stream, source net.Addr, sessionID wire.SessionID) {
	expected := stream.FlowID()
	_ = stream.SetReadDeadline(h.now().Add(h.config.timeouts.RequestIdle))
	header, err := wire.ReadFlowHeader(stream)
	if err != nil {
		_ = stream.Close()
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
			h.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", sessionID, expected, err)
		}
		return
	}
	if header.FlowID != expected {
		h.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", sessionID, expected,
			errors.New("nowhere: mux/header flow ID mismatch"))
		_ = stream.Close()
		return
	}
	target, err := h.readFlowTarget(stream, header)
	if err != nil {
		h.rejectFlowSetup(stream, sessionID, header, wire.SetupResultInvalidRequest)
		_ = stream.Close()
		return
	}
	_ = stream.SetDeadline(time.Time{})
	_ = h.handleFlow(ctx, stream, source, sessionID, header, target, wire.CarrierTLSTCP)
}
