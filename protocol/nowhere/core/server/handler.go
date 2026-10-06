package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// TLSHandshaker lets a host retain ownership of TLS policy while requiring the
// connection-bound exporter produced by the completed TLS 1.3 handshake.
type TLSHandshaker func(context.Context, net.Conn) (wire.HandshakedConn, error)

// HandlerOptions builds a valid Handler and its internal state managers.
type HandlerOptions struct {
	// Config is the normalized protocol and resource configuration.
	Config *Config
	// Upstream receives authenticated, decoded logical flows.
	Upstream Upstream
	// Observer receives structured lifecycle and failure events.
	Observer diagnostic.Observer
}

// Handler authenticates carriers and hands decoded flows to Upstream.
type Handler struct {
	config              *Config
	upstream            Upstream
	observer            diagnostic.Observer
	claims              *claimRegistry
	tasks               *taskTracker
	sessions            *sessionManager
	admission           *unauthenticatedAdmission
	handshake           *handshakeGate
	readyGate           *readyGate
	now                 func() time.Time
	newReassemblyTicker func(time.Duration) reassemblyTicker
	randRead            func([]byte) (int, error)

	admissionLogMu   sync.Mutex
	admissionLastLog time.Time
	admissionSkipped int

	shutdown cleanupCoordinator
}

// NewHandler constructs a handler whose internal state is always initialized.
func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Config == nil || options.Config.credentials == nil {
		return nil, fmt.Errorf("%w: nil config", ErrInvalidHandler)
	}
	if options.Upstream == nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHandler, ErrUpstreamNotConfigured)
	}
	upstream := options.Upstream
	if dialUpstream, ok := upstream.(*DialUpstream); ok {
		upstream = dialUpstream.withTCPReadGrace(options.Config.timeouts.TCPReadGrace)
	} else if portalUpstream, ok := upstream.(*PortalUpstream); ok {
		upstream = portalUpstream.withTCPReadGrace(options.Config.timeouts.TCPReadGrace)
	}
	claims := newClaimRegistry(options.Config.timeouts.FlowPair, options.Config.limits)
	claims.setObserver(options.Observer)
	h := &Handler{
		config: options.Config, upstream: upstream, observer: options.Observer,
		claims: claims, tasks: newTaskTracker(), sessions: newSessionManager(claims),
		admission: newUnauthenticatedAdmission(
			options.Config.limits.MaxUnauthenticatedConnections,
			options.Config.limits.MaxUnauthenticatedPerSource,
		),
		handshake: newHandshakeGate(options.Config.limits.MaxConcurrentHandshakes),
		readyGate: &readyGate{},
		now:       time.Now,
		newReassemblyTicker: func(interval time.Duration) reassemblyTicker {
			return &realReassemblyTicker{Ticker: time.NewTicker(interval)}
		},
		randRead: rand.Read,
	}
	h.sessions.configureLimit(options.Config.limits.ActiveQUICSessions)
	return h, nil
}

// Shutdown closes admission, rejects pending setup, drains existing relays,
// and then releases authenticated sessions and physical carriers. The
// initiating context is the single cleanup deadline; every caller may stop
// waiting at its own deadline while the shared cleanup continues to completion.
func (h *Handler) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done, started := h.beginShutdown(ctx)
	err := h.shutdown.wait(ctx, done)
	if started && ctx.Err() != nil {
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		forcedCause := markForcedTermination(cause)
		if h.claims != nil {
			h.claims.AbortClosing(forcedCause)
		}
		if h.tasks != nil {
			h.tasks.ForceDetach(forcedCause)
		}
	}
	return err
}

func (h *Handler) beginShutdown(ctx context.Context) (<-chan struct{}, bool) {
	return h.shutdown.start(ctx, h.BeginDrain, h.shutdownCleanup)
}

// BeginDrain synchronously closes flow admission. New and not-yet-active flows
// are rejected with FLOW_LIMIT, while already READY relays remain eligible for
// graceful drain when Shutdown is called.
func (h *Handler) BeginDrain() {
	if h == nil {
		return
	}
	if h.readyGate != nil {
		h.readyGate.close()
	}
	if h.claims != nil {
		h.claims.CloseAdmission()
	}
	if h.sessions != nil {
		h.sessions.BeginDrain()
	}
	if h.tasks != nil {
		h.tasks.BeginClose(ErrDraining)
	}
}

func (h *Handler) shutdownCleanup(ctx context.Context) error {
	forcedClosed := markForcedTermination(ErrClosed)
	forceAtDeadline := func() {
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		forcedCause := markForcedTermination(cause)
		if h.claims != nil {
			h.claims.AbortClosing(forcedCause)
		}
		if h.tasks != nil {
			h.tasks.ForceClose(forcedCause)
		}
		if h.sessions != nil {
			h.sessions.Close()
		}
	}
	stopDeadlineClose := func() bool { return true }
	if ctx.Done() != nil {
		stopDeadlineClose = afterContextFunc(ctx, forceAtDeadline)
	}

	var drainErr error
	if h.claims != nil {
		drainErr = h.claims.BeginDrainContext(ctx)
	}
	if drainErr == nil && h.tasks != nil {
		drainErr = h.tasks.WaitRelays(ctx)
	}
	if ctx.Err() != nil {
		forceAtDeadline()
		stopDeadlineClose()
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		return cause
	}

	stopDeadlineClose()
	if h.tasks != nil {
		h.tasks.CancelAll(forcedClosed)
		h.tasks.CloseAll(forcedClosed)
	}
	if h.sessions != nil {
		h.sessions.Close()
	}
	var claimsErr error
	if h.claims != nil {
		claimsErr = h.claims.CloseContextCause(ctx, forcedClosed)
	}
	if h.tasks != nil {
		if err := h.tasks.Wait(ctx); err != nil {
			cause := context.Cause(ctx)
			if cause == nil {
				cause = err
			}
			forcedCause := markForcedTermination(cause)
			h.tasks.ForceClose(forcedCause)
			return cause
		}
	}
	if claimsErr != nil {
		return claimsErr
	}
	return drainErr
}

// Close applies this handler's normalized shutdown timeout.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	timeout := h.config.timeouts.Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return h.Shutdown(ctx)
}

// ServeTCP performs the host TLS handshake on a raw TCP carrier, authenticates,
// and routes exactly one request. On successful handoff Upstream owns the wrapped conn.
func (h *Handler) ServeTCP(ctx context.Context, raw net.Conn, source net.Addr, handshake TLSHandshaker, onClose CloseHandler) error {
	if err := h.validate(); err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return err
	}
	if raw == nil {
		return fmt.Errorf("%w: nil tcp connection", ErrInvalidHandler)
	}
	life := newLifecycle(ctx, raw, onClose, h.observer)
	var transportMu sync.Mutex
	transport := raw
	taskCtx, ownership, err := h.tasks.StartTransferableTransport(ctx, func(cause error) {
		transportMu.Lock()
		current := transport
		transportMu.Unlock()
		closeConnWithError(current, cause)
		life.Close(cause)
	})
	if err != nil {
		life.Close(err)
		return err
	}
	defer ownership.finishCarrier()

	guard, ok := h.admission.tryAcquire(source)
	if !ok {
		life.Close(ErrAdmissionLimit)
		h.emitAdmissionLimited(taskCtx, source)
		return report(ErrAdmissionLimit)
	}
	releaseAdmission := guard.Release
	defer releaseAdmission()

	if handshake == nil {
		life.Close(ErrTLSNotConfigured)
		return ErrTLSNotConfigured
	}
	releaseHandshake, err := h.handshake.acquire(taskCtx)
	if err != nil {
		life.Close(err)
		return report(err)
	}

	handshakeCtx, cancel := context.WithTimeout(taskCtx, h.config.timeouts.TLSHandshake)
	handshaked, err := handshake(handshakeCtx, raw)
	cancel()
	releaseHandshake()
	if err != nil {
		life.Close(err)
		h.emit(taskCtx, classifyTLSHandshake(err), "tls_handshake_failed", source, "", wire.SessionID{}, 0, err)
		return report(err)
	}
	if handshaked.Conn == nil {
		err = fmt.Errorf("%w: TLS handshaker returned nil conn", ErrInvalidHandler)
		life.Close(err)
		return err
	}
	if err := handshaked.TLSHandshakeInfo.Validate(h.config.alpn); err != nil {
		life.Close(err)
		h.emit(taskCtx, classifyTLSHandshake(err), "tls_handshake_failed", source, "", wire.SessionID{}, 0, err)
		return report(err)
	}
	transportMu.Lock()
	transport = handshaked.Conn
	transportMu.Unlock()
	owned := &ownedConn{Conn: handshaked.Conn, life: life}
	return h.handleTCPConn(withTaskOwnership(taskCtx, ownership), owned, source, handshaked.Exporter, releaseAdmission)
}

// HandleConn handles an already handshaked carrier. Hosts should prefer ServeTCP
// when they can provide a TLSHandshaker so its deadline also covers the handshake.
func (h *Handler) HandleConn(ctx context.Context, handshaked wire.HandshakedConn, source net.Addr, onClose CloseHandler) error {
	return h.ServeTCP(ctx, handshaked.Conn, source, func(_ context.Context, _ net.Conn) (wire.HandshakedConn, error) {
		return handshaked, nil
	}, onClose)
}

func (h *Handler) handleTCPConn(ctx context.Context, conn *ownedConn, source net.Addr, exporter wire.TLSExporter, releaseAdmission func()) error {
	deadline := h.authDeadline()
	_ = conn.SetDeadline(deadline)
	br := bufio.NewReader(conn)
	stream := &bufferedConn{Conn: conn, reader: br}

	sessionID, err := wire.ReadAuthFrame(stream, h.config.credentials, wire.AuthTransportTLSTCP, exporter)
	if err != nil {
		h.waitAuthFailure(ctx, deadline)
		conn.closeWithError(err)
		h.emit(ctx, diagnostic.LevelError, "auth_failed", source, "", wire.SessionID{}, 0, err)
		return report(err)
	}
	if releaseAdmission != nil {
		releaseAdmission()
	}
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetReadDeadline(h.now().Add(h.config.timeouts.RequestIdle))

	peeked, err := stream.reader.Peek(1)
	if err != nil {
		conn.closeWithError(err)
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
			h.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", sessionID, 0, err)
			return report(err)
		}
		return err
	}
	if peeked[0] == wire.MuxMarker {
		_, _ = stream.reader.Discard(1)
		_ = conn.SetDeadline(time.Time{})
		return h.handleMuxTCP(ctx, stream, source, sessionID)
	}

	header, err := wire.ReadFlowHeader(stream)
	if err != nil {
		conn.closeWithError(err)
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
			h.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", sessionID, 0, err)
			return report(err)
		}
		return err
	}
	target, err := h.readFlowTarget(stream, header)
	if err != nil {
		h.rejectFlowSetup(stream, sessionID, header, wire.SetupResultInvalidRequest)
		conn.closeWithError(err)
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return h.handleFlow(ctx, stream, source, sessionID, header, target, wire.CarrierTLSTCP)
}

func (h *Handler) readFlowTarget(reader io.Reader, header wire.FlowHeader) (wire.Target, error) {
	if !header.CarriesTarget() {
		return wire.Target{}, nil
	}
	return wire.ReadTarget(reader)
}

func (h *Handler) rejectFlowSetup(conn net.Conn, sessionID wire.SessionID, header wire.FlowHeader, code wire.SetupResult) {
	h.rejectFlowSetupGeneration(conn, sessionID, h.claims.CurrentGeneration(sessionID), false, header, code)
}

func (h *Handler) rejectFlowSetupGeneration(conn net.Conn, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, code wire.SetupResult) {
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach || header.Role == wire.FlowRoleDuplex {
		carrier = header.Downlink
	}
	h.claims.RejectClaim(flowClaim{
		SessionID: sessionID, FlowID: header.FlowID, Generation: generation, BoundGeneration: boundGeneration,
		Role: header.Role, Carrier: carrier,
		Metadata: claimMetadata{Kind: header.Kind, Uplink: header.Uplink, Downlink: header.Downlink, Hops: header.Hops},
		Stream:   conn,
	}, &setupResultError{code: code})
}

func (h *Handler) handleFlow(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target wire.Target, physical wire.Carrier) error {
	return h.handleFlowGeneration(ctx, conn, source, sessionID, h.claims.CurrentGeneration(sessionID), false, header, target, physical)
}

func (h *Handler) handleFlowGeneration(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, target wire.Target, physical wire.Carrier) error {
	if err := validateFlowTransport(header, physical); err != nil {
		h.rejectFlowSetupGeneration(conn, sessionID, generation, boundGeneration, header, setupFailureCode(err))
		closeConnWithError(conn, err)
		return err
	}
	switch header.Kind {
	case wire.FlowKindTCP:
		return h.handleTCPFlowGeneration(ctx, conn, source, sessionID, generation, boundGeneration, header, target, physical)
	case wire.FlowKindUDP:
		return h.handleUDPStreamFlowGeneration(ctx, conn, source, sessionID, generation, boundGeneration, header, target)
	default:
		err := fmt.Errorf("%w: invalid flow kind", ErrUnsupportedFlow)
		closeConnWithError(conn, err)
		return err
	}
}

func (h *Handler) handleTCPFlowGeneration(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, target wire.Target, physical wire.Carrier) error {
	active, err := h.claims.Submit(ctx, flowClaim{
		SessionID: sessionID, FlowID: header.FlowID, Generation: generation, BoundGeneration: boundGeneration,
		Role: header.Role, Carrier: physical,
		Metadata: claimMetadata{Kind: header.Kind, Uplink: header.Uplink, Downlink: header.Downlink, Hops: header.Hops},
		Target:   target, Stream: conn, Source: source,
	})
	if err != nil || active == nil {
		return err
	}

	var routed net.Conn
	if active.Duplex != nil {
		routed = active.Duplex.Stream
	} else {
		if active.Open == nil || active.Attach == nil {
			err := fmt.Errorf("%w: incomplete TCP pair", ErrInvalidHandler)
			closeClaimedFlow(active, err)
			active.Release()
			return err
		}
		routed = &splicedConn{
			reader: active.Open.Stream, writer: active.Attach.Stream,
			closer: []io.Closer{active.Open.Stream, active.Attach.Stream},
			remote: active.Open.Stream.RemoteAddr(), local: active.Open.Stream.LocalAddr(),
			target: active.Target, resultWriter: active.Selected.Stream, onClose: active.Release,
		}
	}
	flowCtx := withFlowInfo(withClaimContext(ctx, active.Context), FlowInfo{Hops: active.Metadata.Hops})
	return h.routeStream(flowCtx, routed, source, active.Target, active.Readiness, active.Release)
}

func (h *Handler) handleUDPStreamFlowGeneration(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, target wire.Target) error {
	half := udpHalf{Role: header.Role}
	switch header.Role {
	case wire.FlowRoleOpen:
		half.Uplink = newTCPUDPUplink(conn)
	case wire.FlowRoleAttach:
		half.Downlink = newTCPUDPDownlink(conn)
	case wire.FlowRoleDuplex:
		half.Uplink = newTCPUDPUplink(conn)
		half.Downlink = newTCPUDPDownlink(conn)
	default:
		err := fmt.Errorf("%w: invalid flow role", ErrUnsupportedFlow)
		closeConnWithError(conn, err)
		return err
	}
	return h.submitAndRouteUDPGeneration(ctx, source, sessionID, generation, boundGeneration, header, target, half)
}

func (h *Handler) submitAndRouteUDPGeneration(ctx context.Context, source net.Addr, sessionID wire.SessionID, generation uint64, boundGeneration bool, header wire.FlowHeader, target wire.Target, half udpHalf) error {
	paired, err := h.claims.SubmitUDPWithGeneration(ctx, sessionID, generation, boundGeneration, header, target, half, source, udpHalfTransport(header, half))
	if err != nil || paired == nil {
		return err
	}
	return h.routeCompletedUDP(ctx, source, paired)
}

func (h *Handler) routeCompletedUDP(ctx context.Context, source net.Addr, paired *pairedUDP) error {
	paired.IdleTimeout = h.config.timeouts.UDPIdle
	packetConn := newPairedUDPConn(paired)
	if conn, ok := packetConn.(*pairedUDPConn); ok && paired.Readiness != nil {
		paired.Readiness.setOnReady(conn.markReady)
	}
	flowCtx := withFlowInfo(withClaimContext(ctx, paired.Context), FlowInfo{Hops: paired.Hops})
	return h.routePacket(flowCtx, packetConn, source, paired.Target, paired.Readiness, paired.Release)
}

func validateFlowTransport(header wire.FlowHeader, physical wire.Carrier) error {
	valid := false
	switch header.Role {
	case wire.FlowRoleOpen:
		valid = header.Uplink == physical
	case wire.FlowRoleAttach:
		valid = header.Downlink == physical
	case wire.FlowRoleDuplex:
		valid = header.Uplink == physical && header.Downlink == physical
	}
	if !valid {
		return fmt.Errorf("%w: role=%d carrier=%d", ErrCarrierMismatch, header.Role, physical)
	}
	return nil
}

func (h *Handler) startRouteTask(ctx context.Context) (context.Context, func(), error) {
	if ownership := taskOwnershipFrom(ctx); ownership != nil {
		taskCtx, finish, err := ownership.claim()
		if err != nil {
			return nil, nil, err
		}
		// Transferable transports are registered before the FLOW header is
		// decoded, so their owned context cannot contain per-flow metadata yet.
		// Preserve the authenticated HOPS value when ownership moves from the
		// physical carrier to the logical route task.
		if info, ok := FlowInfoFromContext(ctx); ok {
			taskCtx = withFlowInfo(taskCtx, info)
		}
		return taskCtx, finish, nil
	}
	return h.tasks.Start(ctx)
}

func (h *Handler) routeStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness *flowReadiness, release func()) error {
	if h == nil || h.upstream == nil || h.tasks == nil {
		if readiness != nil {
			_ = readiness.Reject(ErrUpstreamNotConfigured)
		}
		closeConnWithError(conn, ErrUpstreamNotConfigured)
		if release != nil {
			release()
		}
		return ErrUpstreamNotConfigured
	}
	if readiness == nil {
		readiness = newFlowReadiness(nil, nil)
	}
	claimCtx := claimContextFrom(ctx)
	taskCtx, finish, err := h.startRouteTask(ctx)
	if err != nil {
		_ = readiness.Reject(err)
		closeConnWithError(conn, err)
		if release != nil {
			release()
		}
		return err
	}
	readiness.setReadyGate(h.readyGate)
	baseRouteCtx, cancel := context.WithCancelCause(taskCtx)
	life := &routeLifetime{cancel: cancel, finish: finish, release: release}
	tracked := &trackedFlowConn{Conn: conn, life: life}
	if claimCtx != nil {
		go func() {
			select {
			case <-claimCtx.Done():
				cause := context.Cause(claimCtx)
				if cause == nil {
					cause = claimCtx.Err()
				}
				cancel(cause)
			case <-baseRouteCtx.Done():
			}
		}()
	}
	go func() {
		<-baseRouteCtx.Done()
		cause := context.Cause(baseRouteCtx)
		if cause == nil {
			cause = baseRouteCtx.Err()
		}
		_ = readiness.Reject(cause)
		tracked.closeWithError(cause)
	}()
	upstreamCtx := baseRouteCtx
	if closeHandler := closeHandlerForConn(conn); closeHandler != nil {
		upstreamCtx = ContextWithCloseHandler(upstreamCtx, func(cause error) {
			closeHandler(cause)
			life.end(cause)
		})
	}
	if err := h.upstream.HandleStream(upstreamCtx, tracked, source, target, readiness); err != nil {
		_ = readiness.Reject(err)
		tracked.closeWithError(err)
		h.emit(upstreamCtx, diagnostic.LevelWarn, "upstream_stream_failed", source, targetAddress(target), wire.SessionID{}, 0, err)
		return report(err)
	}
	return nil
}

func (h *Handler) routePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness *flowReadiness, release func()) error {
	if h == nil || h.upstream == nil || h.tasks == nil {
		if readiness != nil {
			_ = readiness.Reject(ErrUpstreamNotConfigured)
		}
		closePacketConnWithError(pc, ErrUpstreamNotConfigured)
		if release != nil {
			release()
		}
		return ErrUpstreamNotConfigured
	}
	if readiness == nil {
		readiness = newFlowReadiness(nil, nil)
	}
	claimCtx := claimContextFrom(ctx)
	taskCtx, finish, err := h.startRouteTask(ctx)
	if err != nil {
		_ = readiness.Reject(err)
		closePacketConnWithError(pc, err)
		if release != nil {
			release()
		}
		return err
	}
	readiness.setReadyGate(h.readyGate)
	baseRouteCtx, cancel := context.WithCancelCause(taskCtx)
	life := &routeLifetime{cancel: cancel, finish: finish, release: release}
	tracked := &trackedFlowPacketConn{PacketConn: pc, life: life}
	if claimCtx != nil {
		go func() {
			select {
			case <-claimCtx.Done():
				cause := context.Cause(claimCtx)
				if cause == nil {
					cause = claimCtx.Err()
				}
				cancel(cause)
			case <-baseRouteCtx.Done():
			}
		}()
	}
	go func() {
		<-baseRouteCtx.Done()
		cause := context.Cause(baseRouteCtx)
		if cause == nil {
			cause = baseRouteCtx.Err()
		}
		_ = readiness.Reject(cause)
		tracked.closeWithError(cause)
	}()
	upstreamCtx := baseRouteCtx
	if closeHandler := closeHandlerForPacketConn(pc); closeHandler != nil {
		upstreamCtx = ContextWithCloseHandler(upstreamCtx, func(cause error) {
			closeHandler(cause)
			life.end(cause)
		})
	}
	if err := h.upstream.HandlePacket(upstreamCtx, tracked, source, target, readiness); err != nil {
		_ = readiness.Reject(err)
		tracked.closeWithError(err)
		h.emit(upstreamCtx, diagnostic.LevelWarn, "upstream_packet_failed", source, targetAddress(target), wire.SessionID{}, 0, err)
		return report(err)
	}
	return nil
}

func (h *Handler) validate() error {
	if h == nil || h.config == nil || h.config.credentials == nil || h.claims == nil || h.tasks == nil || h.sessions == nil {
		return ErrInvalidHandler
	}
	if h.upstream == nil {
		return ErrUpstreamNotConfigured
	}
	return nil
}

func (h *Handler) authDeadline() time.Time {
	var raw [8]byte
	factor := 1.0
	if _, err := h.randRead(raw[:]); err == nil {
		ratio := float64(binary.BigEndian.Uint64(raw[:])) / float64(^uint64(0))
		factor = 0.8 + ratio*0.4
	}
	return h.now().Add(time.Duration(float64(h.config.timeouts.Auth) * factor))
}

func (h *Handler) waitAuthFailure(ctx context.Context, deadline time.Time) {
	delay := deadline.Sub(h.now())
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (h *Handler) emit(ctx context.Context, level diagnostic.Level, code string, source net.Addr, target string, sessionID wire.SessionID, flowID wire.FlowID, err error) {
	h.emitCarrier(ctx, diagnostic.CarrierTCPTLS, level, code, source, target, sessionID, flowID, err)
}

func (h *Handler) emitQUIC(ctx context.Context, level diagnostic.Level, code string, source net.Addr, target string, sessionID wire.SessionID, flowID wire.FlowID, err error) {
	h.emitCarrier(ctx, diagnostic.CarrierQUIC, level, code, source, target, sessionID, flowID, err)
}

func (h *Handler) emitCarrier(ctx context.Context, carrier string, level diagnostic.Level, code string, source net.Addr, target string, sessionID wire.SessionID, flowID wire.FlowID, err error) {
	result, class := "", ""
	if err != nil {
		result, class = diagnostic.ClassifyClose(err)
	}
	diagnostic.Emit(ctx, h.observer, diagnostic.Event{
		Level: level, Code: code, Component: "server", Carrier: carrier,
		Source: source, Target: target, SessionID: sessionID, FlowID: flowID,
		Result: result, ErrorClass: class, Err: err,
	})
}

func (h *Handler) emitAdmissionLimited(ctx context.Context, source net.Addr) {
	h.admissionLogMu.Lock()
	now := h.now()
	if !h.admissionLastLog.IsZero() && now.Sub(h.admissionLastLog) < time.Second {
		h.admissionSkipped++
		h.admissionLogMu.Unlock()
		return
	}
	skipped := h.admissionSkipped
	h.admissionSkipped = 0
	h.admissionLastLog = now
	h.admissionLogMu.Unlock()

	outcome := ""
	if skipped > 0 {
		outcome = fmt.Sprintf("suppressed=%d", skipped)
	}
	diagnostic.Emit(ctx, h.observer, diagnostic.Event{
		Level: diagnostic.LevelWarn, Code: "admission_limited", Component: "server",
		Source: source, Outcome: outcome, Err: ErrAdmissionLimit,
	})
}

func classifyTLSHandshake(err error) diagnostic.Level {
	if err == nil {
		return diagnostic.LevelError
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return diagnostic.LevelWarn
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return diagnostic.LevelWarn
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return diagnostic.LevelDebug
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "use of closed network connection"):
		return diagnostic.LevelDebug
	default:
		return diagnostic.LevelError
	}
}

func closeConnWithError(conn net.Conn, err error) {
	if tracked, ok := conn.(*trackedFlowConn); ok {
		tracked.closeWithError(err)
		return
	}
	if owned, ok := conn.(*ownedConn); ok {
		owned.closeWithError(err)
		return
	}
	if buffered, ok := conn.(*bufferedConn); ok {
		closeConnWithError(buffered.Conn, err)
		return
	}
	if spliced, ok := conn.(*splicedConn); ok {
		spliced.closeWithError(err)
		return
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func closePacketConnWithError(pc net.PacketConn, err error) {
	if tracked, ok := pc.(*trackedFlowPacketConn); ok {
		tracked.closeWithError(err)
		return
	}
	if owned, ok := pc.(*ownedPacketConn); ok {
		owned.closeWithError(err)
		return
	}
	if paired, ok := pc.(*pairedUDPConn); ok {
		paired.closeWithError(err)
		return
	}
	if nowu, ok := pc.(*nowuFlow); ok {
		nowu.shutdown(err)
		return
	}
	if pc != nil {
		_ = pc.Close()
	}
}

func lifecycleFromConn(conn net.Conn) *lifecycle {
	switch value := conn.(type) {
	case *ownedConn:
		return value.life
	case *bufferedConn:
		return lifecycleFromConn(value.Conn)
	}
	return nil
}

func lifecycleFromPacketConn(pc net.PacketConn) *lifecycle {
	if value, ok := pc.(*ownedPacketConn); ok {
		return value.life
	}
	return nil
}

func closeHandlerForConn(conn net.Conn) CloseHandler {
	if life := lifecycleFromConn(conn); life != nil {
		return life.Close
	}
	switch value := conn.(type) {
	case *splicedConn:
		return value.closeWithError
	}
	return nil
}

func closeHandlerForPacketConn(pc net.PacketConn) CloseHandler {
	if life := lifecycleFromPacketConn(pc); life != nil {
		return life.Close
	}
	switch value := pc.(type) {
	case *pairedUDPConn:
		return value.closeWithError
	case *nowuFlow:
		return value.shutdown
	}
	return nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseRead() error           { return closeReadSide(c.Conn) }
func (c *bufferedConn) CloseWrite() error          { return closeWriteSide(c.Conn) }
