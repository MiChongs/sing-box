// Package portal is the Nowhere 3 server. A listener accepts only ALPN nw3.
package portal

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/dgram"
	"github.com/sagernet/sing-box/protocol/nowhere/core/flowio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	maxUnauth      = 256
	maxPerSource   = 32
	maxFlows       = 4096
	udpIdle        = 120 * time.Second
	flowSetupLimit = 20 * time.Second
)

// Config is a Portal. Egress mode ignores Upstream and bridges to the registered exit.
type Config struct {
	SharedKey    string
	Morph        bool
	TLS          *tls.Config
	Upstream     Upstream
	Egress       bool
	UploadMbps   int
	DownloadMbps int
}

// Server accepts Vector and, when Egress is set, one Egress registration.
type Server struct {
	creds    *wire.Credentials
	keys     *morph.Keys
	tls      *tls.Config
	up       Upstream
	egress   bool
	upload   *flowio.Limiter
	download *flowio.Limiter

	admit admit
	flows gate

	mu    sync.Mutex
	owner *egressOwner
}

type egressOwner struct {
	conn   qio.Conn
	router *dgram.Router
}

// New checks the shared key and exit mode.
func New(cfg Config) (*Server, error) {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	if cfg.TLS == nil {
		return nil, errors.New("nw3: missing portal TLS config")
	}
	if !cfg.Egress && cfg.Upstream == nil {
		return nil, errors.New("nw3: missing portal upstream")
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{wire.ALPN}
	tlsCfg.SessionTicketsDisabled = true
	s := &Server{
		creds:    creds,
		tls:      tlsCfg,
		up:       cfg.Upstream,
		egress:   cfg.Egress,
		upload:   flowio.NewMbps(cfg.UploadMbps),
		download: flowio.NewMbps(cfg.DownloadMbps),
		admit:    admit{per: map[string]int{}},
	}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		s.keys = &keys
	}
	return s, nil
}

// Serve accepts TLS connections. The listener is closed when ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveTCP(ctx, conn)
	}
}

// ServeQUIC accepts QUIC connections that already negotiated ALPN nw3 inside the host stack.
// The host TLS config must offer only nw3; mismatched ALPNs are closed here as well.
func (s *Server) ServeQUIC(ctx context.Context, ln qio.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveQUIC(ctx, conn)
	}
}

func (s *Server) serveTCP(ctx context.Context, raw net.Conn) {
	acceptedAt := time.Now()
	deadline := acceptedAt.Add(authBudget())
	morphing := s.keys != nil
	if morphing {
		// Abortive close stays on until Vector authentication succeeds.
		if err := setZeroLinger(raw); err != nil {
			_ = raw.Close()
			return
		}
	}
	if !s.admit.take(raw.RemoteAddr()) {
		if !morphing {
			_ = raw.Close()
			return
		}
		// A Morph TCP connection waits for a slot until the handshake deadline
		// instead of being dropped. The wait does not read the socket.
		if !s.admit.wait(ctx, raw.RemoteAddr(), deadline) {
			_ = raw.Close()
			return
		}
	}
	held := true
	defer func() {
		if held {
			s.admit.release(raw.RemoteAddr())
		}
	}()
	if morphing {
		raw = morph.WrapTCPServer(raw, *s.keys)
	}
	tlsConn := tls.Server(raw, s.tls)
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		// A rejected prelude or ClientHello is not drained: the Morph reader
		// stops returning socket bytes once admission fails. The slot is released
		// before the hold, because the connection will not authenticate. The
		// socket itself stays open until the deadline captured at accept.
		// crypto/tls does not preserve the admission error, so every Morph
		// failure before a TLS response takes this path.
		if morphing {
			s.admit.release(raw.RemoteAddr())
			held = false
			parkUntil(deadline)
		}
		_ = tlsConn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	exp, err := exportState(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthTLS, exp)
	s.admit.release(raw.RemoteAddr())
	held = false
	if err != nil || role != wire.RoleVector {
		_ = tlsConn.Close()
		return
	}
	if morphing {
		if err := morph.ReleaseAuthenticated(raw, deadline); err != nil {
			_ = tlsConn.Close()
			return
		}
	}
	_ = tlsConn.SetDeadline(time.Now().Add(flowSetupLimit))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	rw := &pipe{Reader: br, write: tlsConn, closer: tlsConn}
	if err != nil || !ok {
		if ok || err != nil {
			_ = wire.WriteSetupResult(tlsConn, wire.SetupInvalidRequest)
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	s.serveFlow(ctx, kind, target, rw, nil, 0, true)
}

func (s *Server) serveQUIC(ctx context.Context, conn qio.Conn) {
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return
	}
	if !s.admit.take(conn.RemoteAddr()) {
		return
	}
	dropCtx, cancelDrop := context.WithCancel(ctx)
	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		for {
			if _, err := conn.ReceiveDatagram(dropCtx); err != nil {
				return
			}
		}
	}()
	authCtx, cancelAuth := context.WithTimeout(ctx, authBudget())
	st, err := conn.AcceptStream(authCtx)
	cancelAuth()
	if err != nil || st.ID() != 0 {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	exp, err := exportConn(conn)
	if err != nil {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	_ = st.SetDeadline(time.Now().Add(authBudget()))
	br := bufio.NewReader(st)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthQUIC, exp)
	s.admit.release(conn.RemoteAddr())
	cancelDrop()
	<-dropDone
	if err != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	router := dgram.NewRouter(conn)
	go router.Run(ctx)
	switch role {
	case wire.RoleVector:
		s.serveVectorConn(ctx, conn, router, st, br)
	case wire.RoleEgress:
		s.serveEgressConn(ctx, conn, router, st, br)
	default:
	}
}

func (s *Server) serveVectorConn(ctx context.Context, conn qio.Conn, router *dgram.Router, first qio.Stream, br *bufio.Reader) {
	go s.readAndServe(ctx, router, first, br, true)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if st.ID()&2 != 0 || st.ID()&1 != 0 {
			_ = conn.CloseWithError(0, "direction")
			return
		}
		go s.readAndServe(ctx, router, st, bufio.NewReader(st), true)
	}
}

func (s *Server) readAndServe(ctx context.Context, router *dgram.Router, st qio.Stream, br *bufio.Reader, client bool) {
	_ = st.SetReadDeadline(time.Now().Add(flowSetupLimit))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil || !ok {
		if err != nil {
			_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		}
		_ = st.CloseWrite()
		return
	}
	rw := &pipe{Reader: br, write: st, closer: st}
	s.serveFlow(ctx, kind, target, rw, router, st.ID(), client)
}

func (s *Server) serveFlow(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64, clientInitiated bool) {
	if !s.flows.acquire() {
		_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
		_ = client.Close()
		return
	}
	defer s.flows.release()
	setupCtx, cancel := context.WithTimeout(ctx, flowSetupLimit)
	defer cancel()
	if s.egress {
		s.serveViaEgress(setupCtx, kind, target, client, router, streamID)
		return
	}
	var peer net.Conn
	var err error
	if kind == wire.FlowTCP {
		peer, err = s.up.DialTCP(setupCtx, target)
	} else {
		peer, err = s.up.DialUDP(setupCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer peer.Close()
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	if router == nil {
		relayUoT(client, peer, s.upload, s.download)
		return
	}
	id, err := wire.UDPFlowID(streamID, !clientInitiated)
	if err != nil {
		return
	}
	relayQUICUDP(router, id, client, peer, s.upload, s.download)
}

func (s *Server) serveViaEgress(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	owner := s.currentOwner()
	if owner == nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	st, err := owner.conn.OpenStream(ctx)
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer st.Close()
	if err := wire.WriteFlowRequest(st, kind, target); err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(flowSetupLimit))
	res, err := wire.ReadSetupResult(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		res = wire.SetupDialFailed
	}
	if res != wire.SetupReady {
		_ = wire.WriteSetupResult(client, res)
		_ = client.Close()
		return
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		peer := &pipe{Reader: st, write: st, closer: st}
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	vid, err := wire.UDPFlowID(streamID, false)
	if err != nil {
		return
	}
	eid, err := wire.UDPFlowID(st.ID(), true)
	if err != nil {
		return
	}
	bridgeUDP(router, vid, client, owner.router, eid, &pipe{Reader: st, write: st, closer: st})
}

func (s *Server) serveEgressConn(ctx context.Context, conn qio.Conn, router *dgram.Router, st qio.Stream, br *bufio.Reader) {
	if !s.egress {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(time.Second))
	var extra [1]byte
	if n, err := br.Read(extra[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return
	}
	s.mu.Lock()
	busy := s.owner != nil
	if !busy {
		s.owner = &egressOwner{conn: conn, router: router}
	}
	s.mu.Unlock()
	if busy {
		_ = wire.WriteRegistrationResult(st, wire.RegistrationBusy)
		_ = st.CloseWrite()
		select {
		case <-ctx.Done():
		case <-conn.Context().Done():
		}
		return
	}
	if err := wire.WriteRegistrationResult(st, wire.RegistrationAccepted); err != nil {
		s.clearOwner(conn)
		return
	}
	_ = st.CloseWrite()
	defer s.clearOwner(conn)
	stray, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = stray.Close()
	_ = conn.CloseWithError(0, "direction")
}

func (s *Server) currentOwner() *egressOwner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner
}

func (s *Server) clearOwner(conn qio.Conn) {
	s.mu.Lock()
	if s.owner != nil && s.owner.conn == conn {
		s.owner = nil
	}
	s.mu.Unlock()
}

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}
func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if cw, ok := p.closer.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Close()
}

func relayUoT(client *pipe, udp net.Conn, up, down *flowio.Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				break
			}
		}
		_ = udp.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := udp.Read(buf)
			if err != nil {
				break
			}
			_ = down.WaitN(context.Background(), n)
			if err := wire.WriteUoT(client, buf[:n]); err != nil {
				break
			}
		}
		_ = client.CloseWrite()
	}()
	wg.Wait()
}

func relayQUICUDP(router *dgram.Router, id uint32, client *pipe, udp net.Conn, up, down *flowio.Limiter) {
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := udp.Read(buf)
			if err != nil {
				finish()
				return
			}
			_ = down.WaitN(context.Background(), n)
			if err := router.Send(id, buf[:n]); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			wg.Wait()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				wg.Wait()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				finish()
				wg.Wait()
				return
			}
		}
	}
}

func bridgeUDP(from *dgram.Router, fromID uint32, fromCtl *pipe, to *dgram.Router, toID uint32, toCtl *pipe) {
	left := from.Register(fromID)
	right := to.Register(toID)
	defer from.CloseFlow(fromID)
	defer to.CloseFlow(toID)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = fromCtl.Read(b[:])
		finish()
	}()
	go func() {
		var b [1]byte
		_, _ = toCtl.Read(b[:])
		finish()
	}()
	for {
		select {
		case <-done:
			return
		case pkt := <-left.C:
			_ = to.Send(toID, pkt)
		case pkt := <-right.C:
			_ = from.Send(fromID, pkt)
		}
	}
}

func exportState(state tls.ConnectionState) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func exportConn(conn qio.Conn) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := conn.Exporter()
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func authBudget() time.Duration {
	var b [2]byte
	_, _ = rand.Read(b[:])
	span := binary.BigEndian.Uint16(b[:]) % 2001
	return 4*time.Second + time.Duration(span)*time.Millisecond
}

type admit struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
	per  map[string]int
}

func (a *admit) take(addr net.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.takeLocked(sourceKey(addr))
}

func (a *admit) takeLocked(key string) bool {
	if a.n >= maxUnauth || a.per[key] >= maxPerSource {
		return false
	}
	a.n++
	a.per[key]++
	return true
}

// wait blocks until a slot is taken, ctx ends, or deadline passes. The
// capacity check and the wait share one lock, so a release cannot pass
// unnoticed between them. It is used only for Morph TCP.
func (a *admit) wait(ctx context.Context, addr net.Addr, deadline time.Time) bool {
	a.mu.Lock()
	if a.cond == nil {
		a.cond = sync.NewCond(&a.mu)
	}
	key := sourceKey(addr)
	timer := time.NewTimer(time.Until(deadline))
	stop := make(chan struct{})
	defer func() {
		timer.Stop()
		close(stop)
	}()
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	}()
	for {
		if a.takeLocked(key) {
			a.mu.Unlock()
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			a.mu.Unlock()
			return false
		}
		a.cond.Wait()
	}
}

func (a *admit) release(addr net.Addr) {
	key := sourceKey(addr)
	a.mu.Lock()
	if a.n > 0 {
		a.n--
	}
	if a.per[key] > 0 {
		a.per[key]--
	}
	if a.cond != nil {
		a.cond.Broadcast()
	}
	a.mu.Unlock()
}

func setZeroLinger(conn net.Conn) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(0)
	}
	return nil
}

func parkUntil(deadline time.Time) {
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
}

func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return host
	}
	return hex.EncodeToString(v6[:8])
}

type gate struct {
	mu sync.Mutex
	n  int
}

func (g *gate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n >= maxFlows {
		return false
	}
	g.n++
	return true
}

func (g *gate) release() {
	g.mu.Lock()
	if g.n > 0 {
		g.n--
	}
	g.mu.Unlock()
}
