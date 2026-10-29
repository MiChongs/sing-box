// Package egress is the Nowhere 3 exit client. It dials Portal over QUIC with
// ALPN nw3, registers, and only then dials targets for Portal-opened streams.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/dgram"
	"github.com/sagernet/sing-box/protocol/nowhere/core/flowio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	dialTimeout = 15 * time.Second
	udpIdle     = 120 * time.Second
)

// Config is one Egress process.
type Config struct {
	SharedKey string
	DialQUIC  func(ctx context.Context) (qio.Conn, error)
	Upstream  interface {
		DialTCP(ctx context.Context, target wire.Target) (net.Conn, error)
		DialUDP(ctx context.Context, target wire.Target) (net.Conn, error)
	}
	UploadMbps   int
	DownloadMbps int
}

// ErrBusy is returned when Portal already has an Egress owner.
var ErrBusy = errors.New("nw3: egress registration busy")

// Run registers with Portal and serves flows until ctx ends or the connection drops.
func Run(ctx context.Context, cfg Config) error {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return err
	}
	if cfg.DialQUIC == nil || cfg.Upstream == nil {
		return errors.New("nw3: egress requires QUIC and an upstream")
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return err
	}
	conn, err := cfg.DialQUIC(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return errors.New("nw3: QUIC handshake rejected")
	}
	st, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	if st.ID() != 0 {
		return errors.New("nw3: authentication stream was not stream 0")
	}
	exp, err := exporter(conn)
	if err != nil {
		return err
	}
	if err := wire.WriteAuthFrame(st, creds, wire.RoleEgress, wire.AuthQUIC, exp); err != nil {
		return err
	}
	if err := st.CloseWrite(); err != nil {
		return err
	}
	res, err := wire.ReadRegistrationResult(st)
	if err != nil {
		return err
	}
	if res == wire.RegistrationBusy {
		return ErrBusy
	}
	if res != wire.RegistrationAccepted {
		return errors.New("nw3: invalid registration result")
	}
	router := dgram.NewRouter(conn)
	go router.Run(ctx)
	up := flowio.NewMbps(cfg.UploadMbps)
	down := flowio.NewMbps(cfg.DownloadMbps)
	for {
		flow, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if flow.ID()&2 != 0 || flow.ID()&1 == 0 {
			_ = conn.CloseWithError(0, "direction")
			return errors.New("nw3: invalid business stream direction")
		}
		go serveFlow(ctx, cfg, router, flow, up, down)
	}
}

func serveFlow(ctx context.Context, cfg Config, router *dgram.Router, st qio.Stream, up, down *flowio.Limiter) {
	defer st.Close()
	br := bufio.NewReader(st)
	kind, target, ok, err := wire.ReadFlowRequest(br)
	if err != nil || !ok {
		_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var peer net.Conn
	if kind == wire.FlowTCP {
		peer, err = cfg.Upstream.DialTCP(dialCtx, target)
	} else {
		peer, err = cfg.Upstream.DialUDP(dialCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(st, wire.SetupDialFailed)
		return
	}
	defer peer.Close()
	if err := wire.WriteSetupResult(st, wire.SetupReady); err != nil {
		return
	}
	client := &pipe{Reader: br, write: st, closer: st}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, up, down)
		return
	}
	id, err := wire.UDPFlowID(st.ID(), true)
	if err != nil {
		return
	}
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = br.Read(b[:])
		finish()
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := peer.Read(buf)
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
			return
		case pkt := <-flow.C:
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := peer.Write(pkt); err != nil {
				finish()
				return
			}
		}
	}
}

func exporter(conn qio.Conn) (wire.Exporter, error) {
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

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error                { return p.closer.Close() }
func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Close()
}
