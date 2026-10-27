package urltest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

const (
	DefaultUDPTestServer = "1.1.1.1:53"
	DefaultUDPTestDomain = "www.gstatic.com"

	// udpTestRetransmit resends the query, so one lost datagram does not
	// fail the probe.
	udpTestRetransmit = time.Second
)

// UDPTest sends a DNS query over UDP through detour and waits for the answer,
// proving that the outbound really relays UDP. The delay covers setting up the
// packet connection and the first matching response. ctx bounds the probe.
func UDPTest(ctx context.Context, detour N.Dialer, server M.Socksaddr, domain string) (uint16, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return 0, E.New("UDP test requires a timeout")
	}
	start := time.Now()
	conn, err := detour.ListenPacket(ctx, server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	query := new(mDNS.Msg)
	query.SetQuestion(mDNS.Fqdn(domain), mDNS.TypeA)
	query.Id = binary.BigEndian.Uint16(idBytes[:])
	packet, err := query.Pack()
	if err != nil {
		return 0, err
	}
	// Plain net.PacketConn implementations only take *net.UDPAddr; sing-box
	// outbounds also take M.Socksaddr, which can carry a domain.
	var destination net.Addr = server
	if server.IsIP() {
		destination = server.UDPAddr()
	}
	buffer := make([]byte, 4096)
	for {
		_, err = conn.WriteTo(packet, destination)
		if err != nil {
			return 0, E.Cause(err, "write query")
		}
		resend := time.Now().Add(udpTestRetransmit)
		for {
			deadline, _ := ctx.Deadline()
			if resend.Before(deadline) {
				deadline = resend
			}
			_ = conn.SetReadDeadline(deadline)
			n, _, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if ctx.Err() != nil {
					return 0, E.New("no UDP response from ", server, " within the timeout")
				}
				if errors.Is(readErr, os.ErrDeadlineExceeded) {
					break
				}
				var netErr net.Error
				if errors.As(readErr, &netErr) && netErr.Timeout() {
					break
				}
				return 0, E.Cause(readErr, "read response")
			}
			var response mDNS.Msg
			if response.Unpack(buffer[:n]) != nil || response.Id != query.Id || !response.Response {
				// stray datagram, keep waiting
				continue
			}
			delay := time.Since(start) / time.Millisecond
			if delay == 0 {
				delay = 1
			}
			return uint16(min(delay, 65535)), nil
		}
	}
}

// UDPUnavailable reports whether the latest UDP probe of tag failed and is
// still valid. Outbounds never probed, or whose result expired, are not
// unavailable: their declared network decides.
func UDPUnavailable(history adapter.URLTestHistoryStorage, tag string) bool {
	if history == nil || tag == "" {
		return false
	}
	udpHistory, isUDP := history.(adapter.UDPTestHistoryStorage)
	if !isUDP {
		return false
	}
	return udpHistory.LoadUDPTestHistory(tag).Failed(time.Now())
}
