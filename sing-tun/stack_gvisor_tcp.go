//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TCPForwarder struct {
	ctx                     context.Context
	stack                   *stack.Stack
	handler                 Handler
	inet4LoopbackAddress    []tcpip.Address
	inet6LoopbackAddress    []tcpip.Address
	inet4LoopbackAddressSet map[tcpip.Address]struct{}
	inet6LoopbackAddressSet map[tcpip.Address]struct{}
	tun                     GVisorTun
	forwarder               *tcp.Forwarder
}

func NewTCPForwarder(ctx context.Context, stack *stack.Stack, handler Handler) *TCPForwarder {
	return NewTCPForwarderWithLoopback(ctx, stack, handler, nil, nil, nil)
}

func NewTCPForwarderWithLoopback(ctx context.Context, stack *stack.Stack, handler Handler, inet4LoopbackAddress []netip.Addr, inet6LoopbackAddress []netip.Addr, tun GVisorTun) *TCPForwarder {
	inet4Addrs := common.Map(inet4LoopbackAddress, AddressFromAddr)
	inet6Addrs := common.Map(inet6LoopbackAddress, AddressFromAddr)
	inet4Set := make(map[tcpip.Address]struct{}, len(inet4Addrs))
	for _, a := range inet4Addrs {
		inet4Set[a] = struct{}{}
	}
	inet6Set := make(map[tcpip.Address]struct{}, len(inet6Addrs))
	for _, a := range inet6Addrs {
		inet6Set[a] = struct{}{}
	}
	forwarder := &TCPForwarder{
		ctx:                     ctx,
		stack:                   stack,
		handler:                 handler,
		inet4LoopbackAddress:    inet4Addrs,
		inet6LoopbackAddress:    inet6Addrs,
		inet4LoopbackAddressSet: inet4Set,
		inet6LoopbackAddressSet: inet6Set,
		tun:                     tun,
	}
	forwarder.forwarder = tcp.NewForwarder(stack, 0, 4096, forwarder.Forward)
	return forwarder
}

func (f *TCPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if _, ok := f.inet4LoopbackAddressSet[id.LocalAddress]; ok {
		ipHdr := pkt.Network().(header.IPv4)
		ipHdr.SetDestinationAddressWithChecksumUpdate(ipHdr.SourceAddress())
		ipHdr.SetSourceAddressWithChecksumUpdate(id.LocalAddress)
		tcpHdr := header.TCP(pkt.TransportHeader().Slice())
		tcpHdr.SetChecksum(0)
		tcpHdr.SetChecksum(^checksum.Combine(pkt.Data().Checksum(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
		)))
		f.tun.WritePacket(pkt)
		return true
	}
	if _, ok := f.inet6LoopbackAddressSet[id.LocalAddress]; ok {
		ipHdr := pkt.Network().(header.IPv6)
		ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
		ipHdr.SetSourceAddress(id.LocalAddress)
		tcpHdr := header.TCP(pkt.TransportHeader().Slice())
		tcpHdr.SetChecksum(0)
		tcpHdr.SetChecksum(^checksum.Combine(pkt.Data().Checksum(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
		)))
		f.tun.WritePacket(pkt)
		return true
	}
	return f.forwarder.HandlePacket(id, pkt)
}

func (f *TCPForwarder) Forward(r *tcp.ForwarderRequest) {
	source := M.SocksaddrFrom(AddrFromAddress(r.ID().RemoteAddress), r.ID().RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(r.ID().LocalAddress), r.ID().LocalPort)
	_, pErr := f.handler.PrepareConnection(N.NetworkTCP, source, destination, nil, 0)
	if pErr != nil {
		r.Complete(!errors.Is(pErr, ErrDrop))
		return
	}
	conn := &gLazyConn{
		parentCtx:  f.ctx,
		stack:      f.stack,
		request:    r,
		localAddr:  source.TCPAddr(),
		remoteAddr: destination.TCPAddr(),
	}
	go f.handler.NewConnectionEx(f.ctx, conn, source, destination, nil)
}
