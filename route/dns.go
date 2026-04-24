package route

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"

	mDNS "github.com/miekg/dns"
)

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	metadata.Destination = M.Socksaddr{}
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err := dnsOutbound.HandleStreamDNSRequest(ctx, r.dns, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if natConn, isNatConn := conn.(udpnat.Conn); isNatConn {
		metadata.Destination = M.Socksaddr{}
		for _, packet := range packetBuffers {
			buffer := packet.Buffer
			destination := packet.Destination
			N.PutPacketBuffer(packet)
			go ExchangeDNSPacket(ctx, r.dns, r.logger, r.network, natConn, buffer, metadata, destination)
		}
		natConn.SetHandler(&dnsHijacker{
			router:         r.dns,
			logger:         r.logger,
			networkManager: r.network,
			conn:           conn,
			ctx:            ctx,
			metadata:       metadata,
			onClose:        onClose,
		})
		return nil
	}
	err := dnsOutbound.NewDNSPacketConnection(ctx, r.dns, conn, packetBuffers, metadata)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		// 瞬态不可达：让 monitor 立刻重探；错误仍返回上层（TCP 路径由 caller
		// 决定是否重试 / 静默）。这里不直接打日志，上层只有一个 return 点。
		if isTransientUnreachable(err) && r.network != nil {
			r.network.HintUnreachable()
		}
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

func ExchangeDNSPacket(ctx context.Context, router adapter.DNSRouter, logger logger.ContextLogger, networkManager adapter.NetworkManager, conn N.PacketConn, buffer *buf.Buffer, metadata adapter.InboundContext, destination M.Socksaddr) {
	err := exchangeDNSPacket(ctx, router, conn, buffer, metadata, destination)
	if err == nil || R.IsRejected(err) || E.IsClosedOrCanceled(err) {
		return
	}
	// 切网瞬态错误：反馈 monitor + 降级 Debug + per-second 节流，避免刷屏。
	if isTransientUnreachable(err) {
		if networkManager != nil {
			networkManager.HintUnreachable()
		}
		if transientDNSLogThrottle.allow() {
			logger.DebugContext(ctx, E.Cause(err, "process DNS packet (transient, auto-retry)"))
		}
		return
	}
	logger.ErrorContext(ctx, E.Cause(err, "process DNS packet"))
}

func exchangeDNSPacket(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, buffer *buf.Buffer, metadata adapter.InboundContext, destination M.Socksaddr) error {
	var message mDNS.Msg
	err := message.Unpack(buffer.Bytes())
	buffer.Release()
	if err != nil {
		return E.Cause(err, "unpack request")
	}
	response, err := router.Exchange(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{})
	if err != nil {
		return err
	}
	responseBuffer, err := dns.TruncateDNSMessage(&message, response, 1024)
	if err != nil {
		return err
	}
	err = conn.WritePacket(responseBuffer, destination)
	return err
}

type dnsHijacker struct {
	router         adapter.DNSRouter
	logger         logger.ContextLogger
	networkManager adapter.NetworkManager
	conn           N.PacketConn
	ctx            context.Context
	metadata       adapter.InboundContext
	onClose        N.CloseHandlerFunc
}

func (h *dnsHijacker) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	go ExchangeDNSPacket(h.ctx, h.router, h.logger, h.networkManager, h.conn, buffer, h.metadata, destination)
}

func (h *dnsHijacker) Close() error {
	if h.onClose != nil {
		h.onClose(nil)
	}
	return nil
}
