package listener

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/proxyproto"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/database64128/tfo-go/v2"
)

func (l *Listener) ListenTCP() (net.Listener, error) {
	if l.listenOptions.IsPath() {
		return l.listenUnix()
	}
	var err error
	bindAddr := M.SocksaddrFrom(l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), l.listenOptions.ListenPort)
	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, l.socketControl)
	if l.listenOptions.BindInterface != "" {
		listenConfig.Control = control.Append(listenConfig.Control, control.BindToInterface(service.FromContext[adapter.NetworkManager](l.ctx).InterfaceFinder(), l.listenOptions.BindInterface, -1))
	}
	if l.listenOptions.RoutingMark != 0 {
		listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
	}
	if l.listenOptions.ReuseAddr {
		listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	}
	if l.listenOptions.DisableTCPKeepAlive {
		listenConfig.KeepAlive = -1
		listenConfig.KeepAliveConfig.Enable = false
	} else {
		keepIdle := time.Duration(l.listenOptions.TCPKeepAlive)
		if keepIdle == 0 {
			keepIdle = C.TCPKeepAliveInitial
		}
		keepInterval := time.Duration(l.listenOptions.TCPKeepAliveInterval)
		if keepInterval == 0 {
			keepInterval = C.TCPKeepAliveInterval
		}
		keepCount := max(l.listenOptions.TCPKeepAliveCount, 0)
		listenConfig.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepIdle,
			Interval: keepInterval,
			Count:    keepCount,
		}
	}
	if l.listenOptions.TCPMultiPath {
		listenConfig.SetMultipathTCP(true)
	}
	if l.tproxy {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return redir.TProxy(fd, !strings.HasSuffix(network, "4"), false)
			})
		})
	}
	tcpListener, err := ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		if l.listenOptions.TCPFastOpen {
			var tfoConfig tfo.ListenConfig
			tfoConfig.ListenConfig = listenConfig
			return tfoConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		} else {
			return listenConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		}
	})
	if err != nil {
		return nil, err
	}
	if l.listenOptions.ProxyProtocol {
		tcpListener = &proxyproto.Listener{Listener: tcpListener, AcceptNoHeader: l.listenOptions.ProxyProtocolAcceptNoHeader}
	}
	if !l.disableLog {
		l.logger.Info("tcp server started at ", tcpListener.Addr())
	}
	l.tcpListener = tcpListener
	return tcpListener, err
}

func (l *Listener) listenUnix() (net.Listener, error) {
	socketPath := l.listenOptions.ListenPath
	_ = os.Remove(socketPath)
	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, l.socketControl)
	unixListener, err := ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		return listenConfig.Listen(l.ctx, "unix", socketPath)
	})
	if err != nil {
		return nil, err
	}
	mode := l.listenOptions.ListenPathMode
	if mode == 0 {
		mode = 0660
	}
	_ = os.Chmod(socketPath, mode)
	if l.listenOptions.ProxyProtocol {
		unixListener = &proxyproto.Listener{Listener: unixListener, AcceptNoHeader: l.listenOptions.ProxyProtocolAcceptNoHeader}
	}
	if !l.disableLog {
		l.logger.Info("unix socket server started at ", socketPath)
	}
	l.tcpListener = unixListener
	return unixListener, nil
}

func (l *Listener) loopTCPIn() {
	tcpListener := l.tcpListener
	var (
		metadata    adapter.InboundContext
		acceptDelay time.Duration
	)
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay = min(2*acceptDelay, time.Second)
				}
				l.logger.Error(err, ", retrying in ", acceptDelay)
				time.Sleep(acceptDelay)
				continue
			}
			l.tcpListener.Close()
			l.logger.Error("tcp listener closed: ", err)
			return
		}
		acceptDelay = 0
		//nolint:staticcheck
		metadata.InboundDetour = l.listenOptions.Detour

		remoteAddr := conn.RemoteAddr()
		if remoteAddr != nil && remoteAddr.Network() == "unix" {
			metadata.Source = M.SocksaddrFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
		} else if remoteAddr != nil {
			metadata.Source = M.SocksaddrFromNet(remoteAddr).Unwrap()
		}

		localAddr := conn.LocalAddr()
		if localAddr != nil && localAddr.Network() == "unix" {
			metadata.OriginDestination = M.SocksaddrFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), l.listenOptions.ListenPort)
		} else if localAddr != nil {
			metadata.OriginDestination = M.SocksaddrFromNet(localAddr).Unwrap()
		}
		metadata.Destination = metadata.OriginDestination

		ctx := log.ContextWithNewID(l.ctx)
		if !l.disableLog {
			l.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
		}
		go l.connHandler.NewConnection(ctx, conn, metadata, nil)
	}
}
