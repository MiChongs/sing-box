//go:build with_ebpf && (linux || android)

package dialer

import (
	"net"
	"runtime"
	"sync"
	"syscall"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// bindEBPFSelfBypassConnLifecycle pairs userspace socket registration with the
// returned connection's Close method. Kernel sock_release cleanup remains the
// fast path when available; this closes the gap on kernels where only the
// userspace registration fallback can be used.
func bindEBPFSelfBypassConnLifecycle(networkManager adapter.NetworkManager, conn net.Conn) net.Conn {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return conn
	}
	tracker := provider.EBPFSelfBypass()
	if tracker.CleanupMode() != "lru_fallback" {
		return conn
	}
	if lazyConn, loaded := conn.(*slowOpenConn); loaded {
		lazyConn.setCloseHandler(func(tcpConn *net.TCPConn) {
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				_ = tracker.UnregisterSocket(rawConn)
			}
		})
		return conn
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	return &selfBypassConn{Conn: conn, cleanup: EBPFSelfBypassCleanup(networkManager, rawConn), rawConn: rawConn}
}

func bindEBPFSelfBypassPacketConnLifecycle(networkManager adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return conn
	}
	tracker := provider.EBPFSelfBypass()
	if tracker.CleanupMode() != "lru_fallback" {
		return conn
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	return &selfBypassPacketConn{PacketConn: conn, cleanup: EBPFSelfBypassCleanup(networkManager, rawConn), rawConn: rawConn}
}

type selfBypassConn struct {
	net.Conn
	cleanup   func()
	rawConn   syscall.RawConn
	closeOnce sync.Once
	closeErr  error
}

func (c *selfBypassConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cleanup != nil {
			c.cleanup()
		}
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *selfBypassConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

// Only I/O may unwrap this adapter. The original owner must still close the
// wrapper to unregister the cookie before the socket FD is released.
func (c *selfBypassConn) Upstream() any           { return c.Conn }
func (c *selfBypassConn) ReaderReplaceable() bool { return true }
func (c *selfBypassConn) WriterReplaceable() bool { return true }

type selfBypassPacketConn struct {
	net.PacketConn
	cleanup   func()
	rawConn   syscall.RawConn
	closeOnce sync.Once
	closeErr  error
}

func (c *selfBypassPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cleanup != nil {
			c.cleanup()
		}
		c.closeErr = c.PacketConn.Close()
	})
	return c.closeErr
}

func (c *selfBypassPacketConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

func (c *selfBypassPacketConn) Upstream() any           { return c.PacketConn }
func (c *selfBypassPacketConn) ReaderReplaceable() bool { return true }
func (c *selfBypassPacketConn) WriterReplaceable() bool { return true }

// EBPFSelfBypassCleanup returns an idempotent cleanup callback for a socket
// registered by AppendEBPFSelfBypass. External socket owners should invoke it
// immediately before closing the socket when the runtime has no kernel release
// hook, such as Tailscale's custom packet listener path.
func EBPFSelfBypassCleanup(networkManager adapter.NetworkManager, rawConn syscall.RawConn) func() {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return nil
	}
	tracker := provider.EBPFSelfBypass()
	if tracker == nil || tracker.CleanupMode() != "lru_fallback" {
		return nil
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = tracker.UnregisterSocket(rawConn) })
	}
}

func PrepareEBPFSelfBypass(networkManager adapter.NetworkManager, inbounds []option.Inbound) error {
	localInstances := 0
	localSocketAssign := false
	for _, inbound := range inbounds {
		switch inbound.Type {
		case C.TypeEBPF:
			ebpfOptions, loaded := inbound.Options.(*option.EBPFInboundOptions)
			if !loaded {
				return E.New("invalid eBPF inbound options")
			}
			localEnabled, _ := ebpfOptions.EffectiveEnablement()
			if localEnabled {
				localInstances++
				localSocketAssign = ebpfOptions.Local.DataPlane == "socket_assign"
			}
		}
	}
	if localInstances > 1 {
		return E.New("only one local or hybrid eBPF inbound is supported")
	}
	if localInstances == 0 {
		return nil
	}
	var tracker *commonEBPF.SelfBypass
	var err error
	if runtime.GOOS == "android" {
		tracker, err = commonEBPF.NewSelfBypassWithCapacity(commonEBPF.CompactSelfBypassSocketCapacity)
	} else {
		tracker, err = commonEBPF.NewSelfBypass()
	}
	if err != nil {
		return err
	}
	setter, loaded := networkManager.(interface {
		SetEBPFSelfBypass(*commonEBPF.SelfBypass) error
	})
	if !loaded {
		_ = tracker.Close()
		return E.New("network manager does not support eBPF self-bypass sockets")
	}
	if err = setter.SetEBPFSelfBypass(tracker); err != nil {
		_ = tracker.Close()
		return err
	}
	if localSocketAssign {
		if setter, loaded := networkManager.(interface{ SetEBPFLocalSocketAssign(bool) }); loaded {
			setter.SetEBPFLocalSocketAssign(true)
		}
	}
	return nil
}

// appendEBPFOutboundPortReservation makes an outbound TCP socket take its
// source port at bind time when local socket assignment is active.
//
// Socket assignment keeps every intercepted local socket's original tuple, and
// a direct outbound for it connects from the same address to the same
// destination. When the outbound is bound to an interface (auto-detected or
// configured), the kernel's connect-time uniqueness check does not treat it
// and an unbound application socket as the same tuple, so an application may
// connect from the port a live outbound uses. Both sockets then share one
// tuple and the host delivers either peer's segments to the wrong one, which
// stalls that connection until a SYN retransmission. A port taken by bind()
// is skipped by every connect-time port selection. SO_REUSEADDR lets bind fall
// back to ports held only by TIME_WAIT outbound sockets once nothing else is
// free; the first pass still prefers unused ports.
func appendEBPFOutboundPortReservation(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface{ EBPFLocalSocketAssign() bool })
	if !loaded || !provider.EBPFLocalSocketAssign() {
		return controlFunc
	}
	return control.Append(controlFunc, reserveEBPFOutboundPort)
}

func reserveEBPFOutboundPort(network, _ string, conn syscall.RawConn) error {
	var sockaddr unix.Sockaddr
	switch network {
	case "tcp4":
		sockaddr = &unix.SockaddrInet4{}
	case "tcp6":
		sockaddr = &unix.SockaddrInet6{}
	default:
		return nil
	}
	return control.Raw(conn, func(fd uintptr) error {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return E.Cause(err, "reserve eBPF outbound port")
		}
		if err := unix.Bind(int(fd), sockaddr); err != nil {
			return E.Cause(err, "reserve eBPF outbound port")
		}
		return nil
	})
}

// AppendEBPFSelfBypass appends the eBPF self-bypass registration callback to a
// socket control chain. It is also used by integrations that create sockets
// outside DefaultDialer, such as endpoint-specific network stacks.
func AppendEBPFSelfBypass(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return controlFunc
	}
	tracker := provider.EBPFSelfBypass()
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		return tracker.RegisterSocket(rawConn)
	}
	return control.Append(controlFunc, selfBypassFunc)
}

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return AppendEBPFSelfBypass(networkManager, dialerControl), AppendEBPFSelfBypass(networkManager, listenerControl)
}
