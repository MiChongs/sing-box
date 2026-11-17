package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/kernelports"
	"github.com/sagernet/sing-box/common/wgtun"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

var _ Device = (*systemDevice)(nil)

type systemDevice struct {
	options      DeviceOptions
	dialer       N.Dialer
	device       tun.Tun
	ports        atomic.Pointer[kernelports.Pool]
	batchDevice  tun.LinuxTUN
	reader       *wgtun.Reader
	events       chan wgTun.Event
	closeOnce    sync.Once
	inet4Address netip.Addr
	inet6Address netip.Addr
}

func newSystemDevice(options DeviceOptions) (*systemDevice, error) {
	if options.Name == "" {
		options.Name = tun.CalculateInterfaceName("wg")
	}
	inet4Address, inet6Address := deviceAddresses(options.Address)
	return &systemDevice{
		options:      options,
		dialer:       options.CreateDialer(options.Name),
		events:       make(chan wgTun.Event, 1),
		inet4Address: inet4Address,
		inet6Address: inet6Address,
	}, nil
}

func (w *systemDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return w.dialer.DialContext(ctx, network, destination)
}

func (w *systemDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return w.dialer.ListenPacket(ctx, destination)
}

func (w *systemDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *systemDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *systemDevice) SetDevice(device *device.Device, peers []*device.Peer) {
}

func (w *systemDevice) UpstreamPort() any {
	ports := w.ports.Load()
	if ports == nil {
		return nil
	}
	return ports
}

func (w *systemDevice) Start() error {
	networkManager := service.FromContext[adapter.NetworkManager](w.options.Context)
	tunOptions := tun.Options{
		Name: w.options.Name,
		Inet4Address: common.Filter(w.options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6Address: common.Filter(w.options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}),
		MTU:            w.options.MTU,
		GSO:            w.options.GSO,
		InterfaceScope: true,
		DNSMode:        tun.DNSModeDisabled,
		Inet4RouteAddress: common.Filter(w.options.AllowedAddress, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6RouteAddress: common.Filter(w.options.AllowedAddress, func(it netip.Prefix) bool { return it.Addr().Is6() }),
		InterfaceMonitor:  networkManager.InterfaceMonitor(),
		InterfaceFinder:   networkManager.InterfaceFinder(),
		Logger:            w.options.Logger,
	}
	// works with Linux, macOS with IFSCOPE routes, not tested on Windows
	if runtime.GOOS == "darwin" {
		tunOptions.AutoRoute = true
	}
	tunInterface, err := tun.New(tunOptions)
	if err != nil {
		return err
	}
	err = tunInterface.Start()
	if err != nil {
		tunInterface.Close()
		return err
	}
	ports, err := kernelports.New()
	if err != nil {
		w.options.Logger.Warn(E.Cause(err, "reserve selector ports"))
	} else {
		w.ports.Store(ports)
	}
	w.options.Logger.Info("started at ", w.options.Name)
	w.device = tunInterface
	w.reader = wgtun.NewReader(tunInterface, int(w.options.MTU))
	if w.reader.Batch() {
		w.batchDevice = tunInterface.(tun.LinuxTUN)
	}
	w.events <- wgTun.EventUp
	return nil
}

func (w *systemDevice) File() *os.File {
	return nil
}

func (w *systemDevice) Read(slab []byte, packets []wgTun.ReadPacket) (int, error) {
	return w.reader.Read(slab, packets)
}

func (w *systemDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	if w.batchDevice != nil {
		return w.batchDevice.BatchWrite(bufs, offset)
	} else {
		for _, packet := range bufs {
			if tun.PacketOffset > 0 {
				clear(packet[offset-tun.PacketOffset : offset])
				tun.PacketFillHeader(packet[offset-tun.PacketOffset:], tun.PacketIPVersion(packet[offset:]))
			}
			_, err = w.device.Write(packet[offset-tun.PacketOffset:])
			if err != nil {
				return
			}
		}
	}
	// WireGuard will not read count
	return
}

func (w *systemDevice) Flush() error {
	return nil
}

func (w *systemDevice) MTU() (int, error) {
	return int(w.options.MTU), nil
}

func (w *systemDevice) Name() (string, error) {
	return w.options.Name, nil
}

func (w *systemDevice) Events() <-chan wgTun.Event {
	return w.events
}

func (w *systemDevice) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.events)
		if w.device != nil {
			err = w.device.Close()
		}
		ports := w.ports.Load()
		if ports != nil {
			err = E.Errors(err, ports.Close())
		}
	})
	return err
}

func (w *systemDevice) BatchSize() int {
	if w.batchDevice != nil {
		return w.batchDevice.BatchSize()
	}
	return 1
}
