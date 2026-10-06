//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (i *Inbound) selectRedirectPrefixes() error {
	var err error
	i.redirectIPv4Prefix, err = commonEBPF.SelectRedirectPrefix(
		unix.AF_INET,
		redirectIPv4Candidates,
		i.fakeIPPrefixes(),
	)
	if err != nil {
		return E.Cause(err, "select internal IPv4 redirect prefix")
	}
	if i.requiresIPv6Redirect() {
		i.redirectIPv6Prefix, err = commonEBPF.SelectRedirectPrefix(
			unix.AF_INET6,
			redirectIPv6Candidates,
			i.fakeIPPrefixes(),
		)
		if err != nil {
			return E.Cause(err, "select internal IPv6 redirect prefix")
		}
	} else {
		i.redirectIPv6Prefix = netip.Prefix{}
	}
	return nil
}

func (i *Inbound) setupLocalRoutes() error {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.redirectIPv4Prefix)
	}
	if i.cgroupIPv6Enabled() || i.sharedRewriteIPv6Enabled() {
		prefixes = append(prefixes, i.redirectIPv6Prefix)
	}
	routes, err := commonEBPF.NewLocalRouteSet(prefixes)
	if err != nil {
		return err
	}
	i.localRoutes = routes
	// A failure here only affects sockets bound to an interface; the interface
	// update that follows the monitor's start retries it.
	if _, err = i.reconcileRedirectInterfaceRoutes(); err != nil {
		i.interfaceWarnings.redirectRoutes.warn(i.logger, "configure eBPF redirect routes for bound sockets: ", err)
	}
	return nil
}

// reconcileRedirectInterfaceRoutes keeps the cgroup data plane's redirect
// prefixes reachable from sockets bound to an interface, such as the ones
// systemd-resolved uses for its DNS servers. Their route lookups skip the
// prefixes' loopback routes, so a connection the cgroup programs redirected
// would otherwise leave through the bound interface instead of reaching the
// listeners.
func (i *Inbound) reconcileRedirectInterfaceRoutes() (bool, error) {
	if i.localRoutes == nil || !i.localCgroupEnabled() {
		return false, nil
	}
	return i.localRoutes.ReconcileInterfaceRoutes()
}

func (i *Inbound) removeLocalRoutes() error {
	if i.localRoutes == nil {
		return nil
	}
	routeErr := i.localRoutes.Close()
	if i.localRoutes.IsClosed() {
		i.localRoutes = nil
	}
	return routeErr
}
