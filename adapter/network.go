package adapter

import (
	"encoding/hex"
	"net"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type NetworkManager interface {
	Lifecycle
	Initialize(ruleSets []RuleSet)
	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	DefaultNetworkInterface() *NetworkInterface
	NetworkInterfaces() []NetworkInterface
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	ProtectFunc() control.Func
	DefaultOptions() NetworkOptions
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	AutoRedirectOutputMarkFunc() control.Func
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	NeedWIFIState() bool
	WIFIState() WIFIState
	UpdateWIFIState()
	ResetNetwork()
	RegisterNetworkResetCallback(callback func())

	// HintUnreachable 供下游（DNS/outbound）在遇到 ENETUNREACH/EHOSTUNREACH 时
	// 反馈给 monitor，异步合并触发一次默认接口重探。正常调用开销为一次 CAS；
	// 真的切网时把 monitor 的感知从最多 ~1s 压到 <100ms，对用户无感。
	HintUnreachable()
}

type NetworkOptions struct {
	BindInterface        string
	RoutingMark          uint32
	DomainResolver       string
	DomainResolveOptions DNSQueryOptions
	NetworkStrategy      *C.NetworkStrategy
	NetworkType          []C.InterfaceType
	FallbackNetworkType  []C.InterfaceType
	FallbackDelay        time.Duration
}

type InterfaceUpdateListener interface {
	InterfaceUpdated()
}

type WIFIState struct {
	SSID  string
	BSSID string
}

func NormalizeWIFIBSSID(bssid string) string {
	bssid = strings.TrimSpace(bssid)
	if bssid == "" {
		return ""
	}
	parsed, err := net.ParseMAC(bssid)
	if err == nil && len(parsed) == 6 {
		return parsed.String()
	}
	if len(bssid) == 12 {
		decoded, err := hex.DecodeString(bssid)
		if err == nil {
			return net.HardwareAddr(decoded).String()
		}
	}
	return bssid
}

type NetworkInterface struct {
	control.Interface
	Type        C.InterfaceType
	DNSServers  []string
	Expensive   bool
	Constrained bool
}
