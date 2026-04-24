package tun

import (
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

var ErrNoRoute = E.New("no route to internet")

type (
	NetworkUpdateCallback          = func()
	DefaultInterfaceUpdateCallback = func(defaultInterface *control.Interface, flags int)
)

const FlagAndroidVPNUpdate = 1 << iota

type NetworkUpdateMonitor interface {
	Start() error
	Close() error
	RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[NetworkUpdateCallback])
}

type DefaultInterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterface() *control.Interface
	OverrideAndroidVPN() bool
	AndroidVPNEnabled() bool
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
	RegisterMyInterface(interfaceName string)
	MyInterface() string
	// ForceUpdate 异步、合并地触发一次 checkUpdate。
	// 用途：dial 返回 ENETUNREACH/EHOSTUNREACH 时由路由层调用，向 monitor
	// 反馈"内核 FIB 已变，但用户态快照滞后"，不等待下一个 netlink 事件或
	// debounce 到期。多次并发调用会合并成一次执行；热路径开销只有一次
	// atomic.CompareAndSwap。
	ForceUpdate()
}

type DefaultInterfaceMonitorOptions struct {
	InterfaceFinder       control.InterfaceFinder
	OverrideAndroidVPN    bool
	UnderNetworkExtension bool
}
