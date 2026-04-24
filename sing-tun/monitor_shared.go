//go:build linux || windows || darwin

package tun

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

func (m *networkUpdateMonitor) RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *networkUpdateMonitor) UnregisterCallback(element *list.Element[NetworkUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *networkUpdateMonitor) emit() {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

type defaultInterfaceMonitor struct {
	interfaceFinder       control.InterfaceFinder
	overrideAndroidVPN    bool
	underNetworkExtension bool
	defaultInterface      atomic.Pointer[control.Interface]
	androidVPNEnabled     bool
	noRoute               bool
	networkMonitor        NetworkUpdateMonitor
	logger                logger.Logger
	checkUpdateTimer      *time.Timer
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
	myInterface           string

	// updateAccess 串行化 postCheckUpdate，避免 burst 事件 + ForceUpdate 并发
	// 多次 netlink 查询。checkUpdate 每次耗时 μs 级（NETLINK RuleList/
	// RouteList / GetBestInterface），加锁是为了正确性不是性能瓶颈。
	updateAccess sync.Mutex
	// forcing 合并并发 ForceUpdate；已有协程在跑就直接丢弃。
	forcing atomic.Bool
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		interfaceFinder:       options.InterfaceFinder,
		overrideAndroidVPN:    options.OverrideAndroidVPN,
		underNetworkExtension: options.UnderNetworkExtension,
		networkMonitor:        networkMonitor,
		logger:                logger,
	}, nil
}

func (m *defaultInterfaceMonitor) Start() error {
	m.postCheckUpdate()
	m.element = m.networkMonitor.RegisterCallback(m.delayCheckUpdate)
	return nil
}

// burstCoalesceWindow 是 netlink/系统事件 burst 合并窗口。从 1s 降到 50ms 的理由：
//
//	1s 窗口会把 Android Wi-Fi↔蜂窝切换期间的真实 FIB 已 ready 状态拖延 ~1s，
//	导致期间每个 DNS packet 都命中 "no route to internet" 刷屏；内核 FIB 本身
//	在切网后几十毫秒内就稳定了，我们只需要一个足够吞掉同一事件簇（addr/link/
//	route/policy 连发十几条）的合并窗口。50ms 足够合并一次切网 burst，对稳态
//	CPU 几乎无影响（稳态无事件）。
const burstCoalesceWindow = 50 * time.Millisecond

func (m *defaultInterfaceMonitor) delayCheckUpdate() {
	if m.checkUpdateTimer == nil {
		m.checkUpdateTimer = time.AfterFunc(burstCoalesceWindow, m.postCheckUpdate)
	} else {
		m.checkUpdateTimer.Reset(burstCoalesceWindow)
	}
}

func (m *defaultInterfaceMonitor) postCheckUpdate() {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	err := m.interfaceFinder.Update()
	if err != nil {
		m.logger.Error("update interface: ", err)
		return
	}
	err = m.checkUpdate()
	if errors.Is(err, ErrNoRoute) {
		if !m.noRoute {
			m.noRoute = true
			m.defaultInterface.Store(nil)
			m.emit(nil, 0)
		}
	} else if err != nil {
		m.logger.Error("check interface: ", err)
	} else {
		m.noRoute = false
	}
}

// ForceUpdate 异步、合并触发一次 checkUpdate。若已有 goroutine 在跑则直接丢弃
// （该次调用会借到正在进行的那轮结果）。热路径开销 = 一次 CAS。
func (m *defaultInterfaceMonitor) ForceUpdate() {
	if !m.forcing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer m.forcing.Store(false)
		m.postCheckUpdate()
	}()
}

func (m *defaultInterfaceMonitor) Close() error {
	if m.element != nil {
		m.networkMonitor.UnregisterCallback(m.element)
	}
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.defaultInterface.Load()
}

func (m *defaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return m.overrideAndroidVPN
}

func (m *defaultInterfaceMonitor) AndroidVPNEnabled() bool {
	return m.androidVPNEnabled
}

func (m *defaultInterfaceMonitor) RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *defaultInterfaceMonitor) UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *defaultInterfaceMonitor) emit(defaultInterface *control.Interface, flags int) {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback(defaultInterface, flags)
	}
}

func (m *defaultInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.access.Lock()
	defer m.access.Unlock()
	m.myInterface = interfaceName
}

func (m *defaultInterfaceMonitor) MyInterface() string {
	m.access.Lock()
	defer m.access.Unlock()
	return m.myInterface
}
