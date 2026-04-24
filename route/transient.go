package route

import (
	"errors"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun"
)

// transient.go — 切网过渡期瞬态网络错误的判定 + 日志节流。
//
// 背景：Android/Windows/Linux 在网络切换（Wi-Fi↔Cellular、VPN 起/停、网卡
// 重连）瞬间，用户态 monitor 快照可能滞后内核 FIB 几十到几百毫秒。期间 dial
// 会返回两类"其实正常"的错误：
//
//	tun.ErrNoRoute            —— 用户态 monitor 尚无默认接口快照
//	syscall.ENETUNREACH       —— 内核 FIB 里该出接口此刻无 default route
//	syscall.EHOSTUNREACH      —— 目的 host 在内核看来不可达
//
// 这些错误是自愈的（几百毫秒内恢复）。我们要做的：
//  1. 不打 Error 刷屏（DNS 一次查询放大成几十条错误）；
//  2. 借助这个信号反哺 monitor 重探（HintUnreachable）；
//  3. 真正异常（DNS 正确、proxy 响应异常等）仍走原 Error 路径。

// isTransientUnreachable 判定是否属于"切网瞬态不可达"。
// 跨平台：syscall.ENETUNREACH/EHOSTUNREACH 在 Windows 下也有定义（wrapped from
// WSAENETUNREACH/WSAEHOSTUNREACH），无需按 GOOS 分别写。
func isTransientUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, tun.ErrNoRoute) {
		return true
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	return false
}

// logThrottle 每秒最多放行一条日志。用 atomic.Int64 无锁实现。
type logThrottle struct {
	lastNano atomic.Int64
}

func (t *logThrottle) allow() bool {
	now := time.Now().UnixNano()
	prev := t.lastNano.Load()
	if now-prev < int64(time.Second) {
		return false
	}
	// CAS 失败说明有并发者刚放行，本次静默即可。
	return t.lastNano.CompareAndSwap(prev, now)
}

// 全局单例：DNS 路径瞬态错误日志节流器。
var transientDNSLogThrottle logThrottle
