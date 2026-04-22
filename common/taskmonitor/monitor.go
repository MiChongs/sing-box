package taskmonitor

import (
	"sync"
	"time"

	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

// Monitor 必须支持并发 Start/Finish — 调用点例如
// adapter/outbound/manager.go::startOutbounds 会把同一 Monitor 传给
// 并行的 startSingleOutbound goroutines。原实现 m.timer 写入无锁，
// race 下可能出现：
//
//   - G1.Start() 设 m.timer = T1
//   - G2.Start() 设 m.timer = T2 (丢失 T1)
//   - G1.Finish() 读 m.timer (可能看到 T2 或半写入状态)
//   - 进程被 Go 1.23+ 的 "Stop called on uninitialized Timer"
//     防御性 panic 爆掉
//
// 修复：m.timer 的读写都走 mu，Finish 幂等 (Start 从未调用时 no-op)。
// 用 *time.Timer 字段改成 slice 记录多任务栈同样可以，但当前 Monitor
// 的 "一次只监视一个任务" 语义足够，mutex 是最小变动。
type Monitor struct {
	logger  logger.Logger
	timeout time.Duration
	mu      sync.Mutex
	timer   *time.Timer
}

func New(logger logger.Logger, timeout time.Duration) *Monitor {
	return &Monitor{
		logger:  logger,
		timeout: timeout,
	}
}

// Start 启动一次超时监视。若上一个 Start 没有配对的 Finish (并发调用或
// 调用方漏掉 Finish)，先 Stop 掉旧 timer 再建新的，避免 timer 泄漏。
func (m *Monitor) Start(taskName ...any) {
	t := time.AfterFunc(m.timeout, func() {
		m.logger.Warn(F.ToString(taskName...), " take too much time to finish!")
	})
	m.mu.Lock()
	if old := m.timer; old != nil {
		old.Stop()
	}
	m.timer = t
	m.mu.Unlock()
}

// Finish 停止当前 timer。
// - Start 从未调用过 (m.timer == nil) 时 no-op，不再 panic
// - 并发多次 Finish 幂等，第二次 no-op (m.timer == nil 之后)
// - Go 1.23+ 对 zero-value *time.Timer 的 Stop 会 panic
//   "uninitialized Timer"；Finish 用 Swap 后判空确保只对真实
//   AfterFunc 返回的 Timer 做 Stop
func (m *Monitor) Finish() {
	m.mu.Lock()
	t := m.timer
	m.timer = nil
	m.mu.Unlock()
	if t != nil {
		t.Stop()
	}
}
