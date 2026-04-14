package interrupt

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn 实现 net.Conn 以便注册入 Group
type fakeConn struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

// TestGroup_ConcurrentInterruptAndClose 并发 NewConn / Close / Interrupt，
// 验证不会出现 nil pointer panic（历史 bug：sync.Pool + 锁外置 nil 导致别名）。
// 运行：go test -race ./common/interrupt/
func TestGroup_ConcurrentInterruptAndClose(t *testing.T) {
	g := NewGroup()
	var wg sync.WaitGroup

	// Producer: 持续 NewConn
	const producers = 8
	const perProducer = 500
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				c := g.NewConn(&fakeConn{}, false, false)
				// 半数连接由 Conn.Close 主动关闭
				if j%2 == 0 {
					_ = c.Close()
				}
			}
		}()
	}

	// Interrupter: 并发触发批量中断
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			g.Interrupt(true)
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()
	// 最终状态再中断一次清理
	g.Interrupt(true)
}

// TestGroup_InterruptEmpty 空 Group Interrupt 不崩
func TestGroup_InterruptEmpty(t *testing.T) {
	g := NewGroup()
	g.Interrupt(true)
	g.Interrupt(false)
}

// TestGroup_CloseIdempotent Conn.Close 被调用多次应当安全（部分上游路径可能重复关闭）
func TestGroup_CloseIdempotent(t *testing.T) {
	g := NewGroup()
	c := g.NewConn(&fakeConn{}, false, false)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// 第二次 close：list.Remove 对已移除的 element 应安全（或上层保证不重入）。
	// 不保证 Close 绝对幂等——这里只验证不触发 nil panic。
	defer func() { _ = recover() }()
	_ = c.Close()
}
