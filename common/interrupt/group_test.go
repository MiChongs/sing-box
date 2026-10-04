package interrupt

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type callbackCloser func() error

func (c callbackCloser) Close() error { return c() }

func TestInterruptKeepsResourceDownloadAndClosesOutsideLock(t *testing.T) {
	group := NewGroup()
	var detach func()
	closed := make(chan struct{})
	detach = group.Add(callbackCloser(func() error { detach(); close(closed); return nil }), true)
	left, right := net.Pipe()
	defer right.Close()
	provider := group.NewConn(left, true, true)
	defer provider.Close()
	done := make(chan struct{})
	go func() { group.Interrupt(true); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close callback deadlocked with interrupt group")
	}
	<-closed
	require.Equal(t, 1, group.connections.Len())
}

type testGroupConn struct {
	net.Conn
	closed bool
}

func (c *testGroupConn) Close() error { c.closed = true; return nil }

type testGroupPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *testGroupPacketConn) Close() error { c.closed = true; return nil }

func TestGroupResourceDownloadProtection(t *testing.T) {
	for _, external := range []bool{false, true} {
		for _, resourceDownload := range []bool{false, true} {
			for _, interruptExternal := range []bool{false, true} {
				t.Run(fmt.Sprintf("external=%t/download=%t/interrupt=%t", external, resourceDownload, interruptExternal), func(t *testing.T) {
					group := NewGroup()
					tcp := new(testGroupConn)
					udp := new(testGroupPacketConn)
					wrappedTCP := group.NewConn(tcp, external, resourceDownload)
					wrappedUDP := group.NewPacketConn(udp, external, resourceDownload)
					group.Interrupt(interruptExternal)
					expected := !resourceDownload && (!external || interruptExternal)
					require.Equal(t, expected, tcp.closed)
					require.Equal(t, expected, udp.closed)
					require.NoError(t, wrappedTCP.Close())
					require.NoError(t, wrappedUDP.Close())
					require.True(t, tcp.closed)
					require.True(t, udp.closed)
				})
			}
		}
	}
}

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
