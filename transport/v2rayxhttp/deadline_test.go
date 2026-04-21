package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// blockingPipe 是 io.PipeReader/Writer 的精简等价，用于构造"永远不会有
// 对端读取"的 writer，模拟 xhttp 隧道建立但迟迟等不到响应的场景。
// PipeWriter.Write 会阻塞直到 PipeReader 消费或 Close。
type blockingPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newBlockingPipe() *blockingPipe {
	r, w := io.Pipe()
	return &blockingPipe{r: r, w: w}
}

// TestSetDeadlineUnblocksWrite 验证 SetDeadline 能解开 Write 上的永久阻塞。
// 修复前：xhttpConn.SetDeadline 返回 os.ErrInvalid，Write 走底层 PipeWriter
// 无 deadline 概念，节点失联时 urltest 的 TLS ClientHello 会永远卡住。
// 修复后：deadline 到时 timer 会 Close conn，Write 立刻以 timeout 返回。
func TestSetDeadlineUnblocksWrite(t *testing.T) {
	pipe := newBlockingPipe()
	c := newLateXHTTPConn(pipe.w, nil)

	// 把 deadline 设到 80ms 后。这个值要足够大来观察 timer 生效但又足够
	// 小让测试总时长可控——80ms 远小于默认 probe 预算，又远大于调度抖动。
	deadline := time.Now().Add(80 * time.Millisecond)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		// 1 字节足够触发 pipe write 阻塞（无消费方）
		_, err := c.Write([]byte{0x1})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("want timeout error, got nil")
		}
		var te interface{ Timeout() bool }
		if !errors.As(err, &te) || !te.Timeout() {
			t.Fatalf("want net.Error{Timeout:true}, got %T: %v", err, err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Write did not unblock after SetWriteDeadline fired")
	}

	// 清理：关 pipe 让 reader side 看到 EOF，避免 goroutine 泄漏。
	_ = pipe.r.Close()
}

// TestSetupReaderErrClosesWriter 验证 tunnel 建立失败时 writer 会被关掉，
// pending Write 立即返回而不是永久挂起。修复前：setupReader 只记错误到
// setupErr，writer 仍 open，任何 Write 都会阻塞到对端 pipe 消费为止。
func TestSetupReaderErrClosesWriter(t *testing.T) {
	pipe := newBlockingPipe()
	c := newLateXHTTPConn(pipe.w, nil)

	errCh := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("hello"))
		errCh <- err
	}()

	// 模拟 xhttp RoundTrip goroutine 拿到非 2xx 响应：setupReader(nil, err)
	time.Sleep(20 * time.Millisecond) // 让 Write 先阻塞起来
	tunnelErr := errors.New("xhttp stream-one: status 502 Bad Gateway")
	c.setupReader(nil, tunnelErr)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Write should have failed after setupReader(err)")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Write still blocked after setupReader failure — writer not closed")
	}

	_ = pipe.r.Close()
}

// TestSetDeadlineZeroClears 验证 zero time.Time 能取消已设的 deadline
// （标准 net.Conn 语义），后续 Read/Write 不会被之前的 timer 意外打断。
func TestSetDeadlineZeroClears(t *testing.T) {
	pipe := newBlockingPipe()
	c := newLateXHTTPConn(pipe.w, nil)

	// 先设一个 50ms deadline
	_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	// 立刻取消
	_ = c.SetWriteDeadline(time.Time{})
	// 等过 deadline 原时刻
	time.Sleep(100 * time.Millisecond)

	// 此时 deadlineFired 应为 false（timer 已 stop）
	if c.deadlineFired.Load() {
		t.Fatal("deadline fired after being cleared with zero time.Time")
	}
	_ = pipe.r.Close()
}

// ensure net import not unused
var _ = net.IPv4zero
