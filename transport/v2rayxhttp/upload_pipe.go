package v2rayxhttp

import (
	"io"
	"sync"
)

// uploadPipe 是 packet-up 上行的缓冲管道，等价于 Xray dialer.go 里的
// pipe.New(pipe.WithSizeLimit(...)) + uploadWriter:
//
//   - Write 把数据追加进缓冲，缓冲满 (>= limit) 时阻塞，形成背压；
//   - readAll 一次取走全部已缓冲数据，多次 conn.Write 自然合并成一个 POST；
//   - Close 后 readAll 先把剩余数据交出再返回 EOF，保证关闭前写入的数据都能发出；
//   - interrupt 用于上行 POST 失败: 丢弃缓冲并让后续 Write 立即报错。
type uploadPipe struct {
	access sync.Mutex
	cond   *sync.Cond
	buffer []byte
	limit  int
	closed bool
	err    error
}

func newUploadPipe(limit int) *uploadPipe {
	p := &uploadPipe{limit: max(limit, 1)}
	p.cond = sync.NewCond(&p.access)
	return p
}

func (p *uploadPipe) Write(b []byte) (int, error) {
	p.access.Lock()
	defer p.access.Unlock()
	var written int
	for len(b) > 0 {
		for len(p.buffer) >= p.limit && !p.closed && p.err == nil {
			p.cond.Wait()
		}
		if p.err != nil {
			return written, p.err
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}
		n := min(len(b), p.limit-len(p.buffer))
		p.buffer = append(p.buffer, b[:n]...)
		b = b[n:]
		written += n
		p.cond.Broadcast()
	}
	return written, nil
}

// readAll 阻塞直到有数据或管道关闭，返回的切片归调用方所有。
func (p *uploadPipe) readAll() ([]byte, error) {
	p.access.Lock()
	defer p.access.Unlock()
	for len(p.buffer) == 0 && !p.closed && p.err == nil {
		p.cond.Wait()
	}
	if p.err != nil {
		return nil, p.err
	}
	if len(p.buffer) == 0 {
		return nil, io.EOF
	}
	data := p.buffer
	p.buffer = nil
	p.cond.Broadcast()
	return data, nil
}

func (p *uploadPipe) Close() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.closed = true
	p.cond.Broadcast()
	return nil
}

func (p *uploadPipe) interrupt(err error) {
	p.access.Lock()
	defer p.access.Unlock()
	if p.err == nil {
		p.err = err
	}
	p.buffer = nil
	p.cond.Broadcast()
}
