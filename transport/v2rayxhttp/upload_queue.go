package v2rayxhttp

// uploadQueue 是服务端的优先级队列 + channel，按 seq 重排 packet-up 上行包；
// stream-up 时整条 POST body 作为 reader 挂上来。
//
// 移植自 XTLS/Xray-core v26.9.30 transport/internet/splithttp/upload_queue.go。

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"
)

type packet struct {
	reader  *httpServerConn
	payload []byte
	seq     uint64
}

type uploadQueue struct {
	reader        atomic.Pointer[httpServerConn]
	pushedPackets chan packet
	heap          uploadHeap
	nextSeq       uint64
	maxPackets    int
	closed        chan struct{}
	closeOnce     sync.Once
}

func newUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan packet, maxPackets),
		maxPackets:    maxPackets,
		closed:        make(chan struct{}),
	}
}

func (q *uploadQueue) isClosed() bool {
	select {
	case <-q.closed:
		return true
	default:
		return false
	}
}

func (q *uploadQueue) push(p packet) error {
	if q.reader.Load() != nil || (p.reader != nil && !q.reader.CompareAndSwap(nil, p.reader)) {
		return E.New("xhttp: upload reader already exists")
	}
	select {
	case q.pushedPackets <- p:
		if q.isClosed() {
			return E.New("xhttp: packet queue closed")
		}
		return nil
	case <-q.closed:
		return E.New("xhttp: packet queue closed")
	}
}

func (q *uploadQueue) Close() error {
	q.closeOnce.Do(func() { close(q.closed) })
	if reader := q.reader.Load(); reader != nil {
		return reader.Close()
	}
	return nil
}

func (q *uploadQueue) Read(b []byte) (int, error) {
	if reader := q.reader.Load(); reader != nil {
		return reader.Read(b)
	}
	if q.isClosed() {
		return 0, io.EOF
	}
	if len(q.heap) == 0 {
		select {
		case p := <-q.pushedPackets:
			if p.reader != nil {
				return p.reader.Read(b)
			}
			heap.Push(&q.heap, p)
		case <-q.closed:
			return 0, io.EOF
		}
	}
	for len(q.heap) > 0 {
		p := heap.Pop(&q.heap).(packet)
		if p.seq == q.nextSeq {
			n := copy(b, p.payload)
			if n < len(p.payload) {
				// partial read
				p.payload = p.payload[n:]
				heap.Push(&q.heap, p)
			} else {
				q.nextSeq = p.seq + 1
			}
			return n, nil
		}
		// misordered packet
		if p.seq > q.nextSeq {
			if len(q.heap) > q.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, E.New("xhttp: packet queue is too large")
			}
			heap.Push(&q.heap, p)
			select {
			case p2 := <-q.pushedPackets:
				heap.Push(&q.heap, p2)
			case <-q.closed:
				return 0, io.EOF
			}
		}
	}
	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].seq < h[j].seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) { *h = append(*h, x.(packet)) }

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
