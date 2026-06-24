package v2rayxhttp

// uploadQueue 是给 packet-up 模式 server 端用的优先级队列。
//
// 客户端的 POST 上行包顺序受 CDN / HTTP/2 重排影响，到达服务端时 seq 可能乱序。
// 这个队列按 seq 排序、暂存 (heap)，连续序号的 payload 按顺序读出。
//
// 移植自 XTLS/Xray-core v26.3.27 transport/internet/splithttp/upload_queue.go。
// 该原始实现的版权 / 协议: Xray-core, MPL-2.0 (与本仓库 GPL 兼容)。

import (
	"container/heap"
	"errors"
	"io"
	"runtime"
	"sync"
)

// packet 是 uploadQueue 暂存的单元。
//
// 两种用途:
//   - stream-up: 整条 reader (POST body) 直接挂到 queue 上当永久 reader
//   - packet-up: 每个 POST 的 payload + seq 顺序号，按 seq 重排
type packet struct {
	reader  io.ReadCloser
	payload []byte
	seq     uint64
}

// uploadQueue 实现 io.ReadCloser，让 server 端 splitConn 的 Read 路径
// 可以无差别消费 stream-up 的长 reader 或 packet-up 的乱序 payload。
type uploadQueue struct {
	reader          io.ReadCloser
	nomore          bool
	pushedPackets   chan packet
	writeCloseMutex sync.Mutex
	heap            uploadHeap
	nextSeq         uint64
	closed          bool
	maxPackets      int
}

// newUploadQueue 创建一个上行队列。maxPackets 控制 heap 容量上限
// （超出时直接断连接，让对端重连）。
func newUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        false,
		maxPackets:    maxPackets,
	}
}

func (q *uploadQueue) push(p packet) error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()

	if q.closed {
		return errors.New("xhttp: packet queue closed")
	}
	if q.nomore {
		return errors.New("xhttp: queue already promoted to reader")
	}
	if p.reader != nil {
		q.nomore = true
	}
	q.pushedPackets <- p
	return nil
}

func (q *uploadQueue) Close() error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()

	if !q.closed {
		q.closed = true
		runtime.Gosched() // 让 Read() 先把 channel 里的最后一个包消费掉
	drain:
		for {
			select {
			case p := <-q.pushedPackets:
				if p.reader != nil {
					q.reader = p.reader
				}
			default:
				break drain
			}
		}
		close(q.pushedPackets)
	}
	if q.reader != nil {
		return q.reader.Close()
	}
	return nil
}

// Read 按 seq 顺序从堆里抽 payload。乱序到达的包暂存在 heap 里，
// 等 nextSeq 那一片到了再连续读出。
func (q *uploadQueue) Read(b []byte) (int, error) {
	// 一旦升级为 reader (stream-up 长 body)，后续读全走它。
	if q.reader != nil {
		return q.reader.Read(b)
	}

	if q.closed {
		return 0, io.EOF
	}

	if len(q.heap) == 0 {
		p, more := <-q.pushedPackets
		if !more {
			return 0, io.EOF
		}
		if p.reader != nil {
			q.reader = p.reader
			return q.reader.Read(b)
		}
		heap.Push(&q.heap, p)
	}

	for len(q.heap) > 0 {
		p := heap.Pop(&q.heap).(packet)

		if p.seq == q.nextSeq {
			n := copy(b, p.payload)
			if n < len(p.payload) {
				// b 装不下整片，剩下的塞回 heap 等下次读
				p.payload = p.payload[n:]
				heap.Push(&q.heap, p)
			} else {
				q.nextSeq = p.seq + 1
			}
			return n, nil
		}

		// 出现 seq 跳跃（乱序）— 把它塞回去，等更小的 seq
		if p.seq > q.nextSeq {
			if len(q.heap) > q.maxPackets {
				// 重组缓冲区太大，断流；客户端会重连重发
				return 0, errors.New("xhttp: packet queue overflow")
			}
			heap.Push(&q.heap, p)
			p2, more := <-q.pushedPackets
			if !more {
				return 0, io.EOF
			}
			heap.Push(&q.heap, p2)
		}
	}

	return 0, nil
}

// uploadHeap 直接照搬 container/heap 文档示例。
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
