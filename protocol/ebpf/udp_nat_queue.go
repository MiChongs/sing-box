//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"

	N "github.com/sagernet/sing/common/network"
)

const (
	// udpNATQueuePacketLimit and udpNATQueueByteLimit bound the packets one
	// session may hold before its reader takes them. The listener reads every
	// session from the same sockets, so a burst toward one destination
	// arrives faster than that session's goroutine can forward it; a queue
	// that is too short drops a large share of a single fast flow even when
	// the forwarder keeps up on average. The byte limit counts buffer
	// capacity, which is what a queued packet actually holds.
	udpNATQueuePacketLimit = 512
	udpNATQueueByteLimit   = 4 << 20
	udpNATQueueInitialSize = 16
)

// udpNATPacketQueue is a per-session FIFO that only allocates while packets
// are waiting. An idle session holds no slots, unlike a fixed-capacity channel.
type udpNATPacketQueue struct {
	access  sync.Mutex
	packets []*N.PacketBuffer
	head    int
	count   int
	bytes   int
	// notify holds one pending wake-up for a reader that found the queue empty.
	notify chan struct{}
}

func newUDPNATPacketQueue() *udpNATPacketQueue {
	return &udpNATPacketQueue{notify: make(chan struct{}, 1)}
}

// push appends packet unless the session already holds its limit.
func (q *udpNATPacketQueue) push(packet *N.PacketBuffer) bool {
	size := packet.Buffer.Cap()
	q.access.Lock()
	if q.count >= udpNATQueuePacketLimit || q.count > 0 && q.bytes+size > udpNATQueueByteLimit {
		q.access.Unlock()
		return false
	}
	if q.count == len(q.packets) {
		q.grow()
	}
	q.packets[(q.head+q.count)%len(q.packets)] = packet
	q.count++
	q.bytes += size
	q.access.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

func (q *udpNATPacketQueue) grow() {
	size := len(q.packets) * 2
	if size == 0 {
		size = udpNATQueueInitialSize
	}
	packets := make([]*N.PacketBuffer, size)
	for index := range q.count {
		packets[index] = q.packets[(q.head+index)%len(q.packets)]
	}
	q.packets = packets
	q.head = 0
}

// pop removes the oldest packet without waiting.
func (q *udpNATPacketQueue) pop() (*N.PacketBuffer, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	if q.count == 0 {
		return nil, false
	}
	packet := q.packets[q.head]
	q.packets[q.head] = nil
	q.head = (q.head + 1) % len(q.packets)
	q.count--
	q.bytes -= packet.Buffer.Cap()
	if q.count == 0 {
		// Drop the backing array once a burst is drained so an idle session
		// does not keep the slots it needed at its peak.
		q.packets = nil
		q.head = 0
		q.bytes = 0
	}
	return packet, true
}

func (q *udpNATPacketQueue) len() int {
	q.access.Lock()
	defer q.access.Unlock()
	return q.count
}
