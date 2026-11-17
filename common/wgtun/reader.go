// Package wgtun adapts sing-tun devices to the slab-based read contract of
// wireguard-go's tun.Reader.
package wgtun

import (
	"errors"
	"io"

	"github.com/sagernet/sing-tun"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

// Reader reads packets from a sing-tun device into wireguard-go read slabs:
// ReadPacketSpacing bytes before the first packet, between packets and after
// the last. It is not safe for concurrent use, which matches wireguard-go
// reading each queue from one goroutine.
type Reader struct {
	device tun.Tun
	batch  tun.LinuxTUN
	mtu    int
	bufs   [][]byte
	sizes  []int
}

// NewReader returns a Reader for device. Batched reads are used when device
// reads several packets at once; mtu bounds the size of one packet.
func NewReader(device tun.Tun, mtu int) *Reader {
	reader := &Reader{device: device, mtu: mtu}
	// Without GSO, Linux TUN packets lack the virtio header BatchRead needs.
	if batch, isBatch := device.(tun.LinuxTUN); isBatch && batch.BatchSize() > 1 {
		reader.batch = batch
	}
	return reader
}

// BatchSize is the number of packets one Read may return.
func (r *Reader) BatchSize() int {
	if r.batch != nil {
		return r.batch.BatchSize()
	}
	return 1
}

// Batch reports whether reads return several packets.
func (r *Reader) Batch() bool {
	return r.batch != nil
}

// Read implements [wgTun.Reader].
func (r *Reader) Read(slab []byte, packets []wgTun.ReadPacket) (int, error) {
	const spacing = wgTun.ReadPacketSpacing
	if len(packets) == 0 || len(slab) < 2*spacing {
		return 0, io.ErrShortBuffer
	}
	if r.batch == nil {
		if spacing < tun.PacketOffset {
			return 0, io.ErrShortBuffer
		}
		n, err := r.device.Read(slab[spacing-tun.PacketOffset : len(slab)-spacing])
		if err != nil {
			return 0, convertError(err)
		}
		if n < tun.PacketOffset {
			return 0, io.ErrUnexpectedEOF
		}
		packets[0] = wgTun.ReadPacket{Offset: spacing, Size: n - tun.PacketOffset}
		return 1, nil
	}
	// Every slot holds one packet of at most mtu bytes: a GSO read is split
	// into segments no larger than the device MTU.
	stride := r.mtu + spacing
	count := min(len(packets), (len(slab)-spacing)/stride)
	if count == 0 {
		return 0, io.ErrShortBuffer
	}
	r.bufs = r.bufs[:0]
	for i := range count {
		start := spacing + i*stride
		r.bufs = append(r.bufs, slab[start:start+r.mtu])
	}
	if cap(r.sizes) < count {
		r.sizes = make([]int, count)
	}
	sizes := r.sizes[:count]
	n, err := r.batch.BatchRead(r.bufs, 0, sizes)
	for i := range n {
		packets[i] = wgTun.ReadPacket{Offset: spacing + i*stride, Size: sizes[i]}
	}
	clear(r.bufs)
	return n, convertError(err)
}

// ReadPackets calls visit for each packet of a Read result, for tracing.
func ReadPackets(slab []byte, packets []wgTun.ReadPacket, visit func(packet []byte)) {
	for _, packet := range packets {
		visit(slab[packet.Offset : packet.Offset+packet.Size])
	}
}

func convertError(err error) error {
	if err != nil && errors.Is(err, tun.ErrTooManySegments) {
		return wgTun.ErrTooManySegments
	}
	return err
}
