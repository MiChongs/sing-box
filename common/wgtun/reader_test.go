package wgtun

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-tun"
	wgTun "github.com/sagernet/wireguard-go/tun"

	"github.com/stretchr/testify/require"
)

type singleReadTUN struct {
	tun.Tun
	packet []byte
}

func (t *singleReadTUN) Read(p []byte) (int, error) {
	n := copy(p[tun.PacketOffset:], t.packet)
	return tun.PacketOffset + n, nil
}

type batchReadTUN struct {
	tun.LinuxTUN
	batchSize int
	slots     int
	slotSize  int
}

func (t *batchReadTUN) BatchSize() int { return t.batchSize }

func (t *batchReadTUN) BatchRead(buffers [][]byte, offset int, sizes []int) (int, error) {
	t.slots = len(buffers)
	t.slotSize = len(buffers[0]) - offset
	for i := range buffers {
		sizes[i] = copy(buffers[i][offset:], bytes.Repeat([]byte{byte(i)}, 40))
	}
	return len(buffers), nil
}

func TestReaderSingle(t *testing.T) {
	t.Parallel()
	packet := []byte{0x45, 1, 2, 3, 4}
	reader := NewReader(&singleReadTUN{packet: packet}, 1500)
	require.False(t, reader.Batch())
	require.Equal(t, 1, reader.BatchSize())
	slab := make([]byte, 1500+2*wgTun.ReadPacketSpacing)
	packets := make([]wgTun.ReadPacket, 1)
	n, err := reader.Read(slab, packets)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, wgTun.ReadPacket{Offset: wgTun.ReadPacketSpacing, Size: len(packet)}, packets[0])
	require.Equal(t, packet, slab[packets[0].Offset:packets[0].Offset+packets[0].Size])
}

func TestReaderBatchFitsSlab(t *testing.T) {
	t.Parallel()
	const mtu = 1420
	device := &batchReadTUN{batchSize: 128}
	reader := NewReader(device, mtu)
	require.True(t, reader.Batch())
	require.Equal(t, 128, reader.BatchSize())
	slab := make([]byte, 2*(1<<16-1))
	packets := make([]wgTun.ReadPacket, 128)
	n, err := reader.Read(slab, packets)
	require.NoError(t, err)
	stride := mtu + wgTun.ReadPacketSpacing
	require.Equal(t, (len(slab)-wgTun.ReadPacketSpacing)/stride, n, "slots are bounded by the slab")
	require.Equal(t, n, device.slots)
	require.Equal(t, mtu, device.slotSize)
	end := 0
	for i, packet := range packets[:n] {
		require.GreaterOrEqual(t, packet.Offset, end+wgTun.ReadPacketSpacing)
		require.Equal(t, bytes.Repeat([]byte{byte(i)}, 40), slab[packet.Offset:packet.Offset+packet.Size])
		end = packet.Offset + packet.Size
	}
	require.LessOrEqual(t, end+wgTun.ReadPacketSpacing, len(slab))

	// a small slab bounds the batch to what fits
	n, err = reader.Read(make([]byte, stride+wgTun.ReadPacketSpacing), packets)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}
