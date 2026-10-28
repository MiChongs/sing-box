package easytier

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/stretchr/testify/require"
)

func testIPv4Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	copy(packet[20:], payload)
	return packet
}

func freeLoopbackTCPPort(t *testing.T) int {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

func startTestCore(t *testing.T, ctx context.Context, host *corehost.Host, id int, address string, listen string, peer string) *corehost.Instance {
	builder := corehost.NewInstanceConfigBuilder("default").
		NetworkSecret("test").
		Hostname(fmt.Sprintf("node-%d", id)).
		IPv4(netip.MustParsePrefix(address + "/24")).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false)
	if listen != "" {
		builder.AddListeners(listen)
	}
	if peer != "" {
		builder.AddPeers(peer)
	}
	config, err := builder.Build()
	require.NoError(t, err)
	instance, err := host.CreateInstance(ctx, config)
	require.NoError(t, err)
	require.NoError(t, instance.Start(ctx))
	t.Cleanup(func() { _ = instance.Close(context.Background()) })
	return instance
}

// TestWritePacketBuffersReachesPeer sends device packets through the batched
// ingress path to a second core over a loopback tunnel.
func TestWritePacketBuffersReachesPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two EasyTier cores")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	require.NoError(t, err)
	defer host.Close(context.Background())
	listener := fmt.Sprintf("tcp://127.0.0.1:%d", freeLoopbackTCPPort(t))
	server := startTestCore(t, ctx, host, 1, "10.144.0.1", listener, "")
	client := startTestCore(t, ctx, host, 2, "10.144.0.2", "", listener)

	endpoint := &Endpoint{ctx: ctx, logger: log.NewNOPFactory().NewLogger("easytier")}
	attached := &attachedInstance{endpoint: endpoint, instance: client, ctx: ctx, done: make(chan struct{})}
	attached.state.Store(&instanceState{configured: true, addresses: []netip.Prefix{netip.MustParsePrefix("10.144.0.2/24")}})
	endpoint.snapshot.Store(newRoutingSnapshot([]*attachedInstance{attached}))

	source, destination := netip.MustParseAddr("10.144.0.2"), netip.MustParseAddr("10.144.0.1")
	newBuffers := func(count int, offset int) []*buf.Buffer {
		buffers := make([]*buf.Buffer, count)
		for index := range buffers {
			payload := make([]byte, 100+offset+index)
			buffers[index] = buf.As(testIPv4Packet(source, destination, payload)).ToOwned()
		}
		return buffers
	}
	// Wait for the tunnel with single probes.
	received := make([][]byte, 128)
	require.Eventually(t, func() bool {
		require.NoError(t, endpoint.writePacketBuffers(newBuffers(1, 1000)))
		receiveCtx, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		n, receiveErr := server.ReceivePackets(receiveCtx, received)
		for _, packet := range received[:n] {
			corehost.ReleasePacket(packet)
		}
		return receiveErr == nil && n > 0
	}, 20*time.Second, 10*time.Millisecond)

	// More than one ingress batch, all delivered intact and released.
	const count = packetIngressBatch*2 + 7
	buffers := newBuffers(count, 0)
	require.NoError(t, endpoint.writePacketBuffers(buffers))
	for _, buffer := range buffers {
		require.True(t, buffer.IsEmpty() || buffer.Cap() == 0, "sent buffers are released")
	}
	seen := make(map[int]bool)
	for len(seen) < count {
		receiveCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		n, receiveErr := server.ReceivePackets(receiveCtx, received)
		stop()
		require.NoError(t, receiveErr, "received %d of %d packets", len(seen), count)
		for _, packet := range received[:n] {
			index := len(packet) - 20 - 100
			if index >= 0 && index < count {
				require.Equal(t, testIPv4Packet(source, destination, make([]byte, 100+index)), packet)
				seen[index] = true
			}
			corehost.ReleasePacket(packet)
		}
	}
}
