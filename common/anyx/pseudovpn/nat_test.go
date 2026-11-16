package pseudovpn

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/anyx/pseudovpn/pvtest"

	"github.com/stretchr/testify/require"
)

func TestNAT_UDPChecksums(t *testing.T) {
	assigned4 := netip.MustParseAddr("100.64.0.9")
	packet := pvtest.UDP(netip.AddrPortFrom(LocalPortIPv4, 5000), netip.MustParseAddrPort("1.1.1.1:53"), []byte("query"))
	rewritePacketSrcIPv4(packet, assigned4)
	require.Equal(t, assigned4, pvtest.Source(packet))
	require.True(t, pvtest.ChecksumsValid(packet))

	// IPv4 UDP 校验和为 0 表示未启用，改写后仍保持 0。
	noChecksum := pvtest.UDP(netip.AddrPortFrom(LocalPortIPv4, 5000), netip.MustParseAddrPort("1.1.1.1:53"), []byte("query"))
	binary.BigEndian.PutUint16(pvtest.L4(noChecksum)[6:8], 0)
	rewritePacketSrcIPv4(noChecksum, assigned4)
	require.Zero(t, binary.BigEndian.Uint16(pvtest.L4(noChecksum)[6:8]))

	assigned6 := netip.MustParseAddr("fd00::9")
	packet6 := pvtest.UDP(netip.AddrPortFrom(LocalPortIPv6, 5000), netip.MustParseAddrPort("[2606:4700::1111]:53"), []byte("query"))
	rewritePacketSrcIPv6(packet6, assigned6)
	require.Equal(t, assigned6, pvtest.Source(packet6))
	require.True(t, pvtest.ChecksumsValid(packet6))
}

func TestNAT_TCPAndICMPEchoChecksums(t *testing.T) {
	for _, pair := range []struct {
		local, assigned, remote netip.Addr
		src, dst                func([]byte, netip.Addr)
	}{
		{LocalPortIPv4, netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("93.184.216.34"), rewritePacketSrcIPv4, rewritePacketDstIPv4},
		{LocalPortIPv6, netip.MustParseAddr("fd00::9"), netip.MustParseAddr("2606:2800:220:1::1"), rewritePacketSrcIPv6, rewritePacketDstIPv6},
	} {
		tcp := pvtest.TCP(netip.AddrPortFrom(pair.local, 40000), netip.AddrPortFrom(pair.remote, 443), 1, 0, pvtest.TCPFlagSyn, 1460, []byte("x"))
		pair.src(tcp, pair.assigned)
		require.True(t, pvtest.ChecksumsValid(tcp))
		echo := pvtest.Echo(pair.remote, pair.assigned, 3, 4, true, []byte("pong"))
		pair.dst(echo, pair.local)
		require.Equal(t, pair.local, pvtest.Destination(echo))
		require.True(t, pvtest.ChecksumsValid(echo))
	}
}

// ICMP 差错报文的内嵌头在两个方向上都随外层地址改写，内层 IP / TCP 与外层 ICMP 校验和保持正确。
func TestNAT_ICMPErrorBothDirections(t *testing.T) {
	for _, family := range []struct {
		name     string
		local    netip.Addr
		assigned netip.Addr
		remote   netip.Addr
		src      func([]byte, netip.Addr)
		dst      func([]byte, netip.Addr)
	}{
		{"ipv4", LocalPortIPv4, netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("93.184.216.34"), rewritePacketSrcIPv4, rewritePacketDstIPv4},
		{"ipv6", LocalPortIPv6, netip.MustParseAddr("fd00::9"), netip.MustParseAddr("2606:2800:220:1::1"), rewritePacketSrcIPv6, rewritePacketDstIPv6},
	} {
		t.Run(family.name, func(t *testing.T) {
			// 上行：本机对一个回程报文（remote → local）回 ICMP 差错，内嵌目的地址须一并换成虚拟地址。
			received := pvtest.TCP(netip.AddrPortFrom(family.remote, 443), netip.AddrPortFrom(family.local, 40000), 1, 1, pvtest.TCPFlagAck, 0, []byte("data"))
			uplink := pvtest.ICMPError(family.local, family.remote, received)
			family.src(uplink, family.assigned)
			require.Equal(t, family.assigned, pvtest.Source(uplink))
			require.Equal(t, family.assigned, pvtest.Destination(pvtest.Inner(uplink)))
			require.True(t, pvtest.ChecksumsValid(uplink))
			require.True(t, pvtest.ChecksumsValid(pvtest.Inner(uplink)), "内嵌报文的 IP 与 TCP 校验和必须随之修正")

			// 下行：远端对本机发出的报文（assigned → remote）回差错，内嵌源地址须还原为本地端口地址。
			sent := pvtest.TCP(netip.AddrPortFrom(family.assigned, 40000), netip.AddrPortFrom(family.remote, 443), 1, 0, pvtest.TCPFlagSyn, 1360, nil)
			downlink := pvtest.ICMPError(family.remote, family.assigned, sent)
			family.dst(downlink, family.local)
			require.Equal(t, family.local, pvtest.Destination(downlink))
			require.Equal(t, family.local, pvtest.Source(pvtest.Inner(downlink)))
			require.True(t, pvtest.ChecksumsValid(downlink))
			require.True(t, pvtest.ChecksumsValid(pvtest.Inner(downlink)))

			// 内嵌地址与旧地址不符时不改写内嵌报文，外层仍然正确。
			other := pvtest.TCP(netip.AddrPortFrom(family.remote, 1), netip.AddrPortFrom(family.remote, 2), 1, 0, pvtest.TCPFlagSyn, 0, nil)
			unrelated := pvtest.ICMPError(family.remote, family.assigned, other)
			family.dst(unrelated, family.local)
			require.Equal(t, family.remote, pvtest.Source(pvtest.Inner(unrelated)))
			require.True(t, pvtest.ChecksumsValid(unrelated))
		})
	}
}
