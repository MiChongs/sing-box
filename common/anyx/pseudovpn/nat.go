package pseudovpn

import (
	"encoding/binary"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// 客户端 1:1 NAT。
//
// TUN 转发器在建流时把源地址改写为 PortAddresses() 的返回值，并在流的整个生命周期内沿用。
// 若端口地址跟随协商结果变化，协商前（或换址前）建立的流与之后建立的流会持有不同的端口地址，
// 引擎就无法用一个映射同时服务它们。因此端口地址固定为下面这对本地地址，引擎始终在
// “本地端口地址 ↔ 当前虚拟地址”之间转换：重协商换址后，所有流自动映射到新地址。
//
// 192.0.0.8 是 RFC 7600 为“没有 IPv4 地址的主机”保留的 IPv4 dummy 地址；IPv6 取一个固定的
// ULA。两者只存在于本机转发器与引擎之间，不会出现在隧道里。
var (
	LocalPortIPv4 = netip.MustParseAddr("192.0.0.8")
	LocalPortIPv6 = netip.MustParseAddr("fd61:6e79:7876::2")
)

func isICMPv4Error(icmpType byte) bool {
	switch icmpType {
	case 3, 4, 5, 11, 12: // Destination Unreachable, Source Quench, Redirect, Time Exceeded, Parameter Problem
		return true
	default:
		return false
	}
}

func isICMPv6Error(icmpType byte) bool {
	return icmpType >= 1 && icmpType <= 4 // Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem
}

// rewritePacketSrcIPv4 / rewritePacketDstIPv4 改写 IPv4 源 / 目的地址，并修正 IP 首部、TCP、UDP
// 校验和；ICMP 差错报文的内嵌原始报文中对应的地址（源地址改写时为内嵌目的地址，反之亦然）
// 只在等于旧地址时一并改写，并修正内嵌 IP 首部、内嵌 TCP/UDP 与外层 ICMP 校验和。
func rewritePacketSrcIPv4(packet []byte, newSrc netip.Addr) {
	rewriteIPv4Address(packet, 12, newSrc)
}

func rewritePacketDstIPv4(packet []byte, newDst netip.Addr) {
	rewriteIPv4Address(packet, 16, newDst)
}

func rewritePacketSrcIPv6(packet []byte, newSrc netip.Addr) {
	rewriteIPv6Address(packet, 8, newSrc)
}

func rewritePacketDstIPv6(packet []byte, newDst netip.Addr) {
	rewriteIPv6Address(packet, 24, newDst)
}

func rewriteIPv4Address(packet []byte, offset int, newAddr netip.Addr) {
	if !newAddr.IsValid() || !newAddr.Is4() {
		return
	}
	if header.IPVersion(packet) != header.IPv4Version || len(packet) < header.IPv4MinimumSize {
		return
	}
	hdrLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if hdrLen < header.IPv4MinimumSize || len(packet) < hdrLen || totalLen < hdrLen {
		return
	}
	if totalLen > len(packet) {
		totalLen = len(packet)
	}
	oldAddr := [4]byte(packet[offset : offset+4])
	newBytes := newAddr.As4()
	if oldAddr == newBytes {
		return
	}
	copy(packet[offset:offset+4], newBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:hdrLen]))

	// 非首片不含 L4 首部。
	if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
		return
	}
	l4 := packet[hdrLen:totalLen]
	switch packet[9] {
	case uint8(header.TCPProtocolNumber):
		adjustChecksumAt(l4, 16, oldAddr[:], newBytes[:], false)
	case uint8(header.UDPProtocolNumber):
		adjustChecksumAt(l4, 6, oldAddr[:], newBytes[:], true)
	case uint8(header.ICMPv4ProtocolNumber):
		if len(l4) < header.ICMPv4MinimumSize+header.IPv4MinimumSize || !isICMPv4Error(l4[0]) {
			return
		}
		inner := l4[header.ICMPv4MinimumSize:]
		// 外层源地址改写 ↔ 内嵌目的地址；外层目的地址改写 ↔ 内嵌源地址。
		innerOffset := 12
		if offset == 12 {
			innerOffset = 16
		}
		if !rewriteInnerIPv4(inner, innerOffset, oldAddr, newBytes) {
			return
		}
		binary.BigEndian.PutUint16(l4[2:4], 0)
		binary.BigEndian.PutUint16(l4[2:4], checksum(l4))
	}
}

func rewriteInnerIPv4(inner []byte, offset int, oldAddr, newAddr [4]byte) bool {
	if header.IPVersion(inner) != header.IPv4Version || len(inner) < header.IPv4MinimumSize {
		return false
	}
	innerHdrLen := int(inner[0]&0x0f) * 4
	if innerHdrLen < header.IPv4MinimumSize || len(inner) < innerHdrLen {
		return false
	}
	if [4]byte(inner[offset:offset+4]) != oldAddr {
		return false
	}
	copy(inner[offset:offset+4], newAddr[:])
	binary.BigEndian.PutUint16(inner[10:12], 0)
	binary.BigEndian.PutUint16(inner[10:12], checksum(inner[:innerHdrLen]))
	if binary.BigEndian.Uint16(inner[6:8])&0x1fff == 0 {
		innerL4 := inner[innerHdrLen:]
		switch inner[9] {
		case uint8(header.TCPProtocolNumber):
			adjustChecksumAt(innerL4, 16, oldAddr[:], newAddr[:], false)
		case uint8(header.UDPProtocolNumber):
			adjustChecksumAt(innerL4, 6, oldAddr[:], newAddr[:], true)
		}
	}
	return true
}

func rewriteIPv6Address(packet []byte, offset int, newAddr netip.Addr) {
	if !newAddr.IsValid() || !newAddr.Is6() {
		return
	}
	if header.IPVersion(packet) != header.IPv6Version || len(packet) < header.IPv6MinimumSize {
		return
	}
	oldAddr := [16]byte(packet[offset : offset+16])
	newBytes := newAddr.As16()
	if oldAddr == newBytes {
		return
	}
	copy(packet[offset:offset+16], newBytes[:])

	proto, l4Offset, isFragNonFirst := findIPv6L4Header(packet)
	if isFragNonFirst || l4Offset == 0 || l4Offset >= len(packet) {
		return
	}
	end := header.IPv6MinimumSize + int(binary.BigEndian.Uint16(packet[4:6]))
	if end > len(packet) || end < l4Offset {
		end = len(packet)
	}
	l4 := packet[l4Offset:end]
	switch proto {
	case uint8(header.TCPProtocolNumber):
		adjustChecksumAt(l4, 16, oldAddr[:], newBytes[:], false)
	case uint8(header.UDPProtocolNumber):
		// IPv6 下 UDP 校验和是强制的，0 也按普通值处理。
		adjustChecksumAt(l4, 6, oldAddr[:], newBytes[:], false)
	case uint8(header.ICMPv6ProtocolNumber):
		if len(l4) < header.ICMPv6MinimumSize {
			return
		}
		innerOffset := 8
		if offset == 8 {
			innerOffset = 24
		}
		if isICMPv6Error(l4[0]) && len(l4) >= header.ICMPv6MinimumSize+header.IPv6MinimumSize &&
			rewriteInnerIPv6(l4[header.ICMPv6MinimumSize:], innerOffset, oldAddr, newBytes) {
			// 内嵌报文改动较多，直接按新的伪首部重算整个 ICMPv6 校验和。
			binary.BigEndian.PutUint16(l4[2:4], 0)
			binary.BigEndian.PutUint16(l4[2:4], ipv6PseudoChecksum(packet[8:24], packet[24:40], uint8(header.ICMPv6ProtocolNumber), l4))
			return
		}
		adjustChecksumAt(l4, 2, oldAddr[:], newBytes[:], false)
	}
}

func rewriteInnerIPv6(inner []byte, offset int, oldAddr, newAddr [16]byte) bool {
	if header.IPVersion(inner) != header.IPv6Version || len(inner) < header.IPv6MinimumSize {
		return false
	}
	if [16]byte(inner[offset:offset+16]) != oldAddr {
		return false
	}
	copy(inner[offset:offset+16], newAddr[:])
	proto, l4Offset, isFragNonFirst := findIPv6L4Header(inner)
	if !isFragNonFirst && l4Offset > 0 && l4Offset < len(inner) {
		innerL4 := inner[l4Offset:]
		switch proto {
		case uint8(header.TCPProtocolNumber):
			adjustChecksumAt(innerL4, 16, oldAddr[:], newAddr[:], false)
		case uint8(header.UDPProtocolNumber):
			adjustChecksumAt(innerL4, 6, oldAddr[:], newAddr[:], false)
		case uint8(header.ICMPv6ProtocolNumber):
			adjustChecksumAt(innerL4, 2, oldAddr[:], newAddr[:], false)
		}
	}
	return true
}

// adjustChecksumAt 按 RFC 1624 为伪首部中地址的变化增量修正 l4[at:at+2] 处的校验和。
// 截断的报文（ICMP 差错内嵌）只要校验和字段在范围内就能修正：增量更新与载荷是否完整无关。
// udpZeroMeansNone 用于 IPv4 UDP：校验和为 0 表示未启用，保持为 0。
func adjustChecksumAt(l4 []byte, at int, oldAddr, newAddr []byte, udpZeroMeansNone bool) {
	if len(l4) < at+2 {
		return
	}
	csum := binary.BigEndian.Uint16(l4[at : at+2])
	if udpZeroMeansNone && csum == 0 {
		return
	}
	for i := 0; i+1 < len(oldAddr); i += 2 {
		csum = updateChecksumRFC1624(csum, binary.BigEndian.Uint16(oldAddr[i:i+2]), binary.BigEndian.Uint16(newAddr[i:i+2]))
	}
	if udpZeroMeansNone && csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[at:at+2], csum)
}

func ipv6PseudoChecksum(src, dst []byte, nextHeader uint8, payload []byte) uint16 {
	var sum uint32
	addWords := func(data []byte) {
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}
	addWords(src)
	addWords(dst)
	length := uint32(len(payload))
	sum += length >> 16
	sum += length & 0xffff
	sum += uint32(nextHeader)
	addWords(payload)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
