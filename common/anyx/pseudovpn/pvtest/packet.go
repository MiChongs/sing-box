// Package pvtest 为 PseudoVPN 的测试构造 IP 报文并校验校验和，仅供测试使用。
package pvtest

import (
	"encoding/binary"
	"net/netip"
)

const (
	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58

	TCPFlagFin uint8 = 0x01
	TCPFlagSyn uint8 = 0x02
	TCPFlagRst uint8 = 0x04
	TCPFlagPsh uint8 = 0x08
	TCPFlagAck uint8 = 0x10
)

// TCP 构造一个 TCP 报文（地址族由 src 决定）；mss 非零时附带 MSS 选项。
func TCP(src, dst netip.AddrPort, seq, ack uint32, flags uint8, mss uint16, payload []byte) []byte {
	headerLen := 20
	if mss != 0 {
		headerLen += 4
	}
	segment := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], src.Port())
	binary.BigEndian.PutUint16(segment[2:4], dst.Port())
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = uint8(headerLen/4) << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	if mss != 0 {
		segment[20] = 2
		segment[21] = 4
		binary.BigEndian.PutUint16(segment[22:24], mss)
	}
	copy(segment[headerLen:], payload)
	packet := ip(src.Addr(), dst.Addr(), ProtocolTCP, segment)
	fixL4(packet, 16)
	return packet
}

// UDP 构造一个 UDP 报文。
func UDP(src, dst netip.AddrPort, payload []byte) []byte {
	datagram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], src.Port())
	binary.BigEndian.PutUint16(datagram[2:4], dst.Port())
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[8:], payload)
	packet := ip(src.Addr(), dst.Addr(), ProtocolUDP, datagram)
	fixL4(packet, 6)
	return packet
}

// Echo 构造 ICMP / ICMPv6 回显请求（reply 为 true 时为回显应答）。
func Echo(src, dst netip.Addr, id, seq uint16, reply bool, payload []byte) []byte {
	message := make([]byte, 8+len(payload))
	protocol := uint8(ProtocolICMP)
	if src.Is4() {
		message[0] = 8
		if reply {
			message[0] = 0
		}
	} else {
		protocol = ProtocolICMPv6
		message[0] = 128
		if reply {
			message[0] = 129
		}
	}
	binary.BigEndian.PutUint16(message[4:6], id)
	binary.BigEndian.PutUint16(message[6:8], seq)
	copy(message[8:], payload)
	packet := ip(src, dst, protocol, message)
	fixL4(packet, 2)
	return packet
}

func ip(src, dst netip.Addr, protocol uint8, payload []byte) []byte {
	if src.Is4() {
		packet := make([]byte, 20+len(payload))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		packet[8] = 64
		packet[9] = protocol
		s, d := src.As4(), dst.As4()
		copy(packet[12:16], s[:])
		copy(packet[16:20], d[:])
		binary.BigEndian.PutUint16(packet[10:12], fold(sum(packet[:20])))
		copy(packet[20:], payload)
		return packet
	}
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = protocol
	packet[7] = 64
	s, d := src.As16(), dst.As16()
	copy(packet[8:24], s[:])
	copy(packet[24:40], d[:])
	copy(packet[40:], payload)
	return packet
}

func fixL4(packet []byte, at int) {
	l4 := L4(packet)
	binary.BigEndian.PutUint16(l4[at:at+2], 0)
	binary.BigEndian.PutUint16(l4[at:at+2], l4Checksum(packet))
}

// L4 返回报文的传输层部分（不含扩展头的简单报文）。
func L4(packet []byte) []byte {
	if packet[0]>>4 == 4 {
		return packet[int(packet[0]&0x0f)*4 : binary.BigEndian.Uint16(packet[2:4])]
	}
	return packet[40 : 40+int(binary.BigEndian.Uint16(packet[4:6]))]
}

// Protocol 返回传输层协议号。
func Protocol(packet []byte) uint8 {
	if packet[0]>>4 == 4 {
		return packet[9]
	}
	return packet[6]
}

func Source(packet []byte) netip.Addr {
	if packet[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(packet[12:16]))
	}
	return netip.AddrFrom16([16]byte(packet[8:24]))
}

func Destination(packet []byte) netip.Addr {
	if packet[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(packet[16:20]))
	}
	return netip.AddrFrom16([16]byte(packet[24:40]))
}

// Ports 返回 TCP / UDP 的源、目的端口。
func Ports(packet []byte) (uint16, uint16) {
	l4 := L4(packet)
	return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
}

// TCPFlags 返回 TCP 标志位。
func TCPFlags(packet []byte) uint8 {
	return L4(packet)[13]
}

// MSS 返回 TCP SYN 报文的 MSS 选项，没有时返回 0。
func MSS(packet []byte) uint16 {
	segment := L4(packet)
	dataOffset := int(segment[12]>>4) * 4
	for offset := 20; offset+1 < dataOffset; {
		switch segment[offset] {
		case 0:
			return 0
		case 1:
			offset++
			continue
		}
		length := int(segment[offset+1])
		if length < 2 {
			return 0
		}
		if segment[offset] == 2 && length == 4 {
			return binary.BigEndian.Uint16(segment[offset+2 : offset+4])
		}
		offset += length
	}
	return 0
}

// ChecksumsValid 校验 IPv4 首部与传输层（TCP / UDP / ICMP / ICMPv6）校验和。
func ChecksumsValid(packet []byte) bool {
	if packet[0]>>4 == 4 && fold(sum(packet[:int(packet[0]&0x0f)*4])) != 0 {
		return false
	}
	if Protocol(packet) == ProtocolUDP && packet[0]>>4 == 4 && binary.BigEndian.Uint16(L4(packet)[6:8]) == 0 {
		return true
	}
	return l4Checksum(packet) == 0
}

func l4Checksum(packet []byte) uint16 {
	l4 := L4(packet)
	var total uint32
	protocol := Protocol(packet)
	if packet[0]>>4 == 4 {
		if protocol != ProtocolICMP {
			total += sum(packet[12:20])
			total += uint32(protocol) + uint32(len(l4))
		}
	} else {
		total += sum(packet[8:40])
		total += uint32(len(l4)>>16) + uint32(len(l4)&0xffff) + uint32(protocol)
	}
	total += sum(l4)
	return fold(total)
}

func sum(data []byte) uint32 {
	var total uint32
	for i := 0; i+1 < len(data); i += 2 {
		total += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		total += uint32(data[len(data)-1]) << 8
	}
	return total
}

func fold(total uint32) uint16 {
	for total > 0xffff {
		total = (total & 0xffff) + (total >> 16)
	}
	return ^uint16(total)
}

// ICMPType 返回 ICMP / ICMPv6 类型与代码。
func ICMPType(packet []byte) (uint8, uint8) {
	l4 := L4(packet)
	return l4[0], l4[1]
}

// EchoID 返回 ICMP / ICMPv6 回显报文的标识符。
func EchoID(packet []byte) uint16 {
	return binary.BigEndian.Uint16(L4(packet)[4:6])
}

// ICMPError 构造携带 inner 原始报文的目的不可达差错（IPv4 类型 3 代码 3，IPv6 类型 1 代码 4）。
func ICMPError(src, dst netip.Addr, inner []byte) []byte {
	message := make([]byte, 8+len(inner))
	protocol := uint8(ProtocolICMP)
	if src.Is4() {
		message[0], message[1] = 3, 3
	} else {
		protocol = ProtocolICMPv6
		message[0], message[1] = 1, 4
	}
	copy(message[8:], inner)
	packet := ip(src, dst, protocol, message)
	fixL4(packet, 2)
	return packet
}

// Inner 返回 ICMP 差错报文内嵌的原始报文。
func Inner(packet []byte) []byte {
	return L4(packet)[8:]
}
