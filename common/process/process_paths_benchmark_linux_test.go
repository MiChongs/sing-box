//go:build linux

package process

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func BenchmarkBuildProcessPathsAllUsers(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := buildProcessPaths(context.Background(), processPathsAllUsers); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildProcessPathsCurrentUser(b *testing.B) {
	uid := uint32(os.Getuid())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := buildProcessPaths(context.Background(), uid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSocketDiagQuery(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	diagConn := &socketDiagConn{family: syscall.AF_INET, protocol: syscall.IPPROTO_TCP, fd: -1}
	defer diagConn.Close()
	source, destination := M.AddrPortFromNet(conn.LocalAddr()), M.AddrPortFromNet(listener.Addr())
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err = diagConn.query(source, destination); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSocketDiagDump(b *testing.B) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	source := M.AddrPortFromNet(conn.LocalAddr())
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err = dumpSocketDiag(syscall.AF_INET, syscall.IPPROTO_UDP, source, netip.AddrPort{}); err != nil {
			b.Fatal(err)
		}
	}
}
