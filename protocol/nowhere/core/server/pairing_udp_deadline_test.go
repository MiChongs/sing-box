package server

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestTCPUDPUplinkReadDeadline(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	uplink := newTCPUDPUplink(server)
	defer uplink.Close()
	conn := newPairedUDPConn(&pairedUDP{Uplink: uplink, Target: wire.Target{Type: wire.TargetTypeIPv4, Port: 53}})
	defer conn.Close()

	// A sniff-style read with nothing on the wire must time out instead of
	// blocking forever.
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	buffer := make([]byte, 2048)
	_, _, err := conn.ReadFrom(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("deadline honoured too late: %v", elapsed)
	}

	// The deadline expiring while a frame is half written must not
	// desynchronise the UoT framing.
	frame := []byte{0, 5, 'h', 'e', 'l', 'l', 'o'}
	writeDone := make(chan error, 1)
	go func() {
		if _, err := client.Write(frame[:3]); err != nil {
			writeDone <- err
			return
		}
		time.Sleep(150 * time.Millisecond)
		_, err := client.Write(frame[3:])
		writeDone <- err
	}()
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = conn.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error on partial frame, got %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "hello" {
		t.Fatalf("unexpected payload %q", got)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	go func() { _ = wire.WriteUDPPacket(client, []byte("again")) }()
	n, _, err = conn.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "again" {
		t.Fatalf("unexpected second read %q %v", buffer[:n], err)
	}
}

func TestTCPUDPUplinkEOFAndClose(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	uplink := newTCPUDPUplink(server)
	go func() { _ = client.Close() }()
	if _, err := uplink.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	// Errors are sticky for later readers.
	if _, err := uplink.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected sticky EOF, got %v", err)
	}

	client, server = net.Pipe()
	defer client.Close()
	uplink = newTCPUDPUplink(server)
	readErr := make(chan error, 1)
	go func() {
		_, err := uplink.ReadPacket()
		readErr <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = uplink.Close()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not return after Close")
	}
}
