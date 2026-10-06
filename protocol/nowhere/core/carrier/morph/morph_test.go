package morph

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/chacha20"
)

func TestDeriveMatchesRustFixedVectors(t *testing.T) {
	keys := Derive([]byte("test portal key"))
	wantC2S, _ := hex.DecodeString("90df47db82553ab6b0489ea77a085593475a70c6a61e957ad3ffe0824bd2126a")
	wantS2C, _ := hex.DecodeString("20bc17a22d08469e60efd4c6bdda76f190c33946599a0797bab2d52007b97e27")
	wantUDPC2S, _ := hex.DecodeString("6837a1f0de5a70baf35de9ba7a77174a665d577bde4000386ddf0e5206b56773")
	wantUDPS2C, _ := hex.DecodeString("798c97f634139bb467919fbbcd705e0eeffe9294164981dc34a72e274d449b79")
	if !bytes.Equal(keys.TCPC2S[:], wantC2S) {
		t.Fatalf("tcp c2s\n got %x\nwant %x", keys.TCPC2S[:], wantC2S)
	}
	if !bytes.Equal(keys.TCPS2C[:], wantS2C) {
		t.Fatalf("tcp s2c\n got %x\nwant %x", keys.TCPS2C[:], wantS2C)
	}
	if !bytes.Equal(keys.UDPC2S[:], wantUDPC2S) {
		t.Fatalf("udp c2s\n got %x\nwant %x", keys.UDPC2S[:], wantUDPC2S)
	}
	if !bytes.Equal(keys.UDPS2C[:], wantUDPS2C) {
		t.Fatalf("udp s2c\n got %x\nwant %x", keys.UDPS2C[:], wantUDPS2C)
	}
}

func TestPreludePolicyFromEnv(t *testing.T) {
	cases := []struct {
		value  string
		want   preludePolicy
		wantEr bool
	}{
		{value: "", want: preludeLow7},
		{value: "low7", want: preludeLow7},
		{value: "full8", want: preludeFull8},
		{value: "bogus", wantEr: true},
	}
	for _, tc := range cases {
		t.Setenv(preludeEnv, tc.value)
		got, err := preludePolicyFromEnv()
		if tc.wantEr {
			if err == nil {
				t.Fatalf("policy %q: want error", tc.value)
			}
			continue
		}
		if err != nil {
			t.Fatalf("policy %q: %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("policy %q = %d, want %d", tc.value, got, tc.want)
		}
	}
}

func TestGeneratePreludeLow7ClearsHighBits(t *testing.T) {
	for i := 0; i < 8; i++ {
		prelude, err := generatePrelude(preludeLow7)
		if err != nil {
			t.Fatal(err)
		}
		for index, b := range prelude {
			if b&0x80 != 0 {
				t.Fatalf("low7 prelude byte %d = %#x has high bit set", index, b)
			}
		}
	}
}

func TestTCPPreludeWireImage(t *testing.T) {
	keys := Derive([]byte("secret"))
	left, right := net.Pipe()
	client, err := WrapTCPClient(left, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = right.Close()
	})
	payload := bytes.Repeat([]byte("nw2-morph"), 40)
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errCh <- err
	}()

	// The bootstrap is exactly 64 prelude bytes plus a 12-byte nonce. The
	// low7 policy keeps every prelude byte inside seven bits.
	bootstrap := make([]byte, preludeLen+nonceLen)
	if _, err := io.ReadFull(right, bootstrap); err != nil {
		t.Fatal(err)
	}
	for index, b := range bootstrap[:preludeLen] {
		if b&0x80 != 0 {
			t.Fatalf("prelude byte %d = %#x has high bit set", index, b)
		}
	}
	var nonce [nonceLen]byte
	copy(nonce[:], bootstrap[preludeLen:])

	wire := make([]byte, len(payload))
	if _, err := io.ReadFull(right, wire); err != nil {
		t.Fatal(err)
	}
	chacha20.XORKeyStreamAt(wire, wire, &keys.TCPC2S, &nonce, 0)
	if !bytes.Equal(wire, payload) {
		t.Fatal("client-to-server payload mismatch after bootstrap")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestTCPRoundTrip(t *testing.T) {
	keys := Derive([]byte("secret"))
	left, right := net.Pipe()
	client, err := WrapTCPClient(left, keys)
	if err != nil {
		t.Fatal(err)
	}
	server := WrapTCPServer(right, keys)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	payload := bytes.Repeat([]byte("nw2-morph"), 40)
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errCh <- err
	}()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("server read mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	go func() {
		_, err := server.Write(payload)
		errCh <- err
	}()
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("client read mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestUDPRoundTripDirectional(t *testing.T) {
	keys := Derive([]byte("secret"))
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientPC.Close()
		_ = serverPC.Close()
	})
	client := WrapPacketConn(clientPC, keys, true)
	server := WrapPacketConn(serverPC, keys, false)
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	payload := []byte("datagram")
	if _, err := client.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 32)
	n, addr, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("client->server = %q", got[:n])
	}
	if _, err := server.WriteTo(payload, addr); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("server->client = %q", got[:n])
	}
}

func TestUDPMismatchedRolesDoNotDecrypt(t *testing.T) {
	keys := Derive([]byte("secret"))
	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	// Both ends acting as the client role means the receiver applies udp s2c
	// to a datagram sealed under udp c2s; the payload must not round-trip.
	sender := WrapPacketConn(first, keys, true)
	receiver := WrapPacketConn(second, keys, true)
	deadline := time.Now().Add(2 * time.Second)
	_ = sender.SetDeadline(deadline)
	_ = receiver.SetDeadline(deadline)

	payload := bytes.Repeat([]byte{0xa5}, 64)
	if _, err := sender.WriteTo(payload, receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	n, _, err := receiver.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("short read: %d", n)
	}
	if bytes.Equal(got, payload) {
		t.Fatal("datagram decrypted with the wrong directional key")
	}
}
