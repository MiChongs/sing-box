package wire

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestTargetFixedVectors(t *testing.T) {
	ipv4Addr := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	ipv4, err := NewIPTarget(ipv4Addr, 443)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeTarget(ipv4)
	if err != nil {
		t.Fatal(err)
	}
	wantIPv4 := []byte{0x01, 192, 0, 2, 1, 0x01, 0xbb}
	if !bytes.Equal(got, wantIPv4) {
		t.Fatalf("ipv4 mismatch\n got %x\nwant %x", got, wantIPv4)
	}

	v6raw := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv6, err := NewIPTarget(netip.AddrFrom16(v6raw), 53)
	if err != nil {
		t.Fatal(err)
	}
	got, err = EncodeTarget(ipv6)
	if err != nil {
		t.Fatal(err)
	}
	wantIPv6 := []byte{0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53}
	if !bytes.Equal(got, wantIPv6) {
		t.Fatalf("ipv6 mismatch\n got %x\nwant %x", got, wantIPv6)
	}

	domain, err := NewDomainTarget("xn--bcher-kva.example", 8080)
	if err != nil {
		t.Fatal(err)
	}
	got, err = EncodeTarget(domain)
	if err != nil {
		t.Fatal(err)
	}
	wantDomain := append([]byte{0x03, 21}, []byte("xn--bcher-kva.example")...)
	wantDomain = append(wantDomain, 0x1f, 0x90)
	if !bytes.Equal(got, wantDomain) {
		t.Fatalf("domain mismatch\n got %x\nwant %x", got, wantDomain)
	}
}

func TestTargetRoundTrip(t *testing.T) {
	cases := []Target{
		mustIPv4("127.0.0.1", 80),
		mustIPv6("2001:db8::5", 65535),
		mustDomain(t, "example.com", 443),
	}
	for _, target := range cases {
		encoded, err := EncodeTarget(target)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		decoded, consumed, err := DecodeTarget(encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if consumed != len(encoded) {
			t.Fatalf("consumed %d want %d", consumed, len(encoded))
		}
		if !testTargetsEqual(decoded, target) {
			t.Fatalf("mismatch\n got  %+v\nwant %+v", decoded, target)
		}
	}
}

// testTargetsEqual compares two targets field-by-field for test assertions.
func testTargetsEqual(a, b Target) bool {
	if a.Type != b.Type || a.Port != b.Port || a.Host != b.Host {
		return false
	}
	if a.Type == TargetTypeDomain {
		return true
	}
	return a.Addr == b.Addr
}

func TestTargetRejectsInvalid(t *testing.T) {
	// constructor rejects
	if _, err := NewIPTarget(netip.Addr{}, 80); err == nil {
		t.Fatal("invalid ip accepted")
	}
	if _, err := NewDomainTarget("example.com", 0); err == nil {
		t.Fatal("zero port accepted")
	}
	for _, bad := range []string{
		"", "bad host", "bad:host", "bad[host]", "bad/host", "bad@host",
		"bad..host", "-bad.host", "bad-.host", "bad.host.", "bad.host\n",
	} {
		if _, err := NewDomainTarget(bad, 443); err == nil {
			t.Fatalf("domain %q accepted", bad)
		}
	}
	// oversize domain
	long := makeDomain(64, "example")
	if _, err := NewDomainTarget(long, 443); err == nil {
		t.Fatal("oversize domain accepted")
	}

	// decode rejects
	rejects := [][]byte{
		{},
		{0x02, 1, 2, 3, 4, 0, 80},  // unknown atyp
		{0x01, 127, 0, 0, 1},       // truncated ipv4
		{0x01, 127, 0, 0, 1, 0, 0}, // zero port
		make([]byte, 18),           // truncated ipv6 (fill 0x04)
		{0x03},                     // domain no length
		{0x03, 0, 0, 80},           // domain zero length
		{0x03, 3, 'a', 'b', 0, 80}, // truncated domain
		{0x03, 1, 0xff, 0, 80},     // bad label
		{0x03, 1, 'a', 0, 0},       // zero port
	}
	rejects[4][0] = 0x04 // mark as ipv6 atyp
	for _, raw := range rejects {
		if _, _, err := DecodeTarget(raw); err == nil {
			t.Fatalf("expected decode error for %x", raw)
		}
	}
}

func TestTargetMaxDomainAccepted(t *testing.T) {
	host := makeMaxDomain(253)
	if len(host) != 253 {
		t.Fatalf("host len %d", len(host))
	}
	target, err := NewDomainTarget(host, 1)
	if err != nil {
		t.Fatalf("max domain rejected: %v", err)
	}
	encoded, err := EncodeTarget(target)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[1] != 253 {
		t.Fatalf("domain length byte %d want 253", encoded[1])
	}
}

func mustIPv4(s string, port uint16) Target {
	addr, _ := netip.ParseAddr(s)
	t, _ := NewIPTarget(addr, port)
	return t
}

func mustIPv6(s string, port uint16) Target {
	addr, _ := netip.ParseAddr(s)
	t, _ := NewIPTarget(addr, port)
	return t
}

func mustDomain(t *testing.T, host string, port uint16) Target {
	target, err := NewDomainTarget(host, port)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func makeDomain(labelLen int, suffix string) string {
	label := make([]byte, labelLen)
	for i := range label {
		label[i] = 'a'
	}
	return string(label) + "." + suffix
}

// makeMaxDomain builds a 253-byte ASCII domain: 63.63.63.61 labels.
func makeMaxDomain(total int) string {
	out := make([]byte, 0, total)
	for _, n := range []int{63, 63, 63, 61} {
		label := make([]byte, n)
		for i := range label {
			label[i] = 'a'
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		out = append(out, label...)
	}
	return string(out)
}
