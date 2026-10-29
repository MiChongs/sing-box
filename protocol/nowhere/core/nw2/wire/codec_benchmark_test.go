package wire

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

var (
	benchmarkBytes   []byte
	benchmarkTarget  Target
	benchmarkFlow    FlowHeader
	benchmarkSession SessionID
	benchmarkOutcome ReassemblyOutcome
)

func benchmarkSizes() []struct {
	name string
	size int
} {
	return []struct {
		name string
		size int
	}{
		{name: "empty", size: 0},
		{name: "64B", size: 64},
		{name: "1200B", size: 1200},
		{name: "64KiB", size: UDPPacketMax},
	}
}

func BenchmarkAuth(b *testing.B) {
	credentials, err := NewCredentials("benchmark secret")
	if err != nil {
		b.Fatal(err)
	}
	var exporter TLSExporter
	var sessionID SessionID
	for i := range exporter {
		exporter[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(255 - i)
	}
	frame, err := EncodeAuthFrame(credentials, AuthTransportQUIC, exporter, sessionID)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := EncodeAuthFrame(credentials, AuthTransportQUIC, exporter, sessionID)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkBytes = got[:]
		}
	})
	b.Run("validate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := ValidateAuthFrame(frame[:], credentials, AuthTransportQUIC, exporter)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkSession = got
		}
	})
}

func BenchmarkFLOW(b *testing.B) {
	header := FlowHeader{
		Role: FlowRoleOpen, FlowID: 42, Kind: FlowKindTCP,
		Uplink: CarrierQUIC, Downlink: CarrierTLSTCP,
	}
	encoded, err := EncodeFlowHeader(header)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := EncodeFlowHeader(header)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkBytes = got
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := DecodeFlowHeader(encoded)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkFlow = got
		}
	})
}

func BenchmarkTarget(b *testing.B) {
	ipv4, _ := NewIPTarget(netip.MustParseAddr("192.0.2.1"), 443)
	ipv6, _ := NewIPTarget(netip.MustParseAddr("2001:db8::1"), 443)
	domain, _ := NewDomainTarget("benchmark.example", 443)
	for _, test := range []struct {
		name   string
		target Target
	}{
		{name: "ipv4", target: ipv4},
		{name: "ipv6", target: ipv6},
		{name: "domain", target: domain},
	} {
		encoded, err := EncodeTarget(test.target)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name+"/encode", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				got, err := EncodeTarget(test.target)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = got
			}
		})
		b.Run(test.name+"/decode", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				got, _, err := DecodeTarget(encoded)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkTarget = got
			}
		})
	}
}

func BenchmarkUoT(b *testing.B) {
	for _, test := range benchmarkSizes() {
		payload := make([]byte, test.size)
		encoded, err := EncodeUDPPacket(payload)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name+"/encode", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				got, err := EncodeUDPPacket(payload)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = got
			}
		})
		b.Run(test.name+"/decode", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				got, err := ReadUDPPacket(bytes.NewReader(encoded))
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = got
			}
		})
	}
}

func BenchmarkDATAGRAM(b *testing.B) {
	for _, test := range benchmarkSizes() {
		payload := make([]byte, test.size)
		encoded, err := EncodeUDPData(1, payload)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name+"/encode", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				got, err := EncodeUDPData(1, payload)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = got
			}
		})
		b.Run(test.name+"/decode", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				got, err := DecodeUDPFrame(encoded)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkBytes = got.Payload
			}
		})
	}
}

func BenchmarkFragmentPlanning(b *testing.B) {
	for _, test := range benchmarkSizes() {
		payload := make([]byte, test.size)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				err := EncodeUDPDataFragmentsYield(1, 1, payload, 1200, func(frame []byte) error {
					benchmarkBytes = frame
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReassembly(b *testing.B) {
	for _, test := range benchmarkSizes()[1:] {
		payload := make([]byte, test.size)
		maxDatagramSize := 300
		if test.size == 64 {
			maxDatagramSize = 40
		} else if test.size == 1200 {
			maxDatagramSize = 100
		}
		frames, err := EncodeUDPDataFragments(1, 1, payload, maxDatagramSize)
		if err != nil {
			b.Fatal(err)
		}
		fragments := make([]UDPFragment, len(frames))
		for i, frame := range frames {
			decoded, err := DecodeUDPFrame(frame)
			if err != nil {
				b.Fatal(err)
			}
			fragments[i] = decoded.Fragment
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(test.size))
			for i := 0; i < b.N; i++ {
				reassembler, err := NewDatagramReassembler(DefaultReassemblyConfig())
				if err != nil {
					b.Fatal(err)
				}
				for _, fragment := range fragments {
					benchmarkOutcome = reassembler.Push(1, fragment, time.Unix(0, 0))
				}
				if !benchmarkOutcome.Done {
					b.Fatal("packet did not reassemble")
				}
			}
		})
	}
}

func TestCodecAllocationCeilings(t *testing.T) {
	// Ceilings are the Go 1.20/linux/amd64 baseline plus
	// max(1 allocation, 10%); timing is intentionally not gated.
	credentials, err := NewCredentials("allocation secret")
	if err != nil {
		t.Fatal(err)
	}
	var exporter TLSExporter
	var sessionID SessionID
	auth, err := EncodeAuthFrame(credentials, AuthTransportQUIC, exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	flow := FlowHeader{
		Role: FlowRoleDuplex, FlowID: 1, Kind: FlowKindTCP,
		Uplink: CarrierQUIC, Downlink: CarrierQUIC,
	}
	flowBytes, _ := EncodeFlowHeader(flow)
	domain, _ := NewDomainTarget("allocation.example", 443)
	domainBytes, _ := EncodeTarget(domain)
	payload := make([]byte, 1200)
	uotBytes, _ := EncodeUDPPacket(payload)
	dataBytes, _ := EncodeUDPData(1, payload)
	largePayload := make([]byte, UDPPacketMax)
	largeFrames, err := EncodeUDPDataFragments(1, 1, largePayload, 300)
	if err != nil {
		t.Fatal(err)
	}
	largeFragments := make([]UDPFragment, len(largeFrames))
	for i, frame := range largeFrames {
		decoded, err := DecodeUDPFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		largeFragments[i] = decoded.Fragment
	}

	checks := []struct {
		name    string
		ceiling float64
		run     func()
	}{
		{name: "auth_encode", ceiling: 12.1, run: func() {
			frame, err := EncodeAuthFrame(credentials, AuthTransportQUIC, exporter, sessionID)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = frame[:]
		}},
		{name: "auth_validate", ceiling: 11, run: func() {
			got, err := ValidateAuthFrame(auth[:], credentials, AuthTransportQUIC, exporter)
			if err != nil {
				panic(err)
			}
			benchmarkSession = got
		}},
		{name: "flow_encode", ceiling: 2, run: func() {
			got, err := EncodeFlowHeader(flow)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got
		}},
		{name: "flow_decode", ceiling: 1, run: func() {
			got, err := DecodeFlowHeader(flowBytes)
			if err != nil {
				panic(err)
			}
			benchmarkFlow = got
		}},
		{name: "domain_encode", ceiling: 2, run: func() {
			got, err := EncodeTarget(domain)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got
		}},
		{name: "domain_decode", ceiling: 2, run: func() {
			got, _, err := DecodeTarget(domainBytes)
			if err != nil {
				panic(err)
			}
			benchmarkTarget = got
		}},
		{name: "uot_encode_1200", ceiling: 2, run: func() {
			got, err := EncodeUDPPacket(payload)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got
		}},
		{name: "uot_decode_1200", ceiling: 5, run: func() {
			got, err := ReadUDPPacket(bytes.NewReader(uotBytes))
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got
		}},
		{name: "datagram_encode_1200", ceiling: 2, run: func() {
			got, err := EncodeUDPData(1, payload)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got
		}},
		{name: "datagram_decode_1200", ceiling: 1, run: func() {
			got, err := DecodeUDPFrame(dataBytes)
			if err != nil {
				panic(err)
			}
			benchmarkBytes = got.Payload
		}},
		{name: "fragment_plan_64KiB", ceiling: 61.6, run: func() {
			err := EncodeUDPDataFragmentsYield(1, 1, largePayload, 1200, func(frame []byte) error {
				benchmarkBytes = frame
				return nil
			})
			if err != nil {
				panic(err)
			}
		}},
		{name: "reassembly_64KiB", ceiling: 258.5, run: func() {
			reassembler, err := NewDatagramReassembler(DefaultReassemblyConfig())
			if err != nil {
				panic(err)
			}
			for _, fragment := range largeFragments {
				benchmarkOutcome = reassembler.Push(1, fragment, time.Unix(0, 0))
			}
			if !benchmarkOutcome.Done {
				panic("packet did not reassemble")
			}
		}},
	}
	for _, check := range checks {
		allocs := testing.AllocsPerRun(100, check.run)
		t.Logf("%s allocations/op = %.1f", check.name, allocs)
		if allocs > check.ceiling {
			t.Fatalf("%s allocations/op = %.1f, ceiling %.1f", check.name, allocs, check.ceiling)
		}
	}
}
