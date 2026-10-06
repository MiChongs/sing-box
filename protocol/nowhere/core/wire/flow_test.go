package wire

import (
	"bytes"
	"testing"
)

func TestFlowHeaderFixedVectors(t *testing.T) {
	cases := []struct {
		name   string
		header FlowHeader
		want   [FlowHeaderLen]byte
	}{
		{
			"duplex-tcp-tls-tls",
			FlowHeader{Role: FlowRoleDuplex, FlowID: 0x01020304, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP},
			[FlowHeaderLen]byte{0x00, 1, 2, 3, 4},
		},
		{
			"open-udp-quic-tcp",
			FlowHeader{Role: FlowRoleOpen, FlowID: 0x11223344, Kind: FlowKindUDP, Uplink: CarrierQUIC, Downlink: CarrierTLSTCP},
			[FlowHeaderLen]byte{0x0d, 0x11, 0x22, 0x33, 0x44},
		},
		{
			"attach-udp-tcp-quic",
			FlowHeader{Role: FlowRoleAttach, FlowID: 7, Kind: FlowKindUDP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC},
			[FlowHeaderLen]byte{0x16, 0, 0, 0, 7},
		},
		{
			"duplex-udp-quic-quic",
			FlowHeader{Role: FlowRoleDuplex, FlowID: 0x01020304, Kind: FlowKindUDP, Uplink: CarrierQUIC, Downlink: CarrierQUIC},
			[FlowHeaderLen]byte{0x1c, 1, 2, 3, 4},
		},
		{
			"duplex-tcp-max-hops",
			FlowHeader{Role: FlowRoleDuplex, FlowID: 0x01020304, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP, Hops: MaxPortalHops},
			[FlowHeaderLen]byte{0xe0, 1, 2, 3, 4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WriteFlowHeader(tc.header)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(got[:], tc.want[:]) {
				t.Fatalf("header mismatch\n got %x\nwant %x", got[:], tc.want[:])
			}
			decoded, err := DecodeFlowHeader(got[:])
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded != tc.header {
				t.Fatalf("decoded mismatch\n got %+v\nwant %+v", decoded, tc.header)
			}
		})
	}
}

func TestFlowHeaderRejectsInvalid(t *testing.T) {
	invalids := [][]byte{
		{},                          // empty
		{0, 0, 0, 0},                // short
		{0, 0, 0, 0, 0, 0},          // long
		{0, 0, 0, 0, 0},             // zero flow id
		{0x03, 0, 0, 0, 1},          // invalid role
		{0x10, 0, 0, 0, 1},          // duplex carrier mismatch
		{0, 0x40, 0, 0, 0},          // flow id exceeds 30 bits
		{0, 0xff, 0xff, 0xff, 0xff}, // u32 max
	}
	for _, frame := range invalids {
		if _, err := DecodeFlowHeader(frame); err == nil {
			t.Fatalf("expected decode error for %x", frame)
		}
	}
}

func TestFlowHeaderAllPortalHopBudgetsRoundTrip(t *testing.T) {
	for hops := uint8(0); hops <= MaxPortalHops; hops++ {
		header := FlowHeader{
			Role: FlowRoleDuplex, FlowID: 42, Kind: FlowKindTCP,
			Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP, Hops: hops,
		}
		encoded, err := WriteFlowHeader(header)
		if err != nil {
			t.Fatalf("hops=%d encode: %v", hops, err)
		}
		if got := encoded[0] >> flowHopsShift; got != hops {
			t.Fatalf("hops=%d encoded=%d", hops, got)
		}
		decoded, err := DecodeFlowHeader(encoded[:])
		if err != nil {
			t.Fatalf("hops=%d decode: %v", hops, err)
		}
		if decoded != header {
			t.Fatalf("hops=%d decoded mismatch: got %+v want %+v", hops, decoded, header)
		}
	}
}

func TestFlowHeaderRejectsHopBudgetAboveMaximum(t *testing.T) {
	header := FlowHeader{
		Role: FlowRoleDuplex, FlowID: 1, Kind: FlowKindTCP,
		Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP, Hops: MaxPortalHops + 1,
	}
	if _, err := WriteFlowHeader(header); err == nil {
		t.Fatal("expected excessive hop budget to fail")
	}
}

func TestFlowHeaderAllowsOpenAttachWithEqualCarriers(t *testing.T) {
	open := FlowHeader{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP}
	encoded, err := WriteFlowHeader(open)
	if err != nil {
		t.Fatalf("open equal carriers: %v", err)
	}
	if encoded[0] != 0x01 {
		t.Fatalf("open flags=%x want 0x01", encoded[0])
	}
	attach := FlowHeader{Role: FlowRoleAttach, FlowID: 1, Kind: FlowKindUDP, Uplink: CarrierQUIC, Downlink: CarrierQUIC}
	if _, err := WriteFlowHeader(attach); err != nil {
		t.Fatalf("attach equal carriers: %v", err)
	}
}

func TestFlowHeaderValidateOnCarrier(t *testing.T) {
	open := FlowHeader{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC}
	if err := open.ValidateOn(CarrierTLSTCP); err != nil {
		t.Fatalf("open on uplink carrier: %v", err)
	}
	if err := open.ValidateOn(CarrierQUIC); err == nil {
		t.Fatal("open accepted on downlink carrier")
	}
	attach := FlowHeader{Role: FlowRoleAttach, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC}
	if err := attach.ValidateOn(CarrierQUIC); err != nil {
		t.Fatalf("attach on downlink carrier: %v", err)
	}
	if err := attach.ValidateOn(CarrierTLSTCP); err == nil {
		t.Fatal("attach accepted on uplink carrier")
	}
	if open.CarriesTarget() != true {
		t.Fatal("open must carry target")
	}
	if attach.CarriesTarget() {
		t.Fatal("attach must not carry target")
	}
}

func TestFlowHeaderMaxFlowIDRoundTrips(t *testing.T) {
	header := FlowHeader{Role: FlowRoleDuplex, FlowID: MaxFlowID, Kind: FlowKindTCP, Uplink: CarrierQUIC, Downlink: CarrierQUIC}
	encoded, err := WriteFlowHeader(header)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeFlowHeader(encoded[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != header {
		t.Fatalf("decoded mismatch\n got %+v\nwant %+v", decoded, header)
	}
}
