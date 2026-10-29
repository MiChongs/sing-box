package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Protocol      string `json:"protocol"`
		SharedKey     string `json:"shared_key_text"`
		SaltHex       string `json:"salt_hex"`
		RootHex       string `json:"root_hex"`
		ExporterLabel string `json:"exporter_label"`
		ExporterHex   string `json:"exporter_hex"`
		Auth          []struct {
			Role      string `json:"role"`
			Transport int    `json:"transport"`
			RoleKey   string `json:"role_key_hex"`
			Frame     string `json:"auth_frame_hex"`
		} `json:"auth"`
		FlowStart struct {
			TCP string `json:"tcp_hex"`
			UDP string `json:"udp_hex"`
		} `json:"flow_start"`
		Streams []struct {
			Initiator string `json:"initiator"`
			StreamID  uint64 `json:"stream_id"`
			FlowID    uint32 `json:"flow_id"`
		} `json:"udp_stream_ids"`
		Invalid []uint64        `json:"invalid_stream_ids"`
		Setup   map[string]byte `json:"setup_result"`
		Reg     map[string]byte `json:"registration_result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Protocol != ALPN || doc.ExporterLabel != ExporterLabel {
		t.Fatalf("protocol identity %+v", doc.Protocol)
	}
	salt := sha256.Sum256([]byte("nowhere/nw3/auth-root"))
	if hex.EncodeToString(salt[:]) != doc.SaltHex {
		t.Fatalf("salt %x", salt)
	}
	creds, err := NewCredentials(doc.SharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceKey(doc.SharedKey); err != nil {
		t.Fatal(err)
	}
	root := hmacSHA256(salt[:], []byte(doc.SharedKey))
	if hex.EncodeToString(root[:]) != doc.RootHex {
		t.Fatalf("root %x", root)
	}
	var exporter Exporter
	exp, err := hex.DecodeString(doc.ExporterHex)
	if err != nil || copy(exporter[:], exp) != 32 {
		t.Fatal(err)
	}
	for _, row := range doc.Auth {
		role := RoleVector
		if row.Role == "egress" {
			role = RoleEgress
		}
		key, err := creds.RoleKey(role)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key[:]) != row.RoleKey {
			t.Fatalf("%s key %x", row.Role, key)
		}
		frame, err := EncodeAuthFrame(key, AuthTransport(row.Transport), exporter)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(frame[:]) != row.Frame {
			t.Fatalf("%s/%d frame %x", row.Role, row.Transport, frame)
		}
		got, err := ValidateAuthFrame(frame[:], creds, AuthTransport(row.Transport), exporter)
		if role == RoleEgress && AuthTransport(row.Transport) == AuthTLS {
			if err == nil {
				t.Fatal("egress tag must be rejected on TLS")
			}
			continue
		}
		if err != nil || got != role {
			t.Fatalf("validate %s/%d: %v %v", row.Role, row.Transport, got, err)
		}
	}
	if _, err := ValidateAuthFrame(mustHex(t, doc.Auth[2].Frame), creds, AuthTLS, exporter); err == nil {
		t.Fatal("egress tag must be rejected on TLS")
	}
	tcp, err := ParseFlowStart(mustHex(t, doc.FlowStart.TCP)[0])
	if err != nil || tcp != FlowTCP {
		t.Fatalf("tcp flow start %v %v", tcp, err)
	}
	udp, err := ParseFlowStart(mustHex(t, doc.FlowStart.UDP)[0])
	if err != nil || udp != FlowUDP {
		t.Fatalf("udp flow start %v %v", udp, err)
	}
	for b := 0; b <= 255; b++ {
		kind, err := ParseFlowStart(byte(b))
		if err != nil {
			t.Fatalf("flow start %#x: %v", b, err)
		}
		want := FlowTCP
		if b%2 != 0 {
			want = FlowUDP
		}
		if kind != want {
			t.Fatalf("flow start %#x = %v, want %v", b, kind, want)
		}
		rest := []byte{byte(b), 0x03}
		got, ok, err := ReadFlowStart(bytes.NewReader(rest))
		if err != nil || !ok || got != want {
			t.Fatalf("read flow start %#x: %v %v %v", b, got, ok, err)
		}
	}
	if _, ok, err := ReadFlowStart(bytes.NewReader(nil)); err != nil || ok {
		t.Fatal("empty flow start is not an auth-only fin")
	}
	for _, row := range doc.Streams {
		id, err := UDPFlowID(row.StreamID, row.Initiator == "server")
		if err != nil || id != row.FlowID {
			t.Fatalf("stream %d: %d %v", row.StreamID, id, err)
		}
	}
	for _, id := range doc.Invalid {
		if _, err := UDPFlowID(id, false); err == nil {
			if _, err2 := UDPFlowID(id, true); err2 == nil {
				t.Fatalf("invalid stream %d accepted", id)
			}
		}
	}
	if doc.Setup["FLOW_LIMIT"] != byte(SetupFlowLimit) || doc.Setup["READY"] != byte(SetupReady) {
		t.Fatalf("setup %#v", doc.Setup)
	}
	if doc.Reg["ACCEPTED"] != byte(RegistrationAccepted) || doc.Reg["BUSY"] != byte(RegistrationBusy) {
		t.Fatalf("registration %#v", doc.Reg)
	}
	target, err := NewIPTarget(netip.MustParseAddr("127.0.0.1"), 443)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := AppendTarget([]byte{0x00}, target)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}
	if !bytes.Equal(buf, want) {
		t.Fatalf("target %x", buf)
	}
	kind, gotTarget, ok, err := ReadFlowRequest(bytes.NewReader(buf))
	if err != nil || !ok || kind != FlowTCP || gotTarget.HostPort() != "127.0.0.1:443" {
		t.Fatalf("read request %v %v %v %v", kind, gotTarget, ok, err)
	}
	payload := bytes.Repeat([]byte("abcdef"), 4)
	frames, err := EncodePacket(2, 7, payload, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatal("expected fragments")
	}
	re := NewReassembler(64, 1<<20, 0)
	var complete []byte
	for i, frame := range frames {
		d, err := DecodeDatagram(frame)
		if err != nil {
			t.Fatal(err)
		}
		if i == len(frames)-1 {
			// deliver out of order: push last first by rotating below
		}
		_ = d
	}
	order := []int{len(frames) - 1, 0}
	for i := 1; i < len(frames)-1; i++ {
		order = append(order, i)
	}
	for _, i := range order {
		d, err := DecodeDatagram(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		complete, err = re.Push(d, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(complete, payload) {
		t.Fatalf("reassembled %q", complete)
	}
	data, err := EncodeData(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDatagram(data)
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("data %v %v", decoded, err)
	}
	var uot bytes.Buffer
	if err := WriteUoT(&uot, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteUoT(&uot, payload); err != nil {
		t.Fatal(err)
	}
	empty, err := ReadUoT(&uot)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty uot %q %v", empty, err)
	}
	gotPayload, err := ReadUoT(&uot)
	if err != nil || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("uot %q %v", gotPayload, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
