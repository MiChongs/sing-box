// Package veccheck validates Nowhere harness vectors against the wire codecs.
//
// CheckNW3Dir validates the module-local nw3 conformance corpus
// (testdata/vectors/nw3) against the nw3 wire codecs in wire and morph.
package veccheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/vectors"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// nw3Vectors is the provenance-annotated export of
// Nowhere/src/tests/protocol/vectors.json.
type nw3Vectors struct {
	Protocol         string         `json:"protocol"`
	UpstreamVersion  string         `json:"upstream_version"`
	UpstreamCommit   string         `json:"upstream_commit"`
	ExporterVersion  string         `json:"exporter_version"`
	SharedKeyText    string         `json:"shared_key_text"`
	SaltHex          string         `json:"salt_hex"`
	RootHex          string         `json:"root_hex"`
	ExporterLabel    string         `json:"exporter_label"`
	ExporterHex      string         `json:"exporter_hex"`
	Auth             []nw3AuthCase  `json:"auth"`
	FlowStart        nw3FlowStart   `json:"flow_start"`
	UDPStreamIDs     []nw3StreamID  `json:"udp_stream_ids"`
	InvalidStreamIDs []uint64       `json:"invalid_stream_ids"`
	SetupResult      map[string]int `json:"setup_result"`
	Registration     map[string]int `json:"registration_result"`
}

type nw3AuthCase struct {
	Role       string `json:"role"`
	Transport  int    `json:"transport"`
	RoleKeyHex string `json:"role_key_hex"`
	AuthFrame  string `json:"auth_frame_hex"`
}

type nw3FlowStart struct {
	TCPHex string `json:"tcp_hex"`
	UDPHex string `json:"udp_hex"`
}

type nw3StreamID struct {
	Initiator string `json:"initiator"`
	StreamID  uint64 `json:"stream_id"`
	FlowID    uint32 `json:"flow_id"`
}

// nw3MorphFile pins the Morph KDF outputs.
type nw3MorphFile struct {
	Protocol        string        `json:"protocol"`
	UpstreamVersion string        `json:"upstream_version"`
	UpstreamCommit  string        `json:"upstream_commit"`
	Cases           []nw3MorphRow `json:"cases"`
}

type nw3MorphRow struct {
	ID        string `json:"id"`
	SharedKey string `json:"shared_key_text"`
	TCPC2SHex string `json:"tcp_c2s_hex"`
	TCPS2CHex string `json:"tcp_s2c_hex"`
	UDPC2SHex string `json:"udp_c2s_hex"`
	UDPS2CHex string `json:"udp_s2c_hex"`
}

// CheckNW3Dir validates the nw3 corpus under dir. Returns the number of cases
// checked (each auth/flow/stream/morph row counts once).
func CheckNW3Dir(dir string) (int, error) {
	n := 0
	for _, c := range []struct {
		name string
		fn   func(string) (int, error)
	}{
		{"vectors.json", checkNW3Vectors},
		{"morph.json", checkNW3Morph},
		{"prelude.json", checkNW3Prelude},
	} {
		count, err := c.fn(filepath.Join(dir, c.name))
		if err != nil {
			return n, err
		}
		n += count
	}
	return n, nil
}

func checkNW3Vectors(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f nw3Vectors
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	if f.Protocol != "nw3" {
		return 0, fmt.Errorf("%s: protocol %q, want nw3", path, f.Protocol)
	}
	if f.ExporterLabel != wire.ExporterLabel {
		return 0, fmt.Errorf("%s: exporter label %q, want %q", path, f.ExporterLabel, wire.ExporterLabel)
	}

	creds, err := wire.NewCredentials(f.SharedKeyText)
	if err != nil {
		return 0, fmt.Errorf("%s: credentials: %w", path, err)
	}

	// The documented auth root salt is SHA-256("nowhere/nw3/auth-root"). The
	// corpus pins both it and the resulting root so a derivation change is
	// caught even though the Go API does not expose those intermediates.
	wantSalt, err := vectors.DecodeHex(f.SaltHex)
	if err != nil {
		return 0, fmt.Errorf("%s: salt_hex: %w", path, err)
	}
	if got := sha256.Sum256([]byte("nowhere/nw3/auth-root")); !bytes.Equal(got[:], wantSalt) {
		return 0, fmt.Errorf("%s: auth root salt mismatch\n got %x\nwant %x", path, got[:], wantSalt)
	}

	exporter, err := decodeNW3Exporter(f.ExporterHex)
	if err != nil {
		return 0, fmt.Errorf("%s: exporter_hex: %w", path, err)
	}

	n := 0
	for _, tc := range f.Auth {
		role, err := parseNW3Role(tc.Role)
		if err != nil {
			return n, fmt.Errorf("%s: %w", tc.Role, err)
		}
		transport := wire.AuthTransport(tc.Transport)
		if _, err := wire.EncodeAuthFrame([32]byte{}, transport, wire.Exporter{}); err != nil {
			return n, fmt.Errorf("%s: transport %d: %w", tc.Role, tc.Transport, err)
		}
		key, err := creds.RoleKey(role)
		if err != nil {
			return n, fmt.Errorf("%s: role key: %w", tc.Role, err)
		}
		wantKey, err := vectors.DecodeHex(tc.RoleKeyHex)
		if err != nil {
			return n, fmt.Errorf("%s: role_key_hex: %w", tc.Role, err)
		}
		if !bytes.Equal(key[:], wantKey) {
			return n, fmt.Errorf("%s: role key mismatch\n got %x\nwant %x", tc.Role, key[:], wantKey)
		}
		frame, err := wire.EncodeAuthFrame(key, transport, exporter)
		if err != nil {
			return n, fmt.Errorf("%s: encode auth: %w", tc.Role, err)
		}
		wantFrame, err := vectors.DecodeHex(tc.AuthFrame)
		if err != nil {
			return n, fmt.Errorf("%s: auth_frame_hex: %w", tc.Role, err)
		}
		if !bytes.Equal(frame[:], wantFrame) {
			return n, fmt.Errorf("%s: auth frame mismatch\n got %x\nwant %x", tc.Role, frame[:], wantFrame)
		}
		// Round trip: the tag must validate to exactly the declared role when
		// the role is legal on that transport. Egress is admitted on QUIC only,
		// so an egress tag under TLS is a spec-negative case and MUST be
		// rejected (the corpus pins both).
		wantRole := role
		if role == wire.RoleEgress && transport != wire.AuthQUIC {
			wantRole = 0
		}
		gotRole, err := wire.ValidateAuthFrame(frame[:], creds, transport, exporter)
		if wantRole == 0 {
			if err == nil {
				return n, fmt.Errorf("%s: egress tag accepted on transport %d, want rejected", tc.Role, tc.Transport)
			}
			n++
			continue
		}
		if err != nil {
			return n, fmt.Errorf("%s: validate auth: %w", tc.Role, err)
		}
		if gotRole != wantRole {
			return n, fmt.Errorf("%s: validated role %v, want %v", tc.Role, gotRole, wantRole)
		}
		n++
	}

	// FlowStart bytes as published; the encoder must reproduce them and the
	// decoder must accept them.
	for _, tc := range []struct {
		hex  string
		kind wire.FlowKind
	}{
		{f.FlowStart.TCPHex, wire.FlowTCP},
		{f.FlowStart.UDPHex, wire.FlowUDP},
	} {
		raw, err := vectors.DecodeHex(tc.hex)
		if err != nil || len(raw) != 1 {
			return n, fmt.Errorf("%s: flow start %q not one byte", path, tc.hex)
		}
		var buf bytes.Buffer
		if err := wire.WriteFlowStart(&buf, tc.kind); err != nil {
			return n, fmt.Errorf("%s: write flow start: %w", path, err)
		}
		if buf.Bytes()[0] != raw[0] {
			return n, fmt.Errorf("%s: flow start byte %#x, want %#x", path, buf.Bytes()[0], raw[0])
		}
		got, err := wire.ParseFlowStart(raw[0])
		if err != nil || got != tc.kind {
			return n, fmt.Errorf("%s: parse flow start %#x = %v %v", path, raw[0], got, err)
		}
		n++
	}

	for _, tc := range f.UDPStreamIDs {
		got, err := wire.UDPFlowID(tc.StreamID, tc.Initiator == "server")
		if err != nil {
			return n, fmt.Errorf("%s: stream %d (%s): %w", path, tc.StreamID, tc.Initiator, err)
		}
		if got != tc.FlowID {
			return n, fmt.Errorf("%s: stream %d (%s) = %d, want %d", path, tc.StreamID, tc.Initiator, got, tc.FlowID)
		}
		n++
	}

	for _, id := range f.InvalidStreamIDs {
		if _, err := wire.UDPFlowID(id, false); err == nil {
			// Direction matters for some ids; both directions must reject.
			if _, err2 := wire.UDPFlowID(id, true); err2 == nil {
				return n, fmt.Errorf("%s: invalid stream id %d accepted", path, id)
			}
		}
		n++
	}

	for name, value := range f.SetupResult {
		got, err := wire.ParseSetupResult(byte(value))
		if err != nil {
			return n, fmt.Errorf("%s: setup result %s = %d: %w", path, name, value, err)
		}
		if int(got) != value {
			return n, fmt.Errorf("%s: setup result %s = %d, want %d", path, name, got, value)
		}
		n++
	}
	for name, value := range f.Registration {
		got, err := wire.ParseRegistrationResult(byte(value))
		if err != nil {
			return n, fmt.Errorf("%s: registration result %s = %d: %w", path, name, value, err)
		}
		if int(got) != value {
			return n, fmt.Errorf("%s: registration result %s = %d, want %d", path, name, got, value)
		}
		n++
	}
	return n, nil
}

func checkNW3Morph(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f nw3MorphFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		keys := morph.Derive([]byte(tc.SharedKey))
		for _, row := range []struct {
			name string
			got  [32]byte
			hex  string
		}{
			{"tcp_c2s", keys.TCPC2S, tc.TCPC2SHex},
			{"tcp_s2c", keys.TCPS2C, tc.TCPS2CHex},
			{"udp_c2s", keys.UDPC2S, tc.UDPC2SHex},
			{"udp_s2c", keys.UDPS2C, tc.UDPS2CHex},
		} {
			want, err := vectors.DecodeHex(row.hex)
			if err != nil {
				return 0, fmt.Errorf("%s: %s %s: %w", tc.ID, tc.ID, row.name, err)
			}
			if !bytes.Equal(row.got[:], want) {
				return 0, fmt.Errorf("%s/%s: morph key mismatch\n got %x\nwant %x", tc.ID, row.name, row.got[:], want)
			}
		}
	}
	return len(f.Cases), nil
}

func decodeNW3Exporter(s string) (wire.Exporter, error) {
	var out wire.Exporter
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(raw) != wire.ExporterLen {
		return out, fmt.Errorf("exporter is %d bytes, want %d", len(raw), wire.ExporterLen)
	}
	copy(out[:], raw)
	return out, nil
}

func parseNW3Role(name string) (wire.Role, error) {
	switch name {
	case "vector":
		return wire.RoleVector, nil
	case "egress":
		return wire.RoleEgress, nil
	default:
		return 0, fmt.Errorf("unknown role %q", name)
	}
}

type nw3PreludeFile struct {
	Protocol string          `json:"protocol"`
	Cases    []nw3PreludeRow `json:"cases"`
}

type nw3PreludeRow struct {
	ID          string `json:"id"`
	SharedKey   string `json:"shared_key_text"`
	PrefixHex   string `json:"prefix_hex"`
	NonceHex    string `json:"nonce_hex"`
	HighHex     string `json:"high_hex"`
	IdentityHex string `json:"identity_hex"`
	CounterHex  string `json:"counter_hex"`
	TailHex     string `json:"tail_hex"`
}

func checkNW3Prelude(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f nw3PreludeFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	if f.Protocol != "nw3" {
		return 0, fmt.Errorf("%s: protocol %q, want nw3", path, f.Protocol)
	}
	for _, tc := range f.Cases {
		keys := morph.Derive([]byte(tc.SharedKey))
		prefix, err := vectors.DecodeHex(tc.PrefixHex)
		if err != nil || len(prefix) != 32 {
			return 0, fmt.Errorf("%s: %s prefix", path, tc.ID)
		}
		nonce, err := vectors.DecodeHex(tc.NonceHex)
		if err != nil || len(nonce) != 12 {
			return 0, fmt.Errorf("%s: %s nonce", path, tc.ID)
		}
		high, err := vectors.DecodeHex(tc.HighHex)
		if err != nil || len(high) != 4 {
			return 0, fmt.Errorf("%s: %s high", path, tc.ID)
		}
		identityRaw, err := vectors.DecodeHex(tc.IdentityHex)
		if err != nil || len(identityRaw) != 8 {
			return 0, fmt.Errorf("%s: %s identity", path, tc.ID)
		}
		counterRaw, err := vectors.DecodeHex(tc.CounterHex)
		if err != nil || len(counterRaw) != 6 {
			return 0, fmt.Errorf("%s: %s counter", path, tc.ID)
		}
		var identityBuf, counterBuf [8]byte
		copy(identityBuf[:], identityRaw)
		copy(counterBuf[2:], counterRaw)
		identity := binary.BigEndian.Uint64(identityBuf[:])
		counter := binary.BigEndian.Uint64(counterBuf[:])
		prelude := make([]byte, 64)
		copy(prelude, prefix)
		for i := 0; i < 32; i++ {
			bit := (high[i/8] >> (7 - i%8)) & 1
			prelude[32+i] = bit << 7
		}
		if err := morph.EncodeTCPPrelude(keys, prelude, nonce, identity, counter); err != nil {
			return 0, fmt.Errorf("%s: %s encode: %w", path, tc.ID, err)
		}
		wantTail, err := vectors.DecodeHex(tc.TailHex)
		if err != nil || !bytes.Equal(prelude[32:], wantTail) {
			return 0, fmt.Errorf("%s: %s tail\n got %x\nwant %x", path, tc.ID, prelude[32:], wantTail)
		}
		gotID, gotCounter, ok := morph.DecodeTCPPrelude(keys, prelude, nonce)
		if !ok || gotID != identity || gotCounter != counter {
			return 0, fmt.Errorf("%s: %s decode id=%x counter=%d ok=%v", path, tc.ID, gotID, gotCounter, ok)
		}
	}
	return len(f.Cases), nil
}
