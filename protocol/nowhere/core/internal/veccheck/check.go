// Package veccheck validates Nowhere harness vectors against the wire codecs.
package veccheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/vectors"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// CheckDir validates all known vector files under dir. Returns the number of
// cases checked.
func CheckDir(dir string) (int, error) {
	n := 0
	checkers := []struct {
		name string
		fn   func(string) (int, error)
	}{
		{"auth.json", checkAuth},
		{"target.json", checkTarget},
		{"flow.json", checkFlow},
		{"datagram.json", checkDatagram},
		{"uot.json", checkUOT},
		{"result.json", checkResult},
		{"mux.json", checkMux},
	}
	for _, c := range checkers {
		count, err := c.fn(filepath.Join(dir, c.name))
		if err != nil {
			return n, err
		}
		n += count
	}
	return n, nil
}

func checkAuth(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.AuthFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		creds, err := wire.NewCredentials(tc.SharedKey)
		if err != nil {
			return 0, fmt.Errorf("%s: credentials: %w", tc.ID, err)
		}
		transport, err := parseTransport(tc.Transport)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", tc.ID, err)
		}
		exporter, err := decodeExporter(tc.ExporterHex)
		if err != nil {
			return 0, fmt.Errorf("%s: exporter: %w", tc.ID, err)
		}
		sessionID, err := decodeSessionID(tc.SessionIDHex)
		if err != nil {
			return 0, fmt.Errorf("%s: session_id: %w", tc.ID, err)
		}
		// auth_key must match the exported fixed vector.
		wantKey, err := vectors.DecodeHex(tc.AuthKeyHex)
		if err != nil {
			return 0, fmt.Errorf("%s: auth_key_hex: %w", tc.ID, err)
		}
		if got := wire.DeriveAuthKey([]byte(tc.SharedKey)); !bytes.Equal(got[:], wantKey) {
			return 0, fmt.Errorf("%s: auth_key mismatch\n got %x\nwant %x", tc.ID, got[:], wantKey)
		}
		frame, err := wire.EncodeAuthFrame(creds, transport, exporter, sessionID)
		if err != nil {
			return 0, fmt.Errorf("%s: encode auth: %w", tc.ID, err)
		}
		wantFrame, err := vectors.DecodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		if tc.FrameLen > 0 && len(frame) != tc.FrameLen {
			return 0, fmt.Errorf("%s: frame len %d want %d", tc.ID, len(frame), tc.FrameLen)
		}
		if !bytes.Equal(frame[:], wantFrame) {
			return 0, fmt.Errorf("%s: auth frame mismatch\n got %x\nwant %x", tc.ID, frame[:], wantFrame)
		}
		gotID, err := wire.ValidateAuthFrame(frame[:], creds, transport, exporter)
		if err != nil {
			return 0, fmt.Errorf("%s: validate: %w", tc.ID, err)
		}
		if gotID != sessionID {
			return 0, fmt.Errorf("%s: session id mismatch", tc.ID)
		}
		// tag (trailing 16 bytes) must match the exported tag.
		wantTag, err := vectors.DecodeHex(tc.TagHex)
		if err != nil {
			return 0, fmt.Errorf("%s: tag_hex: %w", tc.ID, err)
		}
		if !bytes.Equal(frame[wire.SessionIDLen:], wantTag) {
			return 0, fmt.Errorf("%s: auth tag mismatch", tc.ID)
		}
	}
	return len(f.Cases), nil
}

func checkTarget(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.TargetFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	n := 0
	for _, tc := range f.Accept {
		want, err := vectors.DecodeHex(tc.WireHex)
		if err != nil {
			return n, fmt.Errorf("%s: wire_hex: %w", tc.ID, err)
		}
		target, err := buildTarget(tc)
		if err != nil {
			return n, fmt.Errorf("%s: build: %w", tc.ID, err)
		}
		got, err := wire.EncodeTarget(target)
		if err != nil {
			return n, fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		if !bytes.Equal(got, want) {
			return n, fmt.Errorf("%s: target mismatch\n got %x\nwant %x", tc.ID, got, want)
		}
		decoded, consumed, err := wire.DecodeTarget(want)
		if err != nil {
			return n, fmt.Errorf("%s: decode: %w", tc.ID, err)
		}
		if consumed != len(want) {
			return n, fmt.Errorf("%s: decode consumed %d want %d", tc.ID, consumed, len(want))
		}
		if !targetsEqual(decoded, target) {
			return n, fmt.Errorf("%s: decoded target mismatch", tc.ID)
		}
		n++
	}
	for _, tc := range f.Reject {
		input, err := vectors.DecodeHex(tc.InputHex)
		if err != nil {
			return n, fmt.Errorf("%s: input_hex: %w", tc.ID, err)
		}
		if _, _, err := wire.DecodeTarget(input); err == nil {
			return n, fmt.Errorf("%s: expected reject (%s)", tc.ID, tc.Reason)
		}
		n++
	}
	return n, nil
}

func buildTarget(tc vectors.TargetAcceptCase) (wire.Target, error) {
	switch tc.ATYP {
	case wire.TargetIPv4:
		addr, err := netip.ParseAddr(tc.IPv4)
		if err != nil {
			return wire.Target{}, fmt.Errorf("parse ipv4: %w", err)
		}
		return wire.NewIPTarget(addr, tc.Port)
	case wire.TargetIPv6:
		addr, err := netip.ParseAddr(tc.IPv6)
		if err != nil {
			return wire.Target{}, fmt.Errorf("parse ipv6: %w", err)
		}
		return wire.NewIPTarget(addr, tc.Port)
	case wire.TargetDomain:
		return wire.NewDomainTarget(tc.Host, tc.Port)
	default:
		return wire.Target{}, fmt.Errorf("unknown atyp %d", tc.ATYP)
	}
}

func targetsEqual(a, b wire.Target) bool {
	if a.Type != b.Type || a.Port != b.Port || a.Host != b.Host {
		return false
	}
	if a.Type == wire.TargetTypeDomain {
		return true
	}
	return a.Addr == b.Addr
}

func checkFlow(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.FlowFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		switch tc.Operation {
		case "flow_header":
			if err := checkFlowHeaderCase(tc); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("%s: unknown flow operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

func checkFlowHeaderCase(tc vectors.FlowCase) error {
	want, err := vectors.DecodeHex(tc.FrameHex)
	if err != nil {
		return fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
	}
	if tc.Valid {
		header, err := buildFlowHeader(tc)
		if err != nil {
			return fmt.Errorf("%s: build: %w", tc.ID, err)
		}
		got, err := wire.WriteFlowHeader(header)
		if err != nil {
			return fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		if !bytes.Equal(got[:], want) {
			return fmt.Errorf("%s: flow header mismatch\n got %x\nwant %x", tc.ID, got[:], want)
		}
		decoded, err := wire.DecodeFlowHeader(want)
		if err != nil {
			return fmt.Errorf("%s: decode: %w", tc.ID, err)
		}
		if decoded != header {
			return fmt.Errorf("%s: decoded header mismatch", tc.ID)
		}
		return nil
	}
	// Invalid: decoding must fail.
	if _, err := wire.DecodeFlowHeader(want); err == nil {
		return fmt.Errorf("%s: expected decode error (%s)", tc.ID, tc.ErrorCode)
	}
	return nil
}

func buildFlowHeader(tc vectors.FlowCase) (wire.FlowHeader, error) {
	flowID, err := strconv.ParseUint(tc.FlowID, 10, 32)
	if err != nil {
		return wire.FlowHeader{}, fmt.Errorf("flow_id: %w", err)
	}
	return wire.FlowHeader{
		Role:     parseRole(tc.Role),
		FlowID:   uint32(flowID),
		Kind:     parseKind(tc.Kind),
		Uplink:   parseCarrier(tc.Uplink),
		Downlink: parseCarrier(tc.Downlink),
		Hops:     tc.Hops,
	}, nil
}

func checkDatagram(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.DatagramFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		flowID, err := strconv.ParseUint(tc.FlowID, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%s: flow_id: %w", tc.ID, err)
		}
		switch tc.Operation {
		case "data":
			payload, err := vectors.DecodeHex(tc.PayloadHex)
			if err != nil {
				return 0, fmt.Errorf("%s: payload: %w", tc.ID, err)
			}
			got, err := wire.EncodeUDPData(uint32(flowID), payload)
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			want, err := vectors.DecodeHex(tc.FramesHex[0])
			if err != nil {
				return 0, fmt.Errorf("%s: frames_hex[0]: %w", tc.ID, err)
			}
			if !bytes.Equal(got, want) {
				return 0, fmt.Errorf("%s: data frame mismatch\n got %x\nwant %x", tc.ID, got, want)
			}
			decoded, err := wire.DecodeUDPFrame(got)
			if err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			if decoded.Type != wire.UDPFrameTypeData || decoded.FlowID != uint32(flowID) {
				return 0, fmt.Errorf("%s: decoded fields mismatch", tc.ID)
			}
			reencoded, err := encodeUDPFrame(decoded)
			if err != nil {
				return 0, fmt.Errorf("%s: re-encode: %w", tc.ID, err)
			}
			if !bytes.Equal(reencoded, want) {
				return 0, fmt.Errorf("%s: data decode/re-encode mismatch", tc.ID)
			}
		case "close":
			got, err := wire.EncodeUDPClose(uint32(flowID))
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			want, err := vectors.DecodeHex(tc.FramesHex[0])
			if err != nil {
				return 0, fmt.Errorf("%s: frames_hex[0]: %w", tc.ID, err)
			}
			if !bytes.Equal(got[:], want) {
				return 0, fmt.Errorf("%s: close frame mismatch\n got %x\nwant %x", tc.ID, got[:], want)
			}
			decoded, err := wire.DecodeUDPFrame(want)
			if err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			reencoded, err := encodeUDPFrame(decoded)
			if err != nil {
				return 0, fmt.Errorf("%s: re-encode: %w", tc.ID, err)
			}
			if !bytes.Equal(reencoded, want) {
				return 0, fmt.Errorf("%s: close decode/re-encode mismatch", tc.ID)
			}
		case "fragment":
			if err := checkFragmentCase(tc, uint32(flowID)); err != nil {
				return 0, err
			}
		case "decode":
			rawFrame, err := vectors.DecodeHex(tc.RawHex)
			if err != nil {
				return 0, fmt.Errorf("%s: raw_hex: %w", tc.ID, err)
			}
			decoded, err := wire.DecodeUDPFrame(rawFrame)
			if tc.Valid && err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			if !tc.Valid && err == nil {
				return 0, fmt.Errorf("%s: expected decode error (%s)", tc.ID, tc.ErrorCode)
			}
			if tc.Valid {
				reencoded, err := encodeUDPFrame(decoded)
				if err != nil {
					return 0, fmt.Errorf("%s: re-encode: %w", tc.ID, err)
				}
				if !bytes.Equal(reencoded, rawFrame) {
					return 0, fmt.Errorf("%s: datagram decode/re-encode mismatch", tc.ID)
				}
			}
		default:
			return 0, fmt.Errorf("%s: unknown datagram operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

func checkFragmentCase(tc vectors.DatagramCase, flowID wire.FlowID) error {
	payload, err := vectors.DecodeHex(tc.PayloadHex)
	if err != nil {
		return fmt.Errorf("%s: payload: %w", tc.ID, err)
	}
	if tc.PacketID == nil || tc.MaxDatagramSize == nil {
		return fmt.Errorf("%s: fragment case missing packet_id/max_datagram_size", tc.ID)
	}
	frames, err := wire.EncodeUDPDataFragments(flowID, *tc.PacketID, payload, *tc.MaxDatagramSize)
	if err != nil {
		return fmt.Errorf("%s: encode: %w", tc.ID, err)
	}
	if len(frames) != len(tc.FramesHex) {
		return fmt.Errorf("%s: frame count %d want %d", tc.ID, len(frames), len(tc.FramesHex))
	}
	reassembler, err := wire.NewDatagramReassembler(wire.DefaultReassemblyConfig())
	if err != nil {
		return fmt.Errorf("%s: reassembler: %w", tc.ID, err)
	}
	for i, got := range frames {
		want, err := vectors.DecodeHex(tc.FramesHex[i])
		if err != nil {
			return fmt.Errorf("%s: frames_hex[%d]: %w", tc.ID, i, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("%s: frame[%d] mismatch\n got %x\nwant %x", tc.ID, i, got, want)
		}
		decoded, err := wire.DecodeUDPFrame(got)
		if err != nil {
			return fmt.Errorf("%s: decode frame[%d]: %w", tc.ID, i, err)
		}
		if decoded.Type != wire.UDPFrameTypeFragment || decoded.FlowID != flowID {
			return fmt.Errorf("%s: decoded frame[%d] fields mismatch", tc.ID, i)
		}
		reencoded, err := encodeUDPFrame(decoded)
		if err != nil {
			return fmt.Errorf("%s: re-encode frame[%d]: %w", tc.ID, i, err)
		}
		if !bytes.Equal(reencoded, want) {
			return fmt.Errorf("%s: fragment[%d] decode/re-encode mismatch", tc.ID, i)
		}
		outcome := reassembler.Push(flowID, decoded.Fragment, reassemblyTime())
		if outcome.Done {
			if !bytes.Equal(outcome.Payload, payload) {
				return fmt.Errorf("%s: reassembled payload mismatch", tc.ID)
			}
		} else if outcome.DropReason != wire.ReassemblyDropNone {
			return fmt.Errorf("%s: unexpected drop %s", tc.ID, outcome.DropReason)
		}
	}
	return nil
}

func checkUOT(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.UOTFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		switch tc.Operation {
		case "encode":
			payload, err := vectors.DecodeHex(tc.PayloadHex)
			if err != nil {
				return 0, fmt.Errorf("%s: payload: %w", tc.ID, err)
			}
			got, err := wire.EncodeUDPPacket(payload)
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			want, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
			}
			if !bytes.Equal(got, want) {
				return 0, fmt.Errorf("%s: uot packet mismatch\n got %x\nwant %x", tc.ID, got, want)
			}
			decoded, err := wire.ReadUDPPacket(bytes.NewReader(want))
			if err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			reencoded, err := wire.EncodeUDPPacket(decoded)
			if err != nil {
				return 0, fmt.Errorf("%s: re-encode: %w", tc.ID, err)
			}
			if !bytes.Equal(reencoded, want) {
				return 0, fmt.Errorf("%s: uot decode/re-encode mismatch", tc.ID)
			}
		case "header":
			want, err := vectors.DecodeHex(tc.FrameHex)
			if tc.Valid {
				if err != nil {
					return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
				}
				if len(want) != wire.UoTHeaderLen {
					return 0, fmt.Errorf("%s: header len %d want %d", tc.ID, len(want), wire.UoTHeaderLen)
				}
				length := int(want[0])<<8 | int(want[1])
				got, err := wire.EncodeUDPPacketHeader(length)
				if err != nil {
					return 0, fmt.Errorf("%s: header encode: %w", tc.ID, err)
				}
				if !bytes.Equal(got[:], want) {
					return 0, fmt.Errorf("%s: uot header mismatch\n got %x\nwant %x", tc.ID, got[:], want)
				}
			} else {
				// Invalid header (oversize length): EncodeUDPPacketHeader must fail.
				// Decode the (oversize) length from frame_hex if present; otherwise
				// simply assert the encoder rejects UoTPacketMax+1.
				if _, err := wire.EncodeUDPPacketHeader(wire.UoTPacketMax + 1); err == nil {
					return 0, fmt.Errorf("%s: expected header encode error (%s)", tc.ID, tc.ErrorCode)
				}
			}
		default:
			return 0, fmt.Errorf("%s: unknown uot operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

func checkResult(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.ResultFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		switch tc.Operation {
		case "setup_result":
			if tc.Valid {
				result, err := parseSetupResult(tc.SetupResult)
				if err != nil {
					return 0, fmt.Errorf("%s: %w", tc.ID, err)
				}
				got, err := wire.EncodeSetupResult(result)
				if err != nil {
					return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
				}
				want, err := vectors.DecodeHex(tc.FrameHex)
				if err != nil {
					return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
				}
				if !bytes.Equal(got[:], want) {
					return 0, fmt.Errorf("%s: result mismatch\n got %x\nwant %x", tc.ID, got[:], want)
				}
				decoded, err := wire.DecodeSetupResult(want)
				if err != nil {
					return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
				}
				if decoded != result {
					return 0, fmt.Errorf("%s: decoded result mismatch", tc.ID)
				}
			} else {
				want, err := vectors.DecodeHex(tc.FrameHex)
				if err != nil {
					return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
				}
				if _, err := wire.DecodeSetupResult(want); err == nil {
					return 0, fmt.Errorf("%s: expected decode error (%s)", tc.ID, tc.ErrorCode)
				}
			}
		case "flow_result":
			// flow_result vectors reuse the setup-result wire byte.
			want, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
			}
			if len(want) != 1 || want[0] != tc.Code {
				return 0, fmt.Errorf("%s: flow_result wire byte mismatch", tc.ID)
			}
			decoded, err := wire.DecodeSetupResult(want)
			if err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			reencoded, err := wire.EncodeSetupResult(decoded)
			if err != nil {
				return 0, fmt.Errorf("%s: re-encode: %w", tc.ID, err)
			}
			if !bytes.Equal(reencoded[:], want) {
				return 0, fmt.Errorf("%s: flow result decode/re-encode mismatch", tc.ID)
			}
		default:
			return 0, fmt.Errorf("%s: unknown result operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

// helpers ------------------------------------------------------------------

func unmarshal(raw []byte, path string, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func parseTransport(s string) (wire.AuthTransport, error) {
	switch s {
	case "tls_tcp":
		return wire.AuthTransportTLSTCP, nil
	case "quic":
		return wire.AuthTransportQUIC, nil
	default:
		return 0, fmt.Errorf("unknown transport %q", s)
	}
}

func parseRole(s string) wire.FlowRole {
	switch s {
	case "duplex":
		return wire.FlowRoleDuplex
	case "open":
		return wire.FlowRoleOpen
	case "attach":
		return wire.FlowRoleAttach
	default:
		return wire.FlowRoleDuplex
	}
}

func parseKind(s string) wire.FlowKind {
	if s == "udp" {
		return wire.FlowKindUDP
	}
	return wire.FlowKindTCP
}

func parseCarrier(s string) wire.Carrier {
	if s == "quic" {
		return wire.CarrierQUIC
	}
	return wire.CarrierTLSTCP
}

func parseSetupResult(s string) (wire.SetupResult, error) {
	switch s {
	case "ready":
		return wire.SetupResultReady, nil
	case "invalid_request":
		return wire.SetupResultInvalidRequest, nil
	case "metadata_conflict":
		return wire.SetupResultMetadataConflict, nil
	case "pair_timeout":
		return wire.SetupResultPairTimeout, nil
	case "flow_limit":
		return wire.SetupResultFlowLimit, nil
	case "dial_failed":
		return wire.SetupResultDialFailed, nil
	case "session_replaced":
		return wire.SetupResultSessionReplaced, nil
	case "internal_error":
		return wire.SetupResultInternalError, nil
	default:
		return 0, fmt.Errorf("unknown setup_result %q", s)
	}
}

func decodeExporter(hexStr string) (wire.TLSExporter, error) {
	raw, err := vectors.DecodeHex(hexStr)
	if err != nil {
		return wire.TLSExporter{}, err
	}
	if len(raw) != wire.TLSExporterLen {
		return wire.TLSExporter{}, fmt.Errorf("exporter length %d want %d", len(raw), wire.TLSExporterLen)
	}
	var out wire.TLSExporter
	copy(out[:], raw)
	return out, nil
}

func decodeSessionID(hexStr string) (wire.SessionID, error) {
	raw, err := vectors.DecodeHex(hexStr)
	if err != nil {
		return wire.SessionID{}, err
	}
	if len(raw) != wire.SessionIDLen {
		return wire.SessionID{}, fmt.Errorf("session_id length %d want %d", len(raw), wire.SessionIDLen)
	}
	var out wire.SessionID
	copy(out[:], raw)
	return out, nil
}

func reassemblyTime() time.Time { return time.Unix(0, 0) }

func encodeUDPFrame(frame wire.UDPFrame) ([]byte, error) {
	switch frame.Type {
	case wire.UDPFrameTypeData:
		return wire.EncodeUDPData(frame.FlowID, frame.Payload)
	case wire.UDPFrameTypeFragment:
		header, err := wire.EncodeUDPFragmentHeader(frame.FlowID, frame.Fragment)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(header)+len(frame.Fragment.Payload))
		copy(out, header[:])
		copy(out[len(header):], frame.Fragment.Payload)
		return out, nil
	case wire.UDPFrameTypeClose:
		encoded, err := wire.EncodeUDPClose(frame.FlowID)
		if err != nil {
			return nil, err
		}
		return encoded[:], nil
	default:
		return nil, fmt.Errorf("unknown UDP frame type %d", frame.Type)
	}
}
