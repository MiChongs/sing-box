package veccheck

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/vectors"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func checkMux(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f vectors.MuxFile
	if err := unmarshal(raw, path, &f); err != nil {
		return 0, err
	}
	for _, tc := range f.Cases {
		if tc.Operation != "header" {
			return 0, fmt.Errorf("%s: unknown mux operation %q", tc.ID, tc.Operation)
		}
		want, err := vectors.DecodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		if !tc.Valid {
			if _, err := wire.DecodeMuxHeader(want); err == nil {
				return 0, fmt.Errorf("%s: expected decode error (%s)", tc.ID, tc.ErrorCode)
			}
			continue
		}
		header, err := buildMuxHeader(tc)
		if err != nil {
			return 0, fmt.Errorf("%s: build: %w", tc.ID, err)
		}
		got, err := wire.EncodeMuxHeader(header)
		if err != nil {
			return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		if !bytes.Equal(got[:], want) {
			return 0, fmt.Errorf("%s: mux header mismatch\n got %x\nwant %x", tc.ID, got[:], want)
		}
		decoded, err := wire.DecodeMuxHeader(want)
		if err != nil {
			return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
		}
		if decoded != header {
			return 0, fmt.Errorf("%s: decoded mux header mismatch", tc.ID)
		}
	}
	return len(f.Cases), nil
}

func buildMuxHeader(tc vectors.MuxCase) (wire.MuxHeader, error) {
	flowID, err := strconv.ParseUint(tc.FlowID, 10, 32)
	if err != nil {
		return wire.MuxHeader{}, fmt.Errorf("flow_id: %w", err)
	}
	var kind wire.MuxFrameKind
	switch tc.Kind {
	case "open":
		kind = wire.MuxFrameOpen
	case "data":
		kind = wire.MuxFrameData
	case "window":
		kind = wire.MuxFrameWindow
	case "fin":
		kind = wire.MuxFrameFin
	case "reset":
		kind = wire.MuxFrameReset
	default:
		return wire.MuxHeader{}, fmt.Errorf("unknown mux kind %q", tc.Kind)
	}
	return wire.MuxHeader{Kind: kind, Value: tc.Value, FlowID: uint32(flowID)}, nil
}
