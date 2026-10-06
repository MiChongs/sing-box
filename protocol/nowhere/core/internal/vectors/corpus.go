package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AuthCase is one nw2 connection-bound authentication vector.
type AuthCase struct {
	ID           string `json:"id"`
	SharedKey    string `json:"shared_key"`
	Transport    string `json:"transport"`
	ExporterHex  string `json:"exporter_hex"`
	SessionIDHex string `json:"session_id_hex"`
	AuthKeyHex   string `json:"auth_key_hex"`
	TagHex       string `json:"tag_hex"`
	FrameHex     string `json:"frame_hex"`
	FrameLen     int    `json:"frame_len"`
}

// AuthFile is the harness auth.json corpus.
type AuthFile struct {
	Protocol string     `json:"protocol"`
	Cases    []AuthCase `json:"cases"`
}

// TargetAcceptCase is one accepted target vector.
type TargetAcceptCase struct {
	ID      string `json:"id"`
	ATYP    byte   `json:"atyp"`
	Host    string `json:"host"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Port    uint16 `json:"port"`
	WireHex string `json:"wire_hex"`
}

// TargetRejectCase is one rejected target vector.
type TargetRejectCase struct {
	ID       string `json:"id"`
	InputHex string `json:"input_hex"`
	Reason   string `json:"reason"`
}

// TargetFile is the harness target.json corpus.
type TargetFile struct {
	Protocol string             `json:"protocol"`
	Accept   []TargetAcceptCase `json:"accept"`
	Reject   []TargetRejectCase `json:"reject"`
}

// FlowCase is one flow-header vector.
type FlowCase struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Valid     bool   `json:"valid"`
	Role      string `json:"role,omitempty"`
	FlowID    string `json:"flow_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Uplink    string `json:"uplink,omitempty"`
	Downlink  string `json:"downlink,omitempty"`
	Hops      uint8  `json:"hops,omitempty"`
	FrameHex  string `json:"frame_hex"`
	ErrorCode string `json:"error_code,omitempty"`
}

// FlowFile is the harness flow.json corpus.
type FlowFile struct {
	Protocol string     `json:"protocol"`
	Cases    []FlowCase `json:"cases"`
}

// DatagramCase is one datagram encode/decode vector.
type DatagramCase struct {
	ID              string   `json:"id"`
	Operation       string   `json:"operation"`
	Valid           bool     `json:"valid"`
	FlowID          string   `json:"flow_id"`
	PacketID        *uint32  `json:"packet_id,omitempty"`
	MaxDatagramSize *int     `json:"max_datagram_size,omitempty"`
	PayloadHex      string   `json:"payload_hex"`
	FramesHex       []string `json:"frames_hex"`
	RawHex          string   `json:"raw_hex,omitempty"`
	ErrorCode       string   `json:"error_code,omitempty"`
}

// DatagramFile is the harness datagram.json corpus.
type DatagramFile struct {
	Protocol string         `json:"protocol"`
	Cases    []DatagramCase `json:"cases"`
}

// UOTCase is one UoT packet vector.
type UOTCase struct {
	ID         string `json:"id"`
	Operation  string `json:"operation"`
	Valid      bool   `json:"valid"`
	PayloadHex string `json:"payload_hex"`
	FrameHex   string `json:"frame_hex"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// UOTFile is the harness uot.json corpus.
type UOTFile struct {
	Protocol string    `json:"protocol"`
	Cases    []UOTCase `json:"cases"`
}

// ResultCase is one setup-result / flow-result vector.
type ResultCase struct {
	ID          string `json:"id"`
	Operation   string `json:"operation"`
	Valid       bool   `json:"valid"`
	SetupResult string `json:"setup_result"`
	Code        uint8  `json:"code"`
	FrameHex    string `json:"frame_hex"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// ResultFile is the harness result.json corpus.
type ResultFile struct {
	Protocol string       `json:"protocol"`
	Cases    []ResultCase `json:"cases"`
}

// LoadAuth loads auth.json from Dir().
func LoadAuth() (AuthFile, error) { return loadJSON[AuthFile]("auth.json") }

// LoadTarget loads target.json from Dir().
func LoadTarget() (TargetFile, error) { return loadJSON[TargetFile]("target.json") }

// LoadFlow loads flow.json from Dir().
func LoadFlow() (FlowFile, error) { return loadJSON[FlowFile]("flow.json") }

// LoadDatagram loads datagram.json from Dir().
func LoadDatagram() (DatagramFile, error) { return loadJSON[DatagramFile]("datagram.json") }

// LoadUOT loads uot.json from Dir().
func LoadUOT() (UOTFile, error) { return loadJSON[UOTFile]("uot.json") }

// LoadResult loads result.json from Dir().
func LoadResult() (ResultFile, error) { return loadJSON[ResultFile]("result.json") }

func loadJSON[T any](name string) (T, error) {
	var out T
	dir, err := Dir()
	if err != nil {
		return out, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
