package vectors

// MuxCase is one TLS Mux header vector.
type MuxCase struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Valid     bool   `json:"valid"`
	Kind      string `json:"kind,omitempty"`
	Flags     byte   `json:"flags,omitempty"`
	Value     uint16 `json:"value,omitempty"`
	FlowID    string `json:"flow_id,omitempty"`
	FrameHex  string `json:"frame_hex"`
	ErrorCode string `json:"error_code,omitempty"`
}

// MuxFile is the harness mux.json corpus.
type MuxFile struct {
	Protocol string    `json:"protocol"`
	Cases    []MuxCase `json:"cases"`
}

// LoadMux loads mux.json from Dir().
func LoadMux() (MuxFile, error) { return loadJSON[MuxFile]("mux.json") }
