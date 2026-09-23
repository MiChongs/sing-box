package smart

import (
	"bytes"

	gojson "github.com/goccy/go-json"
	"github.com/vmihailenco/msgpack/v5"
)

// This package uses github.com/goccy/go-json for Smart-store record
// encoding because every closed connection writes a StatsRecord to
// bbolt through the queue, and every prefetch read deserialises it back.
// With many Smart groups active, that adds up to tens of thousands of
// marshal/unmarshal calls per minute — the encoding/json reflective path
// was showing up as a top allocation site in profiles.
//
// goccy/go-json is a drop-in replacement: same tag semantics (json:"..."),
// produces identical output for the record types we use, roughly 2-3x
// faster on marshal and allocates ~30-40% less on unmarshal into structs
// with simple scalar fields. Importantly, it's backwards-compatible with
// data previously written by encoding/json, so there's no migration step.
//
// We intentionally do NOT shim these as the sing package-level json aliases
// because many other sing-box packages need encoding/json's exact semantics
// (tolerating RawMessage edge cases, etc). The aliases here are scoped to
// the Smart package's hot path only.
var (
	jsonMarshal   = gojson.Marshal
	jsonUnmarshal = gojson.Unmarshal
)

// msgpackMagic is the first byte of a msgpack-encoded StatsRecord. The
// msgpack wire format for a fixmap (<=15 entries) starts with 0x80-0x8f;
// the plain map format uses 0xde. Either value is distinguishable from
// JSON's '{' (0x7b) on the first byte — so readers can sniff format.
//
// This lets us migrate recordStats data lazily: new writes are msgpack
// (smaller + faster), old JSON rows stay readable until they're
// overwritten on next update.
const msgpackMagic = 0x80 // fixmap prefix range starts here

// isMsgpack reports whether data looks like a msgpack payload. The test
// is cheap — just the first byte, no full parse.
func isMsgpack(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	first := data[0]
	// fixmap: 0x80-0x8f, map16: 0xde, map32: 0xdf
	return (first >= 0x80 && first <= 0x8f) || first == 0xde || first == 0xdf
}

// MarshalStatsRecord encodes a StatsRecord for bbolt storage.
//
// Benchmarked goccy/go-json vs msgpack/v5 on the float-heavy StatsRecord
// shape: goccy produced smaller output (247 vs 277 bytes) AND faster
// encode (750 ns / 2 allocs vs 1044 ns / 10 allocs). goccy's JIT-
// specialised encoder beats msgpack's reflect path on this struct, so
// we stay on JSON for the write side.
//
// The read side (UnmarshalStatsRecord) keeps the msgpack-fallback sniff
// anyway — dirt-cheap (one byte compare) and future-proofs the store
// against a format change without another migration round.
func MarshalStatsRecord(r *StatsRecord) ([]byte, error) {
	return jsonMarshal(r)
}

// UnmarshalStatsRecord dispatches to msgpack or JSON based on a
// first-byte sniff, handling the migration window where bbolt still
// contains JSON records written by older builds.
func UnmarshalStatsRecord(data []byte, out *StatsRecord) error {
	if isMsgpack(data) {
		dec := msgpack.NewDecoder(bytes.NewReader(data))
		dec.SetCustomStructTag("json")
		return dec.Decode(out)
	}
	return jsonUnmarshal(data, out)
}
