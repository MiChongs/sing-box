package smart

import (
	gojson "github.com/goccy/go-json"
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
