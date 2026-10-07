// Package geodbtest builds minimal MaxMind databases for tests: IPv4-only
// files in which every address maps to one record.
package geodbtest

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// ASN returns a GeoLite2-ASN style database answering asn for every
// address.
func ASN(asn uint32) []byte {
	return database("GeoLite2-ASN", mapField(map[string][]byte{
		"autonomous_system_number": uintField(6, uint64(asn)),
	}))
}

// Country returns a GeoLite2-Country style database answering isoCode for
// every address.
func Country(isoCode string) []byte {
	return database("GeoLite2-Country", mapField(map[string][]byte{
		"country": mapField(map[string][]byte{
			"iso_code": stringField(isoCode),
		}),
	}))
}

// database lays out a one-node search tree whose two records both point at
// the start of the data section, so every lookup resolves to record.
func database(databaseType string, record []byte) []byte {
	const nodeCount = 1
	var out bytes.Buffer
	// Record values past nodeCount point into the data section, offset by
	// the 16-byte separator.
	pointer := uint32(nodeCount + 16)
	for range 2 {
		out.Write([]byte{byte(pointer >> 16), byte(pointer >> 8), byte(pointer)})
	}
	out.Write(make([]byte, 16))
	out.Write(record)
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	out.Write(mapField(map[string][]byte{
		"binary_format_major_version": uintField(5, 2),
		"binary_format_minor_version": uintField(5, 0),
		"build_epoch":                 uintField(9, 1700000000),
		"database_type":               stringField(databaseType),
		"ip_version":                  uintField(5, 4),
		"node_count":                  uintField(6, nodeCount),
		"record_size":                 uintField(5, 24),
	}))
	return out.Bytes()
}

// control encodes a field header; types past 7 use the extended form.
func control(fieldType byte, size int) []byte {
	if size >= 29 {
		panic("geodbtest: field too large")
	}
	if fieldType <= 7 {
		return []byte{fieldType<<5 | byte(size)}
	}
	return []byte{byte(size), fieldType - 7}
}

func stringField(value string) []byte {
	return append(control(2, len(value)), value...)
}

// uintField encodes value as a uint16 (5), uint32 (6) or uint64 (9).
func uintField(fieldType byte, value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	trimmed := bytes.TrimLeft(raw[:], "\x00")
	return append(control(fieldType, len(trimmed)), trimmed...)
}

func mapField(entries map[string][]byte) []byte {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := control(7, len(entries))
	for _, key := range keys {
		out = append(out, stringField(key)...)
		out = append(out, entries[key]...)
	}
	return out
}
