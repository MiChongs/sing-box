package anyx

import (
	"maps"
	"slices"
	"strings"
)

type settings map[string]string

func (s settings) Bytes() []byte {
	var builder strings.Builder
	for index, key := range slices.Sorted(maps.Keys(s)) {
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(s[key])
	}
	return []byte(builder.String())
}

func parseSettings(data []byte) settings {
	parsed := make(settings)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		key, value, found := strings.Cut(line, "=")
		if found {
			parsed[key] = value
		}
	}
	return parsed
}
