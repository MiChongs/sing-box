package smart

import (
	"strings"
	"testing"
)

// TestEscapeUnescapeKeyPart_Roundtrip covers the inverse property: any
// string survives FormatDBKey → SplitDBKey unchanged. Pulls in every
// pathological case we've actually shipped or could plausibly see in
// the wild: tag separators, control chars, raw quotes, RTL marks,
// CJK punctuation, multi-byte emoji clusters.
func TestEscapeUnescapeKeyPart_Roundtrip(t *testing.T) {
	cases := []string{
		// trivial
		"",
		"plain",
		"with-dash",
		"with space",
		// path-fragment hazards (the original /用户案例)
		"ENET/🇳🇿 Base 新西兰",
		"a/b/c/d",
		"/",
		// percent + escape-the-escape
		"50% off",
		"%",
		"%2F", // user typed a literal escape sequence
		"%/%",
		"100% organic / fair-trade",
		// ASCII control characters
		"with\nnewline",
		"with\ttab",
		"with\rcarriage-return",
		"with\x00null-in-middle",
		"\x01\x02\x03\x1F\x7F", // every control byte category
		// quotes / shell-hostile chars
		`name "with quotes"`,
		`back\slash`,
		`semi;colon`,
		`pipe|bar`,
		`amp&persand`,
		// emoji + flags + skin tone (multi-codepoint clusters)
		"🚀 Smart",
		"👨‍👩‍👧‍👦 family",
		"👋🏻 wave",
		"🇭🇰🇯🇵🇺🇸",
		// CJK / RTL / mixed scripts
		"🚀 香港 节点 01",
		"日本 - JP - 🇯🇵",
		"שלום עולם", // Hebrew RTL
		"العربية",   // Arabic
		"Ｆｕｌｌｗｉｄｔｈ", // full-width Latin
		// raw bytes that aren't valid UTF-8 (theoretical: should still round-trip)
		"\xFE\xFF\x00",
		// long mixed
		strings.Repeat("混合/with%special\x00chars-🚀 ", 20),
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			esc := escapeKeyPart(in)
			// The escaped form must NEVER contain raw control bytes,
			// raw `/`, or anything that would corrupt a subsequent
			// strings.Split parse.
			for i := 0; i < len(esc); i++ {
				c := esc[i]
				if c == '/' {
					t.Fatalf("escaped form contains raw /: %q (orig %q)", esc, in)
				}
				if c < 0x20 || c == 0x7F {
					t.Fatalf("escaped form contains raw control byte 0x%02X: %q", c, esc)
				}
			}
			got := UnescapeKeyPart(esc)
			if got != in {
				t.Fatalf("roundtrip lost data:\n in  = %q\n esc = %q\n got = %q", in, esc, got)
			}
		})
	}
}

// TestEscapeKeyPart_FastPathMatchesSafeInput is the cheap-path
// invariant: keys that don't contain any encoding-required byte
// must come back as the SAME string (no allocation, no surprises).
// Important because most production keys hit this path on every
// dial.
func TestEscapeKeyPart_FastPathMatchesSafeInput(t *testing.T) {
	safe := []string{
		"HK-1",
		"*.gstatic.com",
		"🇭🇰 香港 01",
		"node:tagged",
		"www.example.com:443",
		"A_B-C.d",
	}
	for _, s := range safe {
		t.Run(s, func(t *testing.T) {
			esc := escapeKeyPart(s)
			if esc != s {
				t.Fatalf("safe input mutated: %q → %q", s, esc)
			}
		})
	}
}

// TestUnescapeKeyPart_AllByteValues stress-tests the decoder over
// every possible byte value (0–255). The encoder must produce a form
// the decoder reliably reverses.
func TestUnescapeKeyPart_AllByteValues(t *testing.T) {
	for b := 0; b < 256; b++ {
		in := string([]byte{byte(b)})
		esc := escapeKeyPart(in)
		got := UnescapeKeyPart(esc)
		if got != in {
			t.Fatalf("byte 0x%02X: roundtrip failed esc=%q got=%q", b, esc, got)
		}
	}
}

// TestFormatDBKey_PreservesSlashTag drives the actual user-visible
// regression: a stats key for an outbound named "ENET/🇳🇿 ..." used
// to fragment into 7 path segments, breaking every downstream parser.
// After the fix it stays a single path segment.
func TestFormatDBKey_PreservesSlashTag(t *testing.T) {
	const target = "*.gstatic.com"
	const node = "ENET/🇳🇿 Base 新西兰"
	key := FormatDBKey(KeyTypeStats, "singbox", "🚀 Smart", target, node)

	// The 5 path segments after "smart" map to keyType / config /
	// group / target / node — exactly 6 total.
	parts := strings.Split(key, "/")
	if len(parts) != 6 {
		t.Fatalf("key has %d segments, want 6: %q (parts=%v)", len(parts), key, parts)
	}
	// SplitDBKey reverses the escape so callers see the original
	// node / target values intact.
	got := SplitDBKey(key)
	want := []string{KeyTypeStats, "singbox", "🚀 Smart", target, node}
	if len(got) != len(want) {
		t.Fatalf("SplitDBKey len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SplitDBKey[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestUnescapeKeyPart_TolerantToOldData: bbolt rows written before
// the escape fix don't contain `%2F` — their `/` characters are
// literal path separators and there's nothing the unescaper can do.
// Verify the unescape function still handles them gracefully (returns
// the input unchanged when no escape sequences present) instead of
// erroring out and dropping the row.
func TestUnescapeKeyPart_TolerantToOldData(t *testing.T) {
	cases := []string{
		"plain-no-escape",
		"a/b/c", // literal slashes from old data
		"50%X",  // malformed escape — leave as-is
		"%",     // bare percent — no change
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := UnescapeKeyPart(in); got != in {
				t.Fatalf("UnescapeKeyPart(%q) = %q, want unchanged", in, got)
			}
		})
	}
}
