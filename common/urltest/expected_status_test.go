package urltest

import "testing"

func TestParseExpectedStatus(t *testing.T) {
	tcs := []struct {
		input  string
		checks map[int]bool // code -> expected Match
		err    bool
	}{
		{"", map[int]bool{200: true, 404: true, 500: true}, false},             // matchAny
		{"*", map[int]bool{100: true, 599: true}, false},                        // matchAny
		{"204", map[int]bool{204: true, 200: false, 205: false}, false},         // single
		{"200-299", map[int]bool{200: true, 250: true, 299: true, 300: false}, false},
		{"200/204", map[int]bool{200: true, 204: true, 201: false}, false},     // list
		{"200-299/301-302", map[int]bool{200: true, 250: true, 299: true, 301: true, 302: true, 300: false, 400: false}, false},
		{"  200 - 299  ", map[int]bool{200: true, 299: true}, false},           // whitespace
		{"abc", nil, true}, // invalid
		{"99", nil, true},  // below 100
		{"600", nil, true}, // above 599
		{"300-200", nil, true}, // inverted range
		{"200-abc", nil, true}, // half-broken range
	}
	for _, tc := range tcs {
		m, err := ParseExpectedStatus(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("[%q] expected error, got match=%v", tc.input, m)
			}
			continue
		}
		if err != nil {
			t.Errorf("[%q] unexpected error: %v", tc.input, err)
			continue
		}
		for code, want := range tc.checks {
			if got := m.Match(code); got != want {
				t.Errorf("[%q] code=%d got=%v want=%v", tc.input, code, got, want)
			}
		}
	}
}

func TestMatchAnyMatchesAll(t *testing.T) {
	m := MatchAny()
	for code := 100; code <= 599; code++ {
		if !m.Match(code) {
			t.Errorf("MatchAny rejected code=%d", code)
		}
	}
}

func TestNilMatcherMatchesAll(t *testing.T) {
	// nil matcher acts as MatchAny (caller-side convention: nil = no explicit filter)
	var m *StatusMatcher
	if !m.Match(200) || !m.Match(500) {
		t.Fatal("nil matcher should return true for any code")
	}
}

func TestStatusMatcherString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "*"},
		{"*", "*"},
		{"204", "204"},
		{"200-299", "200-299"},
		{"200/204", "200/204"},
		{"200-299/301-302", "200-299/301-302"},
	}
	for _, c := range cases {
		m, err := ParseExpectedStatus(c.input)
		if err != nil {
			t.Fatalf("[%q] parse: %v", c.input, err)
		}
		if got := m.String(); got != c.want {
			t.Errorf("[%q] String=%q want %q", c.input, got, c.want)
		}
	}
}
