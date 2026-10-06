//go:build with_quic

package quicx

import "testing"

func TestParseBBRProfile(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		expected string
		wantErr  bool
	}{
		{name: "default", expected: "conservative"},
		{name: "conservative", profile: "conservative", expected: "conservative"},
		{name: "standard", profile: "standard", expected: "standard"},
		{name: "aggressive", profile: "aggressive", expected: "aggressive"},
		{name: "unknown", profile: "unknown", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, err := parseBBRProfile(test.profile)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if profile.Name() != test.expected {
				t.Fatalf("expected profile %q, got %q", test.expected, profile.Name())
			}
		})
	}
}
