package nowhere

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func TestDecodePortalKey(t *testing.T) {
	t.Parallel()

	ok := []struct {
		name    string
		key     string
		wantKey string
	}{
		{name: "generated-length", key: strings.Repeat("a", 32)},
		{name: "odd-length", key: strings.Repeat("0", 33), wantKey: strings.Repeat("0", 33)},
		{name: "max-length", key: strings.Repeat("f", 64)},
		{name: "full-hex-alphabet", key: strings.Repeat("0123456789abcdef", 4)},
		{name: "percent-decoded", key: "%31" + strings.Repeat("a", 31), wantKey: "1" + strings.Repeat("a", 31)},
	}
	for _, testCase := range ok {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodePortalKey(testCase.key)
			if err != nil {
				t.Fatalf("decodePortalKey(%q) error = %v, want nil", testCase.key, err)
			}
			want := testCase.wantKey
			if want == "" {
				want = testCase.key
			}
			if got != want {
				t.Fatalf("decodePortalKey(%q) = %q, want %q", testCase.key, got, want)
			}
		})
	}

	bad := []struct {
		name string
		key  string
	}{
		{name: "too-short", key: strings.Repeat("a", 31)},
		{name: "too-long", key: strings.Repeat("a", 65)},
		{name: "uppercase", key: strings.Repeat("A", 32)},
		{name: "non-hex", key: "g" + strings.Repeat("a", 31)},
		{name: "leading-whitespace", key: " " + strings.Repeat("a", 32)},
		{name: "trailing-whitespace", key: strings.Repeat("a", 32) + " "},
		{name: "embedded-whitespace", key: strings.Repeat("a", 16) + " " + strings.Repeat("a", 15)},
		{name: "double-percent-leaves-percent", key: "%25" + strings.Repeat("a", 30)},
		{name: "malformed-escape", key: "%a" + strings.Repeat("a", 31)},
		{name: "empty", key: ""},
	}
	for _, testCase := range bad {
		t.Run("reject-"+testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodePortalKey(testCase.key); err == nil {
				t.Fatalf("decodePortalKey(%q) error = nil, want rejection", testCase.key)
			}
		})
	}
}

func TestNewInboundRejectsShortPortalListenerKey(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: "secret",
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, ALPN: badoption.Listable[string]{"nw2"}},
		},
	})
	if err == nil {
		t.Fatal("short Portal listener key accepted")
	}
	if !strings.Contains(err.Error(), "32\u201364 lowercase hexadecimal") {
		t.Fatalf("error = %v, want Portal key rule", err)
	}
}

func TestNewInboundRejectsShortNextPortalKey(t *testing.T) {
	t.Parallel()
	_, certPEM, keyPEM := chainTestKeyPair(t)
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password: testPortalKey,
		Network:  option.NetworkList(N.NetworkTCP),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ALPN:        badoption.Listable[string]{"nw2"},
				Certificate: badoption.Listable[string]{string(certPEM)},
				Key:         badoption.Listable[string]{string(keyPEM)},
			},
		},
		Next: &option.NowhereNextOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2080},
			Password:      "origin-key",
			Up:            "tcp",
			Down:          "tcp",
		},
	})
	if err == nil {
		t.Fatal("short next-hop key accepted")
	}
	if !strings.Contains(err.Error(), "32\u201364 lowercase hexadecimal") {
		t.Fatalf("error = %v, want Portal key rule", err)
	}
}
