package nowhere

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
)

func TestResolveMatrixDefaultsAndPool(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		in          MatrixInputs
		wantUp      string
		wantDown    string
		wantPool    int
		wantMux     bundle.MuxMode
		wantAsym    bool
		wantQUIC    bool
		wantTCP     bool
		wantMix     bool
		wantWarning bool
		wantErr     bool
	}{
		{name: "default-udp-udp", wantUp: "udp", wantDown: "udp", wantQUIC: true},
		{name: "tcp-tcp-default-pool", in: MatrixInputs{Up: "tcp", Down: "tcp"}, wantUp: "tcp", wantDown: "tcp", wantPool: 5, wantTCP: true},
		{name: "tcp-tcp-explicit-pool", in: MatrixInputs{Up: "tcp", Down: "tcp", Pool: intPtr(3)}, wantUp: "tcp", wantDown: "tcp", wantPool: 3, wantTCP: true},
		{name: "tcp-tcp-large-valid-pool", in: MatrixInputs{Up: "tcp", Down: "tcp", Pool: intPtr(99)}, wantUp: "tcp", wantDown: "tcp", wantPool: 99, wantTCP: true},
		{name: "tcp-tcp-over-limit-clamped", in: MatrixInputs{Up: "tcp", Down: "tcp", Pool: intPtr(257)}, wantUp: "tcp", wantDown: "tcp", wantPool: 256, wantTCP: true, wantWarning: true},
		{name: "udp-udp-forces-pool-zero", in: MatrixInputs{Up: "udp", Down: "udp", Pool: intPtr(5)}, wantUp: "udp", wantDown: "udp", wantQUIC: true, wantWarning: true},
		{name: "udp-udp-explicit-zero", in: MatrixInputs{Up: "udp", Down: "udp", Pool: intPtr(0)}, wantUp: "udp", wantDown: "udp", wantQUIC: true},
		{name: "tcp-udp-forces-pool-zero", in: MatrixInputs{Up: "tcp", Down: "udp", Pool: intPtr(5)}, wantUp: "tcp", wantDown: "udp", wantAsym: true, wantQUIC: true, wantTCP: true, wantWarning: true},
		{name: "udp-tcp-forces-pool-zero", in: MatrixInputs{Up: "udp", Down: "tcp", Pool: intPtr(5)}, wantUp: "udp", wantDown: "tcp", wantAsym: true, wantQUIC: true, wantTCP: true, wantWarning: true},
		{name: "one-sided-up", in: MatrixInputs{Up: "tcp"}, wantErr: true},
		{name: "one-sided-down", in: MatrixInputs{Down: "udp"}, wantErr: true},
		{name: "bad-carrier", in: MatrixInputs{Up: "quic", Down: "tcp"}, wantErr: true},
		{name: "negative-pool", in: MatrixInputs{Up: "tcp", Down: "tcp", Pool: intPtr(-1)}, wantErr: true},
		{name: "negative-pool-udp-ignored", in: MatrixInputs{Up: "udp", Down: "udp", Pool: intPtr(-1)}, wantUp: "udp", wantDown: "udp", wantQUIC: true, wantWarning: true},
		{name: "mix-mix", in: MatrixInputs{Up: "mix", Down: "mix"}, wantUp: "mix", wantDown: "mix", wantTCP: true, wantQUIC: true, wantMix: true},
		{name: "tcp-tcp-mux", in: MatrixInputs{Up: "tcp", Down: "tcp", Mux: intPtr(1), Pool: intPtr(5)}, wantUp: "tcp", wantDown: "tcp", wantTCP: true, wantMux: bundle.MuxEnabled, wantWarning: true},
		{name: "udp-udp-mux-canonicalized", in: MatrixInputs{Up: "udp", Down: "udp", Mux: intPtr(1)}, wantUp: "udp", wantDown: "udp", wantQUIC: true, wantWarning: true},
		{name: "invalid-mux", in: MatrixInputs{Mux: intPtr(2)}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveMatrix(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveMatrix: %v", err)
			}
			if got.Up != tc.wantUp || got.Down != tc.wantDown {
				t.Fatalf("up/down = %s/%s, want %s/%s", got.Up, got.Down, tc.wantUp, tc.wantDown)
			}
			if got.Pool != tc.wantPool {
				t.Fatalf("pool = %d, want %d", got.Pool, tc.wantPool)
			}
			if got.Mux != tc.wantMux {
				t.Fatalf("mux = %d, want %d", got.Mux, tc.wantMux)
			}
			if got.Asymmetric != tc.wantAsym {
				t.Fatalf("asymmetric = %v, want %v", got.Asymmetric, tc.wantAsym)
			}
			if got.NeedsQUIC != tc.wantQUIC || got.NeedsTCP != tc.wantTCP {
				t.Fatalf("needs quic/tcp = %v/%v, want %v/%v", got.NeedsQUIC, got.NeedsTCP, tc.wantQUIC, tc.wantTCP)
			}
			if got.MixEnabled() != tc.wantMix {
				t.Fatalf("mix = %v, want %v", got.MixEnabled(), tc.wantMix)
			}
			if (len(got.Warnings()) > 0) != tc.wantWarning {
				t.Fatalf("warnings = %v, want warning=%v", got.Warnings(), tc.wantWarning)
			}
			if got.RequiresFlowEnvelope() != tc.wantAsym {
				t.Fatalf("RequiresFlowEnvelope = %v, want %v", got.RequiresFlowEnvelope(), tc.wantAsym)
			}
			if tc.wantWarning {
				joined := strings.Join(got.Warnings(), "; ")
				if joined == "" {
					t.Fatal("expected warning text")
				}
			}
		})
	}
}

func intPtr(v int) *int { return &v }
