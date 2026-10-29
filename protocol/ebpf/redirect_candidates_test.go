//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/MiChongs/sing-ebpf"
)

// Every redirect candidate must pass the data plane's own validation, or the
// inbound fails to start.
func TestRedirectCandidatesAreAccepted(t *testing.T) {
	for _, prefix := range append(append(redirectIPv4Candidates[:0:0], redirectIPv4Candidates...), redirectIPv6Candidates...) {
		if err := commonEBPF.ValidateRedirectPrefix(prefix); err != nil {
			t.Errorf("%s: %v", prefix, err)
		}
	}
}
