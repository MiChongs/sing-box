//go:build go1.24

package bundle

import "testing"

func TestCarrierBundleSessionIDRandomErrorPersists(t *testing.T) {
	t.Skip("crypto/rand.Read no longer returns errors in Go 1.24+ (see https://go.dev/issue/66821)")
}
