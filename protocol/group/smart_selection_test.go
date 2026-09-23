package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// TestRecordConnectionSelection verifies the winning member is stored on
// the connection metadata shared with the traffic tracker, which is what
// DELETE /connections/smart/{id} reads to block the node that actually
// carried the connection.
func TestRecordConnectionSelection(t *testing.T) {
	s := newSmartForSuspendTest(t)
	var metadata adapter.InboundContext
	ctx := adapter.WithContext(context.Background(), &metadata)

	// The tracker keeps a copy of the metadata taken before the dial.
	tracked := metadata

	s.recordConnectionSelection(ctx, "node-b")
	if got := tracked.SelectedOutbound(s.Tag()); got != "node-b" {
		t.Fatalf("SelectedOutbound = %q, want %q", got, "node-b")
	}

	// A dial without inbound metadata must be a no-op.
	s.recordConnectionSelection(context.Background(), "node-c")
}
