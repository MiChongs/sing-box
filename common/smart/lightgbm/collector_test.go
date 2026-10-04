package lightgbm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/smart"
)

// TestCollectorSizeLimitLatch: once the CSV exceeds its cap, samples are
// dropped without touching the file, and collection resumes after the
// periodic flush notices the file was removed.
func TestCollectorSizeLimitLatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "samples.csv")
	c, err := NewDataCollector(path, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.sizeLimit = 1 // bytes: the header alone exceeds it

	input := &smart.ModelInput{Success: 3, GroupName: "g", NodeName: "n"}
	c.AddSample(input, nil, 1.0, "traditional")
	if c.WrittenRows() != 1 {
		t.Fatalf("first sample not written: written=%d dropped=%d", c.WrittenRows(), c.DroppedRows())
	}
	for i := 0; i < 5; i++ {
		c.AddSample(input, nil, 1.0, "traditional")
	}
	if c.DroppedRows() != 5 || !c.limitReached {
		t.Fatalf("over-limit samples: dropped=%d latched=%v", c.DroppedRows(), c.limitReached)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.Flush()
	if c.limitReached {
		t.Fatal("flush should clear the latch once the file is gone")
	}
	c.AddSample(input, nil, 1.0, "traditional")
	if c.WrittenRows() != 2 {
		t.Fatalf("collection did not resume: written=%d", c.WrittenRows())
	}
}
