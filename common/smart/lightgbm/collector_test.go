package lightgbm

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
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

// TestCollectorHeaderMatchesRows: every row must have exactly one uniquely
// named header column per field, with the features named in model order.
func TestCollectorHeaderMatchesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "samples.csv")
	c, err := NewDataCollector(path, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.AddSample(&smart.ModelInput{Success: 3, GroupName: "g", NodeName: "n"}, nil, 1.0, "traditional")
	if c.WrittenRows() != 1 {
		t.Fatalf("sample not written: dropped=%d", c.DroppedRows())
	}
	c.Close()

	records := readCSV(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records, want header + 1 row", len(records))
	}
	header, row := records[0], records[1]
	if !slices.Equal(header, collectorHeader) {
		t.Fatalf("header = %v, want %v", header, collectorHeader)
	}
	if len(row) != len(header) {
		t.Fatalf("row has %d columns, header names %d", len(row), len(header))
	}
	seen := make(map[string]bool, len(header))
	for _, name := range header {
		if seen[name] {
			t.Fatalf("duplicate column name %q", name)
		}
		seen[name] = true
	}
	order := getDefaultFeatureOrder()
	for i := 0; i < MaxFeatureSize; i++ {
		if header[i] != order[i] {
			t.Fatalf("column %d = %q, want feature %q", i, header[i], order[i])
		}
	}
	for name, want := range map[string]string{
		"group_name":     "g",
		"node_name":      "n",
		"weight_source":  "traditional",
		"schema_version": collectorSchemaVersion,
	} {
		if got := row[slices.Index(header, name)]; got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestCollectorReplacesStaleHeader: a CSV written under another header is
// moved aside instead of receiving rows its header mislabels, and an empty
// file gets a header.
func TestCollectorReplacesStaleHeader(t *testing.T) {
	for name, content := range map[string]string{
		"stale": "success,failure,group_name\n1,0,g\n",
		"empty": "",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "samples.csv")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			c, err := NewDataCollector(path, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.AddSample(&smart.ModelInput{Success: 1, GroupName: "g", NodeName: "n"}, nil, 1.0, "traditional")
			c.Close()

			records := readCSV(t, path)
			if len(records) != 2 || !slices.Equal(records[0], collectorHeader) {
				t.Fatalf("records = %v, want current header + 1 row", records)
			}
			backups, _ := filepath.Glob(path + ".bak.*")
			if wantBackup := content != ""; (len(backups) == 1) != wantBackup {
				t.Fatalf("backups = %v, want backup: %v", backups, wantBackup)
			}
		})
	}
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	return records
}
