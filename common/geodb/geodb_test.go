package geodb_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/geodb"
	"github.com/sagernet/sing-box/common/geodb/geodbtest"
)

type asnRecord struct {
	AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
}

var testIP = netip.MustParseAddr("8.8.8.8")

func lookupASN(t *testing.T, database *geodb.Database) uint {
	t.Helper()
	var record asnRecord
	if err := database.Lookup(testIP, &record); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return record.AutonomousSystemNumber
}

// replace writes content next to path and renames it over path, the way
// downloads replace a file.
func replace(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func TestReloadSwapsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	replace(t, path, geodbtest.ASN(15169))

	first, err := geodb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := geodb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first != second {
		t.Fatal("users of one path got different databases")
	}
	if got := lookupASN(t, first); got != 15169 {
		t.Fatalf("ASN = %d, want 15169", got)
	}

	replace(t, path, geodbtest.ASN(13335))
	if loaded, err := geodb.Reload(path); !loaded || err != nil {
		t.Fatalf("Reload = %v, %v", loaded, err)
	}
	if got := lookupASN(t, second); got != 13335 {
		t.Fatalf("ASN after reload = %d, want 13335", got)
	}

	// A broken replacement keeps the loaded data.
	replace(t, path, []byte("not a database"))
	if _, err := geodb.Reload(path); err == nil {
		t.Fatal("Reload accepted a broken file")
	}
	if got := lookupASN(t, first); got != 13335 {
		t.Fatalf("ASN after failed reload = %d, want 13335", got)
	}
}

// TestOpenBeforeDownload: a database opened before its file exists starts
// answering once the file is downloaded and reloaded.
func TestOpenBeforeDownload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	database, err := geodb.Open(path)
	if err == nil {
		t.Fatal("Open of a missing file reported no error")
	}
	defer database.Close()
	if database.Loaded() {
		t.Fatal("missing file reported loaded")
	}
	var record asnRecord
	if err := database.Lookup(testIP, &record); !errors.Is(err, geodb.ErrNotLoaded) {
		t.Fatalf("lookup before load: %v", err)
	}

	replace(t, path, geodbtest.ASN(4134))
	if loaded, err := geodb.Reload(path); !loaded || err != nil {
		t.Fatalf("Reload = %v, %v", loaded, err)
	}
	if got := lookupASN(t, database); got != 4134 {
		t.Fatalf("ASN = %d, want 4134", got)
	}
}

func TestCloseReleasesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	replace(t, path, geodbtest.ASN(1))
	first, _ := geodb.Open(path)
	second, _ := geodb.Open(path)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if got := lookupASN(t, second); got != 1 {
		t.Fatalf("remaining user lost the database: ASN = %d", got)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if loaded, _ := geodb.Reload(path); loaded {
		t.Fatal("Reload found a database nobody has open")
	}
	reopened, err := geodb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened == first {
		t.Fatal("closed database was handed out again")
	}
}

// TestLookupDuringReload runs lookups against concurrent reloads; with
// -race it checks that no lookup reads data a reload has released.
func TestLookupDuringReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	replace(t, path, geodbtest.ASN(100))
	database, err := geodb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var record asnRecord
				if err := database.Lookup(testIP, &record); err != nil || record.AutonomousSystemNumber < 100 {
					t.Errorf("lookup = %d, %v", record.AutonomousSystemNumber, err)
					return
				}
			}
		}()
	}
	for i := uint32(101); i < 150; i++ {
		replace(t, path, geodbtest.ASN(i))
		if _, err := geodb.Reload(path); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if got := lookupASN(t, database); got != 149 {
		t.Fatalf("ASN = %d, want 149", got)
	}
}

func TestCountryDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	replace(t, path, geodbtest.Country("JP"))
	database, err := geodb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := database.Lookup(testIP, &record); err != nil || record.Country.ISOCode != "JP" {
		t.Fatalf("country = %q, %v", record.Country.ISOCode, err)
	}
}
