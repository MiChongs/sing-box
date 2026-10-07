package geox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geodb"
	"github.com/sagernet/sing-box/common/geodb/geodbtest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
)

// asnServer serves an ASN database answering the current value of asn.
func asnServer(t *testing.T, asn *atomic.Uint32) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(geodbtest.ASN(asn.Load()))
	}))
	t.Cleanup(server.Close)
	return server
}

func startService(t *testing.T, ctx context.Context, options option.GeoXOptions) *Service {
	t.Helper()
	s := NewService(ctx, logger.NOP(), options)
	scope := adapter.NewScope(ctx, logger.NOP())
	if err := s.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.Close() })
	return s
}

func dataDirContext(t *testing.T) context.Context {
	return filemanager.WithDefault(context.Background(), t.TempDir(), "", 0, 0)
}

// waitASN waits until database answers want for a public address.
func waitASN(t *testing.T, database *geodb.Database, want uint) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var record struct {
			AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
		}
		err := database.Lookup(netip.MustParseAddr("1.1.1.1"), &record)
		if err == nil && record.AutonomousSystemNumber == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ASN = %d (%v), want %d", record.AutonomousSystemNumber, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDownloadReloadsOpenDatabase: a database opened before its first
// download, and again on every update, answers with the downloaded data
// without being reopened.
func TestDownloadReloadsOpenDatabase(t *testing.T) {
	var asn atomic.Uint32
	asn.Store(15169)
	server := asnServer(t, &asn)
	ctx := dataDirContext(t)
	options := option.GeoXOptions{
		Enabled:        true,
		URL:            option.GeoXURLOptions{ASN: badoption.Listable[string]{server.URL}},
		AutoUpdate:     true,
		UpdateInterval: badoption.Duration(100 * time.Millisecond),
	}
	s := NewService(ctx, logger.NOP(), options)
	path := s.ASNPath()
	database, err := geodb.Open(path)
	if err == nil {
		t.Fatal("database existed before the first download")
	}
	defer database.Close()

	scope := adapter.NewScope(ctx, logger.NOP())
	if err := s.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	waitASN(t, database, 15169)

	asn.Store(13335)
	waitASN(t, database, 13335)
}

// TestRequireDefaultDatabases: default databases are downloaded on request,
// even with GeoX disabled, and reloaded for their users.
func TestRequireDefaultDatabases(t *testing.T) {
	var asn atomic.Uint32
	asn.Store(4134)
	server := asnServer(t, &asn)
	country := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(geodbtest.Country("SG"))
	}))
	defer country.Close()
	defer func(asnURL, mmdbURL string) { defaultASNURL, defaultMMDBURL = asnURL, mmdbURL }(defaultASNURL, defaultMMDBURL)
	defaultASNURL, defaultMMDBURL = server.URL, country.URL

	ctx := dataDirContext(t)
	s := startService(t, ctx, option.GeoXOptions{})
	path := s.RequireDefaultASN()
	if path != filemanager.BasePath(ctx, DefaultASNFilename) || s.RequireDefaultASN() != path {
		t.Fatalf("default ASN path = %q", path)
	}
	database, _ := geodb.Open(path)
	defer database.Close()
	waitASN(t, database, 4134)

	countryDB, _ := geodb.Open(s.RequireDefaultMMDB())
	defer countryDB.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !countryDB.Loaded() {
		if time.Now().After(deadline) {
			t.Fatal("default country database never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.ASNPath() != "" || s.MMDBPath() != "" {
		t.Fatal("default databases reported as configured")
	}
}

// TestExistingFileNotRedownloaded: without auto_update a file on disk is
// used as is.
func TestExistingFileNotRedownloaded(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(geodbtest.ASN(1))
	}))
	defer server.Close()
	ctx := dataDirContext(t)
	options := option.GeoXOptions{
		Enabled: true,
		URL:     option.GeoXURLOptions{ASN: badoption.Listable[string]{server.URL}},
	}
	s := startService(t, ctx, options)
	database, _ := geodb.Open(s.ASNPath())
	defer database.Close()
	waitASN(t, database, 1)
	if got := requests.Load(); got != 1 {
		t.Fatalf("first start downloaded %d times, want 1", got)
	}

	startService(t, ctx, options)
	time.Sleep(200 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("second start downloaded again: %d requests", got)
	}
}

func TestAssetPaths(t *testing.T) {
	ctx := dataDirContext(t)
	s := NewService(ctx, logger.NOP(), option.GeoXOptions{
		Enabled: true,
		URL:     option.GeoXURLOptions{ASN: badoption.Listable[string]{"http://a", "http://b"}},
	})
	paths := s.ASNPaths()
	if len(paths) != 2 || filepath.Base(paths[0]) != DefaultASNFilename || filepath.Base(paths[1]) != "GeoLite2-ASN-1.mmdb" {
		t.Fatalf("ASN paths = %v", paths)
	}
}
