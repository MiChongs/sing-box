package assetdl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// recordingTransport stands in for an http_client transport: it adds a
// header the way a configured client does and counts its use.
type recordingTransport struct {
	requests atomic.Int32
	idle     atomic.Int32
}

func (t *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.requests.Add(1)
	request = request.Clone(request.Context())
	request.Header.Set("X-Client", "configured")
	return http.DefaultTransport.RoundTrip(request)
}

func (t *recordingTransport) CloseIdleConnections() { t.idle.Add(1) }
func (t *recordingTransport) Reset()                {}

func TestFetchUsesTransport(t *testing.T) {
	var header atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header.Store(r.Header.Get("X-Client"))
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()

	transport := &recordingTransport{}
	path := filepath.Join(t.TempDir(), "nested", "asset.bin")
	var updates atomic.Int32
	dl, err := New(Options{
		Context:   context.Background(),
		URL:       server.URL,
		Interval:  time.Hour,
		Path:      path,
		Transport: transport,
		OnUpdate:  func(string) error { updates.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The one-shot path creates the directory itself.
	if err := dl.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "payload" {
		t.Fatalf("file = %q, %v", content, err)
	}
	if transport.requests.Load() != 1 || header.Load() != "configured" {
		t.Fatalf("request did not go through the transport: requests=%d header=%v", transport.requests.Load(), header.Load())
	}
	if transport.idle.Load() == 0 {
		t.Fatal("idle connections kept after the download")
	}
	// An unchanged asset is neither rewritten nor reported.
	if err := dl.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 1 {
		t.Fatalf("updates = %d, want 1", updates.Load())
	}
}

// TestMissingFileRetried: a missing file whose download fails is retried
// until it succeeds, both one-shot and with periodic updates.
func TestMissingFileRetried(t *testing.T) {
	defer func(minDelay, maxDelay time.Duration) {
		missingRetryMin, missingRetryMax = minDelay, maxDelay
	}(missingRetryMin, missingRetryMax)
	missingRetryMin, missingRetryMax = 10*time.Millisecond, 40*time.Millisecond

	for _, periodic := range []bool{false, true} {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if requests.Add(1) <= 2 {
				http.NotFound(w, nil)
				return
			}
			_, _ = w.Write([]byte("payload"))
		}))
		path := filepath.Join(t.TempDir(), "asset.bin")
		dl, err := New(Options{URL: server.URL, Interval: time.Hour, Path: path})
		if err != nil {
			t.Fatal(err)
		}
		if periodic {
			dl.Start()
		} else {
			dl.StartMissing()
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(path); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("periodic=%v: file never downloaded after %d requests", periodic, requests.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = dl.Close()
		server.Close()
		if got := requests.Load(); got != 3 {
			t.Fatalf("periodic=%v: %d requests, want 3", periodic, got)
		}
	}
}
