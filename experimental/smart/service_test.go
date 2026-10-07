package smart

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// TestModelFetchedOnlyWhenMissing: with auto_update off, a missing model is
// downloaded once at startup, while a model file that exists is never
// re-downloaded — whether it loads or not.
func TestModelFetchedOnlyWhenMissing(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "common", "smart", "lightgbm", "testdata", "named_v4.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	for _, tc := range []struct {
		name         string
		existing     []byte // nil: no file
		wantRequests int32
		wantLoaded   bool
	}{
		{"missing", nil, 1, true},
		{"usable", fixture, 0, true},
		{"unusable", []byte("tree\nversion=v9\n"), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests.Store(0)
			path := filepath.Join(t.TempDir(), "model.bin")
			if tc.existing != nil {
				if err := os.WriteFile(path, tc.existing, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			s := NewService(context.Background(), logger.NOP(), option.SmartOptions{
				LightGBM: &option.SmartLightGBMOptions{ModelPath: path, URL: server.URL},
			})
			defer s.close()
			model, err := s.WeightModel()
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && (requests.Load() < tc.wantRequests || tc.wantLoaded && !model.IsLoaded()) {
				time.Sleep(10 * time.Millisecond)
			}
			// Leave time for an unwanted fetch to show up.
			time.Sleep(200 * time.Millisecond)
			if got := requests.Load(); got != tc.wantRequests {
				t.Errorf("downloads = %d, want %d", got, tc.wantRequests)
			}
			if model.IsLoaded() != tc.wantLoaded {
				t.Errorf("loaded = %v, want %v (load error: %v)", model.IsLoaded(), tc.wantLoaded, model.LoadError())
			}
		})
	}
}
