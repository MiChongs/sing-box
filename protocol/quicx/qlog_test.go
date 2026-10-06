//go:build with_quic

package quicx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// TestQLOGTracerTrace checks that the tracer writes a readable qlog trace for
// both perspectives, named after the connection id like quic-go does.
func TestQLOGTracerTrace(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "qlog")
	tracer, err := newQLOGTracer(logger.NOP(), directory, 0)
	require.NoError(t, err)
	connID := quic.ConnectionIDFromBytes([]byte{0x01, 0x02, 0x03, 0x04})
	for _, testCase := range []struct {
		isClient    bool
		perspective string
	}{
		{isClient: true, perspective: "client"},
		{isClient: false, perspective: "server"},
	} {
		trace := tracer(context.Background(), testCase.isClient, connID)
		require.NotNil(t, trace, testCase.perspective)
		producer := trace.AddProducer()
		require.NotNil(t, producer, testCase.perspective)
		// Closing the last producer closes the trace and flushes the file.
		require.NoError(t, producer.Close(), testCase.perspective)

		content, err := os.ReadFile(filepath.Join(directory, connID.String()+"_"+testCase.perspective+".sqlog"))
		require.NoError(t, err, testCase.perspective)
		require.True(t, strings.HasPrefix(string(content), "\x1e"), testCase.perspective)
		require.Contains(t, string(content), `"file_schema":"urn:ietf:params:qlog:file:sequential"`, testCase.perspective)
		require.Contains(t, string(content), `"vantage_point":{"type":"`+testCase.perspective+`"}`, testCase.perspective)
		require.Contains(t, string(content), `"group_id":"`+connID.String()+`"`, testCase.perspective)
		require.Contains(t, string(content), `"event_schemas":["`+qlog.EventSchema+`"]`, testCase.perspective)
	}
}

// TestQLOGTracerDirectoryError checks that an unusable directory fails when the
// tracer is created, instead of leaving the instance running without traces.
func TestQLOGTracerDirectoryError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(path, []byte("qlog"), 0o644))
	_, err := newQLOGTracer(logger.NOP(), filepath.Join(path, "qlog"), 0)
	require.Error(t, err)
}

// TestQLOGTracerFileError checks that a trace that cannot be created leaves the
// connection running untraced.
func TestQLOGTracerFileError(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "qlog")
	tracer, err := newQLOGTracer(logger.NOP(), directory, 0)
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(directory))
	require.Nil(t, tracer(context.Background(), false, quic.ConnectionIDFromBytes([]byte{0x01})))
}

// TestQLOGMaxSizeDefault checks that a missing or non-positive limit selects
// the 300 MiB default while explicit limits are kept.
func TestQLOGMaxSizeDefault(t *testing.T) {
	require.EqualValues(t, 300*1024*1024, defaultQLOGMaxSize)
	require.EqualValues(t, defaultQLOGMaxSize, normalizeQLOGMaxSize(0))
	require.EqualValues(t, defaultQLOGMaxSize, normalizeQLOGMaxSize(-1))
	require.EqualValues(t, 1024, normalizeQLOGMaxSize(1024))
}

// TestQLOGStorePrunesOldest checks that a directory over the limit keeps the
// newest traces and drops the oldest completed ones.
func TestQLOGStorePrunesOldest(t *testing.T) {
	directory := t.TempDir()
	base := time.Now().Add(-time.Hour)
	oldest := qlogTestFile(t, directory, "01_client.sqlog", 60, base)
	newest := qlogTestFile(t, directory, "02_server.sqlog", 60, base.Add(time.Minute))

	store, err := newQLOGStore(logger.NOP(), directory, 100)
	require.NoError(t, err)

	_, err = os.Stat(oldest)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.FileExists(t, newest)
	require.EqualValues(t, 60, store.total.Load())
}

// TestQLOGStorePrunesOnRelease checks that completed traces are pruned as they
// close, not only when the store is created.
func TestQLOGStorePrunesOnRelease(t *testing.T) {
	directory := t.TempDir()
	store, err := newQLOGStore(logger.NOP(), directory, 100)
	require.NoError(t, err)
	first := filepath.Join(directory, "01_client.sqlog")
	qlogTestWrite(t, store, first, 60)
	require.FileExists(t, first)
	second := filepath.Join(directory, "02_client.sqlog")
	qlogTestWrite(t, store, second, 60)
	_, err = os.Stat(first)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.FileExists(t, second)
	require.EqualValues(t, 60, store.total.Load())
}

// TestQLOGStoreKeepsOpenTrace checks that pruning never removes a trace whose
// connection is still recording, even when that leaves the directory over the
// limit until the connection closes.
func TestQLOGStoreKeepsOpenTrace(t *testing.T) {
	directory := t.TempDir()
	store, err := newQLOGStore(logger.NOP(), directory, 100)
	require.NoError(t, err)
	completed := qlogTestFile(t, directory, "00_client.sqlog", 60, time.Now().Add(-time.Hour))
	openPath := filepath.Join(directory, "01_client.sqlog")
	openFile, err := store.create(openPath)
	require.NoError(t, err)
	_, err = openFile.Write(bytes.Repeat([]byte{'x'}, 150))
	require.NoError(t, err)
	// The store scans the directory, so the open trace has to reach the disk
	// to be accounted for here.
	require.NoError(t, openFile.writer.Flush())

	store.prune()
	_, err = os.Stat(completed)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.FileExists(t, openPath)
	require.Greater(t, store.total.Load(), int64(100))

	require.NoError(t, openFile.Close())
	require.LessOrEqual(t, store.total.Load(), int64(100))
}

// TestQLOGStoreKeepsUnrelatedFiles checks that only qlog traces count towards
// the limit and are pruned.
func TestQLOGStoreKeepsUnrelatedFiles(t *testing.T) {
	directory := t.TempDir()
	unrelated := filepath.Join(directory, "keep.txt")
	require.NoError(t, os.WriteFile(unrelated, bytes.Repeat([]byte{'k'}, 200), 0o644))
	qlogTestFile(t, directory, "01_client.sqlog", 200, time.Now())

	store, err := newQLOGStore(logger.NOP(), directory, 100)
	require.NoError(t, err)

	require.FileExists(t, unrelated)
	_, err = os.Stat(filepath.Join(directory, "01_client.sqlog"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.EqualValues(t, 0, store.total.Load())
}

// TestQLOGStoreAccountsWrites checks that written bytes are accounted for so
// pruning knows how full the directory is.
func TestQLOGStoreAccountsWrites(t *testing.T) {
	directory := t.TempDir()
	store, err := newQLOGStore(logger.NOP(), directory, 1<<20)
	require.NoError(t, err)
	file, err := store.create(filepath.Join(directory, "01_client.sqlog"))
	require.NoError(t, err)
	_, err = file.Write(bytes.Repeat([]byte{'x'}, 512))
	require.NoError(t, err)
	require.EqualValues(t, 512, store.total.Load())
	require.NoError(t, file.Close())
	require.EqualValues(t, 512, store.total.Load())
}

// TestQLOGStoreSharedPerDirectory checks that endpoints tracing into the same
// directory share one store and that the stricter limit wins.
func TestQLOGStoreSharedPerDirectory(t *testing.T) {
	directory := t.TempDir()
	store, err := newQLOGStore(logger.NOP(), directory, 100)
	require.NoError(t, err)
	shared, err := newQLOGStore(logger.NOP(), directory, 500)
	require.NoError(t, err)
	require.Same(t, store, shared)
	require.EqualValues(t, 100, store.maxSize.Load())
	stricter, err := newQLOGStore(logger.NOP(), directory, 50)
	require.NoError(t, err)
	require.Same(t, store, stricter)
	require.EqualValues(t, 50, store.maxSize.Load())
}

// TestQLOGStoreConcurrent checks that traces can be created, written and closed
// while other connections prune the directory, and that the limit is honoured
// once everything is complete.
func TestQLOGStoreConcurrent(t *testing.T) {
	directory := t.TempDir()
	store, err := newQLOGStore(logger.NOP(), directory, 4096)
	require.NoError(t, err)
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for round := 0; round < 32; round++ {
				path := filepath.Join(directory, fmt.Sprintf("%02d_%02d_client.sqlog", worker, round))
				file, err := store.create(path)
				if err != nil {
					continue
				}
				_, _ = file.Write(bytes.Repeat([]byte{'x'}, 256))
				_ = file.Close()
			}
		}(worker)
	}
	group.Wait()
	store.prune()
	_, total, err := store.scan()
	require.NoError(t, err)
	require.LessOrEqual(t, total, int64(4096))
	require.EqualValues(t, total, store.total.Load())
}

// qlogTestFile writes a qlog file of the given size with a fixed modification
// time, so pruning can be asserted deterministically.
func qlogTestFile(t *testing.T, directory string, name string, size int, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(directory, name)
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o644))
	require.NoError(t, os.Chtimes(path, modTime, modTime))
	return path
}

// qlogTestWrite records one complete trace of the given size through the store.
func qlogTestWrite(t *testing.T, store *qlogStore, path string, size int) {
	t.Helper()
	file, err := store.create(path)
	require.NoError(t, err)
	_, err = file.Write(bytes.Repeat([]byte{'x'}, size))
	require.NoError(t, err)
	require.NoError(t, file.Close())
}
