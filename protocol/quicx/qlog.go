//go:build with_quic

package quicx

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// defaultQLOGMaxSize bounds the total size of a qlog directory when the
// configuration does not set qlog_max_size: 300 MiB.
const defaultQLOGMaxSize = 300 * 1024 * 1024

// qlogClientSuffix and qlogServerSuffix name the traces this package writes.
// Pruning only removes files matching them, so a directory shared with other
// files stays untouched.
const (
	qlogClientSuffix = "_client.sqlog"
	qlogServerSuffix = "_server.sqlog"
)

var qlogFileSuffixes = []string{qlogClientSuffix, qlogServerSuffix}

// qlogTracer is the per-connection tracer accepted by the QUICX client and
// service. It is called once for every QUIC connection and returns the trace
// the connection records its events into, or nil to leave it untraced.
type qlogTracer = func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace

// newQLOGTracer returns a tracer writing one qlog trace per QUIC connection
// into directory, named after the original destination connection id like
// quic-go's QLOGDIR: <connection id>_<client|server>.sqlog.
//
// The directory is created here, so a path that cannot be used fails the
// configuration instead of silently disabling tracing. The total size of the
// directory is bounded to maxSize; a non-positive maxSize selects
// defaultQLOGMaxSize. Completed traces are deleted oldest first once the
// directory exceeds the limit, so tracing can be left on without the directory
// growing forever.
func newQLOGTracer(instanceLogger logger.Logger, directory string, maxSize int64) (qlogTracer, error) {
	store, err := newQLOGStore(instanceLogger, directory, normalizeQLOGMaxSize(maxSize))
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		suffix := qlogServerSuffix
		if isClient {
			suffix = qlogClientSuffix
		}
		path := filepath.Join(directory, connID.String()+suffix)
		file, err := store.create(path)
		if err != nil {
			instanceLogger.Error(E.Cause(err, "create qlog file ", path))
			return nil
		}
		trace := qlogwriter.NewConnectionFileSeq(file, isClient, connID, []string{qlog.EventSchema})
		go trace.Run()
		return trace
	}, nil
}

// normalizeQLOGMaxSize selects the default limit for an unset or invalid
// configuration value.
func normalizeQLOGMaxSize(maxSize int64) int64 {
	if maxSize <= 0 {
		return defaultQLOGMaxSize
	}
	return maxSize
}

// qlogStores shares one store per directory, so several endpoints tracing into
// the same directory agree on how full it is and never prune a trace another
// endpoint is still recording.
var (
	qlogStoresMu sync.Mutex
	qlogStores   = make(map[string]*qlogStore)
)

// qlogStore bounds the total size of one qlog directory. A trace that is still
// being recorded is never deleted or truncated, so a directory can exceed the
// limit while connections are open and is brought back under it as they close.
type qlogStore struct {
	logger    logger.Logger
	directory string
	maxSize   atomic.Int64

	// total approximates the bytes stored in the directory. It is updated on
	// every write and re-derived from the directory on every scan.
	total atomic.Int64

	mu   sync.Mutex
	open map[string]struct{}
}

func newQLOGStore(instanceLogger logger.Logger, directory string, maxSize int64) (*qlogStore, error) {
	key, err := filepath.Abs(directory)
	if err != nil {
		key = directory
	}
	qlogStoresMu.Lock()
	defer qlogStoresMu.Unlock()
	store, loaded := qlogStores[key]
	if loaded {
		// A smaller limit configured for the same directory wins, so the
		// stricter of the configured limits is always honoured.
		if maxSize < store.maxSize.Load() {
			store.maxSize.Store(maxSize)
		}
		return store, nil
	}
	err = os.MkdirAll(directory, 0o755)
	if err != nil {
		return nil, E.Cause(err, "create qlog directory ", directory)
	}
	store = &qlogStore{
		logger:    instanceLogger,
		directory: directory,
		open:      make(map[string]struct{}),
	}
	store.maxSize.Store(maxSize)
	// Traces left behind by a previous run count towards the limit and are
	// pruned here when the directory already exceeds it.
	store.prune()
	qlogStores[key] = store
	return store, nil
}

// create opens a new trace file, making room first so a directory at the limit
// does not keep growing just because new connections keep arriving. The path is
// registered before the file exists, so a concurrent prune cannot remove it in
// the window between creation and registration.
func (s *qlogStore) create(path string) (*qlogFile, error) {
	s.pruneIfNeeded()
	s.mu.Lock()
	s.open[path] = struct{}{}
	s.mu.Unlock()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		s.mu.Lock()
		delete(s.open, path)
		s.mu.Unlock()
		return nil, err
	}
	return newQLOGFile(s, path, file), nil
}

// release marks a trace as complete, allowing it to be pruned, and enforces
// the limit afterwards.
func (s *qlogStore) release(path string) {
	s.mu.Lock()
	delete(s.open, path)
	s.mu.Unlock()
	s.pruneIfNeeded()
}

func (s *qlogStore) grow(size int64) {
	s.total.Add(size)
}

func (s *qlogStore) pruneIfNeeded() {
	if s.total.Load() <= s.maxSize.Load() {
		return
	}
	s.prune()
}

// prune scans the directory and deletes the oldest complete traces until what
// is left fits into maxSize. The scan also resynchronises total, so files
// removed outside this store are noticed.
func (s *qlogStore) prune() {
	files, total, err := s.scan()
	if err != nil {
		s.logger.Error(E.Cause(err, "scan qlog directory ", s.directory))
		return
	}
	maxSize := s.maxSize.Load()
	if total > maxSize {
		s.mu.Lock()
		open := make(map[string]struct{}, len(s.open))
		for path := range s.open {
			open[path] = struct{}{}
		}
		s.mu.Unlock()
		for _, file := range files {
			if total <= maxSize {
				break
			}
			if _, isOpen := open[file.path]; isOpen {
				continue
			}
			err = os.Remove(file.path)
			if err != nil && !os.IsNotExist(err) {
				s.logger.Error(E.Cause(err, "remove qlog file ", file.path))
				continue
			}
			total -= file.size
		}
	}
	s.total.Store(total)
}

type qlogCandidate struct {
	path    string
	size    int64
	modTime time.Time
}

func (s *qlogStore) scan() ([]qlogCandidate, int64, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, 0, err
	}
	var (
		files []qlogCandidate
		total int64
	)
	for _, entry := range entries {
		if entry.IsDir() || !isQLOGFile(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, qlogCandidate{
			path:    filepath.Join(s.directory, entry.Name()),
			size:    info.Size(),
			modTime: info.ModTime(),
		})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].path < files[j].path
		}
		return files[i].modTime.Before(files[j].modTime)
	})
	return files, total, nil
}

func isQLOGFile(name string) bool {
	for _, suffix := range qlogFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// qlogFile buffers the events of one trace: quic-go encodes the qlog JSON
// token by token, so without buffering every connection would issue one write
// syscall per token. quic-go closes the trace together with its connection,
// which flushes the buffer here and releases the file for pruning.
type qlogFile struct {
	store  *qlogStore
	path   string
	writer *bufio.Writer
	file   *os.File
	closed atomic.Bool
}

func newQLOGFile(store *qlogStore, path string, file *os.File) *qlogFile {
	return &qlogFile{
		store:  store,
		path:   path,
		writer: bufio.NewWriter(file),
		file:   file,
	}
}

func (f *qlogFile) Write(p []byte) (int, error) {
	n, err := f.writer.Write(p)
	if n > 0 {
		f.store.grow(int64(n))
	}
	return n, err
}

func (f *qlogFile) Close() error {
	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := errors.Join(f.writer.Flush(), f.file.Close())
	f.store.release(f.path)
	return err
}
