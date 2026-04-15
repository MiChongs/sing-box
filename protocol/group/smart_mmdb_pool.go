package group

import (
	"os"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/oschwald/maxminddb-golang"
	"github.com/puzpuzpuz/xsync/v3"
	"golang.org/x/sync/singleflight"
)

// mmdbPool is a process-wide deduplicated loader for maxminddb files.
//
// Problem it solves: with 15+ Smart groups referencing the same ASN
// database files (e.g. every group has use_asn=true against the
// GeoX-downloaded GeoLite2-ASN.mmdb), each group used to call
// maxminddb.Open() independently. Each Open() creates:
//
//   - A new file handle (Android has aggressive per-process FD limits)
//   - A new mmap region (visible in RSS even though read-only)
//   - A new *maxminddb.Reader struct holding decoder state
//
// 16 groups × 2 ASN files = 32 mmap regions where 2 would suffice. On
// Android, mmap regions over limit causes mmap() to fail and the group
// falls back to bare-IP routing (silent quality degradation).
//
// The pool uses two indexes so both the get and release paths are O(1):
//
//   - forwardPool: keyed by (abs path, size, mtime) — lookup on acquire
//     so a file replaced via GeoX auto-update naturally produces a new
//     reader on next lookup.
//   - reverseIndex: keyed by the *maxminddb.Reader pointer — lookup on
//     release so the refcount can be decremented without scanning.
//
// Concurrent acquires of the same key are deduplicated by golang.org/x/sync
// singleflight so we only call maxminddb.Open() once even if every Smart
// group races to hydrate during startup. Previously the hand-rolled
// double-check pattern (unlock → Open → relock → re-check) could end up
// calling Open() multiple times if several goroutines lost the race —
// singleflight collapses the entire op into a single in-flight call.
//
// Both maps are xsync.MapOf which gives lock-free reads and sharded-lock
// writes; the hot "already loaded" path is fully lock-free.

type mmdbKey struct {
	path  string
	size  int64
	mtime int64 // unix nano — nanosecond-resolution stat
}

func (k mmdbKey) sfKey() string {
	// singleflight wants a string; encode all three fields so two paths
	// with identical basename don't collide and a file replaced in place
	// (same path, different mtime) races on a distinct key.
	return k.path + "|" + strconv.FormatInt(k.size, 10) + "|" + strconv.FormatInt(k.mtime, 10)
}

type sharedMMDBReader struct {
	reader   *maxminddb.Reader
	key      mmdbKey
	refcount atomic.Int32
}

var (
	forwardPool  = xsync.NewMapOf[mmdbKey, *sharedMMDBReader]()
	reverseIndex = xsync.NewMapOf[uintptr, *sharedMMDBReader]()
	sfOpen       singleflight.Group
)

// readerAddr returns the stable pointer identity used as the reverse
// index key. We key on the *maxminddb.Reader pointer (not value) since
// callers always hold the same pointer they got from getSharedMMDB,
// right up to when they call releaseSharedMMDB.
func readerAddr(r *maxminddb.Reader) uintptr {
	return uintptr(unsafe.Pointer(r))
}

// getSharedMMDB returns a refcounted reader for path. The caller MUST
// pair this with releaseSharedMMDB when no longer needed, or the
// underlying mmap region will leak.
//
// Returns (nil, err) when the file is missing or malformed — matches the
// contract of maxminddb.Open so callers can fall through to "no ASN DB
// configured" path.
func getSharedMMDB(path string) (*maxminddb.Reader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	key := mmdbKey{
		path:  path,
		size:  info.Size(),
		mtime: info.ModTime().UnixNano(),
	}

	// Fast path: already loaded. The MapOf read is lock-free.
	if shared, ok := forwardPool.Load(key); ok {
		shared.refcount.Add(1)
		return shared.reader, nil
	}

	// Slow path: collapse concurrent opens onto a single maxminddb.Open
	// call. All racing callers wait on the same singleflight entry and
	// share the resulting *sharedMMDBReader.
	v, err, _ := sfOpen.Do(key.sfKey(), func() (interface{}, error) {
		// Re-check the map under singleflight — a previous caller may
		// have finished while we were queueing.
		if shared, ok := forwardPool.Load(key); ok {
			return shared, nil
		}
		reader, openErr := maxminddb.Open(path)
		if openErr != nil {
			return nil, openErr
		}
		shared := &sharedMMDBReader{
			reader: reader,
			key:    key,
		}
		shared.refcount.Store(0) // caller increments below
		forwardPool.Store(key, shared)
		reverseIndex.Store(readerAddr(reader), shared)
		return shared, nil
	})
	if err != nil {
		return nil, err
	}
	shared := v.(*sharedMMDBReader)
	shared.refcount.Add(1)
	return shared.reader, nil
}

// releaseSharedMMDB decrements the refcount on the reader obtained from
// getSharedMMDB. When the refcount hits zero the reader is closed and
// its mmap region released.
//
// Nil-safe. Unknown readers (e.g. if the caller opened directly without
// the pool) are silently ignored.
func releaseSharedMMDB(reader *maxminddb.Reader) {
	if reader == nil {
		return
	}
	shared, ok := reverseIndex.Load(readerAddr(reader))
	if !ok {
		return
	}
	if shared.refcount.Add(-1) > 0 {
		return
	}
	// Refcount hit zero — tear down. Compute-with-delete to avoid racing a
	// concurrent acquire that just re-incremented and wants to keep the
	// reader alive: inside the compute callback the bucket is locked, so
	// no acquirer can observe the stale entry while we verify it.
	var shouldClose bool
	forwardPool.Compute(shared.key, func(old *sharedMMDBReader, loaded bool) (*sharedMMDBReader, bool) {
		if !loaded || old != shared {
			// Another goroutine already replaced or removed the entry.
			return old, !loaded
		}
		if shared.refcount.Load() > 0 {
			// Concurrent acquire raced in after our decrement. Keep it.
			return shared, false
		}
		shouldClose = true
		return shared, true // delete
	})
	if !shouldClose {
		return
	}
	reverseIndex.Delete(readerAddr(reader))
	// Forget the singleflight entry so a subsequent acquire re-opens.
	sfOpen.Forget(shared.key.sfKey())
	_ = reader.Close()
}
