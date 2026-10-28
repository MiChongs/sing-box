//go:build linux

package process

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProcessPathGlobalHitSkipsUIDScan(t *testing.T) {
	var scopes []uint32
	c := newProcessPathCache(func(_ context.Context, uid uint32) (processPathIndex, error) {
		scopes = append(scopes, uid)
		if uid == processPathsAllUsers {
			return pathIndex(map[uint32][]string{1: {"netd"}, 2: {"netd", "helper"}}), nil
		}
		return processPathIndex{}, nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 1, 10001, true)
	require.NoError(t, err)
	paths, err := c.find(context.Background(), 2, 10002, true)
	require.NoError(t, err)
	require.Equal(t, []string{"netd", "helper"}, paths)
	require.Equal(t, []uint32{10001, processPathsAllUsers}, scopes)
}

func TestProcessPathNewInodeAndLoggingBudget(t *testing.T) {
	var calls atomic.Int32
	c := newProcessPathCache(func(_ context.Context, uid uint32) (processPathIndex, error) {
		calls.Add(1)
		if uid == processPathsAllUsers {
			return pathIndex(map[uint32][]string{uint32(calls.Load()): {"netd"}}), nil
		}
		return processPathIndex{}, nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 2, 10001, false)
	require.NoError(t, err)
	_, err = c.find(context.Background(), 4, 10001, false)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 2, calls.Load())
	// A deferred logging lookup must not poison the full lookup's cache.
	paths, err := c.find(context.Background(), 4, 10001, true)
	require.NoError(t, err)
	require.Equal(t, []string{"netd"}, paths)
	require.EqualValues(t, 4, calls.Load())
}

func TestProcessPathNegativeCache(t *testing.T) {
	var calls atomic.Int32
	var clock atomic.Int64
	c := newProcessPathCache(func(context.Context, uint32) (processPathIndex, error) { calls.Add(1); return processPathIndex{}, nil })
	c.now = func() time.Time { return time.Unix(0, clock.Load()) }
	defer c.close()
	for range 2 {
		_, err := c.find(context.Background(), 1, 10001, true)
		require.ErrorIs(t, err, ErrNotFound)
	}
	require.EqualValues(t, 2, calls.Load())
	// A different inode is not a cached miss, even within the lifetime.
	_, err := c.find(context.Background(), 2, 10001, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 4, calls.Load())
	clock.Store(int64(processPathMissLifetime + time.Nanosecond))
	_, err = c.find(context.Background(), 1, 10001, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 6, calls.Load())
}

func TestProcessPathConcurrentScanAndCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c := newProcessPathCache(func(context.Context, uint32) (processPathIndex, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return pathIndex(map[uint32][]string{1: {"one"}, 2: {"two"}}), nil
	})
	defer c.close()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.find(ctx, 1, 42, true); first <- err }()
	<-started
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			paths, err := c.find(context.Background(), 2, 42, true)
			require.NoError(t, err)
			require.Equal(t, []string{"two"}, paths)
		})
	}
	close(release)
	group.Wait()
	require.EqualValues(t, 1, calls.Load())
}

func TestProcessPathResetDiscardsOldScan(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c := newProcessPathCache(func(_ context.Context, _ uint32) (processPathIndex, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return pathIndex(map[uint32][]string{1: {"old"}}), nil
		}
		return pathIndex(map[uint32][]string{1: {"new"}}), nil
	})
	defer c.close()
	result := make(chan error, 1)
	go func() { _, err := c.find(context.Background(), 1, 42, true); result <- err }()
	<-started
	c.access.Lock()
	oldScan := c.scans[42]
	c.access.Unlock()
	c.reset()
	require.ErrorIs(t, <-result, context.Canceled)
	paths, err := c.find(context.Background(), 1, 42, true)
	require.NoError(t, err)
	require.Equal(t, []string{"new"}, paths)
	close(release)
	<-oldScan.done
	require.Equal(t, []string{"new"}, c.cached(1, 42))
	c.close()
	_, err = c.find(context.Background(), 1, 42, true)
	require.ErrorIs(t, err, context.Canceled)
}

func TestProcessPathScanErrorIsNotNegativeCached(t *testing.T) {
	var calls atomic.Int32
	failure := errors.New("procfs unavailable")
	c := newProcessPathCache(func(context.Context, uint32) (processPathIndex, error) {
		if calls.Add(1) == 1 {
			return processPathIndex{}, failure
		}
		return pathIndex(map[uint32][]string{1: {"ok"}}), nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 1, 42, true)
	require.ErrorIs(t, err, failure)
	paths, err := c.find(context.Background(), 1, 42, true)
	require.NoError(t, err)
	require.Equal(t, []string{"ok"}, paths)
}

func TestProcessPathCacheCapacity(t *testing.T) {
	c := newProcessPathCache(func(context.Context, uint32) (processPathIndex, error) { return processPathIndex{}, nil })
	c.scanInterval = 0
	defer c.close()
	for i := range uint32(processPathMissCapacity + 10) {
		_, err := c.find(context.Background(), i, i, true)
		require.ErrorIs(t, err, ErrNotFound)
	}
	c.access.Lock()
	defer c.access.Unlock()
	require.LessOrEqual(t, len(c.snapshots), processPathCapacity)
	require.LessOrEqual(t, len(c.misses), processPathMissCapacity)
	require.LessOrEqual(t, len(c.scanStarts), processPathCapacity)
}

func TestProcessPathScansAreSpacedAndShared(t *testing.T) {
	var (
		calls  atomic.Int32
		starts = make(chan time.Time, 8)
	)
	c := newProcessPathCache(func(_ context.Context, uid uint32) (processPathIndex, error) {
		calls.Add(1)
		starts <- time.Now()
		return pathIndex(map[uint32][]string{uint32(calls.Load()): {"netd"}}), nil
	})
	c.scanInterval = 100 * time.Millisecond
	defer c.close()
	// The first required miss scans at once.
	_, err := c.find(context.Background(), 1, processPathsAllUsers, true)
	require.NoError(t, err)
	first := <-starts
	// Misses right after it wait for the next slot and share one scan,
	// which still starts after each of them arrived.
	requested := time.Now()
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			paths, findErr := c.find(context.Background(), 2, processPathsAllUsers, true)
			require.NoError(t, findErr)
			require.Equal(t, []string{"netd"}, paths)
		})
	}
	group.Wait()
	second := <-starts
	require.EqualValues(t, 2, calls.Load())
	require.GreaterOrEqual(t, second.Sub(first), c.scanInterval-5*time.Millisecond)
	require.True(t, second.After(requested))
}

func TestProcessPathDelayedScanCanceledByReset(t *testing.T) {
	var calls atomic.Int32
	c := newProcessPathCache(func(context.Context, uint32) (processPathIndex, error) {
		calls.Add(1)
		return processPathIndex{}, nil
	})
	c.scanInterval = time.Hour
	defer c.close()
	_, err := c.find(context.Background(), 1, 42, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 2, calls.Load())
	result := make(chan error, 1)
	go func() { _, findErr := c.find(context.Background(), 2, 42, true); result <- findErr }()
	require.Eventually(t, func() bool {
		c.access.Lock()
		defer c.access.Unlock()
		return c.scans[42] != nil
	}, time.Second, time.Millisecond)
	c.reset()
	require.ErrorIs(t, <-result, context.Canceled)
	// After a reset the scope is scanned again without waiting.
	_, err = c.find(context.Background(), 2, 42, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 4, calls.Load())
}
