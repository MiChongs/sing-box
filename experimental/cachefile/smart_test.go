package cachefile

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// TestSmartBucketSurvivesReopen: opening the cache file purges unknown
// buckets, so Smart data must be listed to outlive a restart or reload.
func TestSmartBucketSurvivesReopen(t *testing.T) {
	for _, cacheID := range []string{"", "profile"} {
		t.Run(cacheID, func(t *testing.T) {
			options := option.CacheFileOptions{Path: filepath.Join(t.TempDir(), "cache.db"), CacheID: cacheID}
			key := []byte("smart/stats/singbox/auto/example.com/node")
			open := func() (*CacheFile, *adapter.Scope) {
				cache := New(context.Background(), logger.NOP(), options)
				scope := adapter.NewScope(context.Background(), logger.NOP())
				require.NoError(t, cache.Start(adapter.StartStateInitialize, scope))
				return cache, scope
			}

			cache, scope := open()
			require.NoError(t, cache.SmartDB().Update(func(tx *bbolt.Tx) error {
				bucket, err := tx.CreateBucketIfNotExists([]byte(smart.BucketName))
				if err != nil {
					return err
				}
				return bucket.Put(key, []byte("record"))
			}))
			require.NoError(t, scope.Close())

			cache, scope = open()
			defer scope.Close()
			require.NoError(t, cache.SmartDB().View(func(tx *bbolt.Tx) error {
				bucket := tx.Bucket([]byte(smart.BucketName))
				require.NotNil(t, bucket, "smart bucket purged on reopen")
				require.Equal(t, []byte("record"), bucket.Get(key))
				return nil
			}))
		})
	}
}
