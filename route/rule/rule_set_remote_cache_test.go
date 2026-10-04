package rule

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type ruleSetCacheStub struct {
	adapter.CacheFile
	saved  *adapter.SavedBinary
	stored []*adapter.SavedBinary
}

func (c *ruleSetCacheStub) LoadRuleSet(string) *adapter.SavedBinary {
	return c.saved
}

func (c *ruleSetCacheStub) SaveRuleSet(_ string, set *adapter.SavedBinary) error {
	c.stored = append(c.stored, set)
	return nil
}

func newCachedRemoteRuleSet(t *testing.T, content []byte, saved *adapter.SavedBinary) (*RemoteRuleSet, *ruleSetCacheStub, time.Time) {
	t.Helper()
	const url = "https://example.com/rules.json"
	path := filepath.Join(t.TempDir(), "rules.json")
	require.NoError(t, os.WriteFile(path, content, 0o644))
	modTime := time.Unix(1750000000, 0)
	require.NoError(t, os.Chtimes(path, modTime, modTime))
	urlHash := sha256.Sum256([]byte(url))
	if saved != nil {
		saved.URLHash = urlHash[:]
	}
	cache := &ruleSetCacheStub{saved: saved}
	return &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    context.Background(),
			logger: logger.NOP(),
			tag:    "remote",
			sType:  constant.RuleSetTypeRemote,
			format: constant.RuleSetFormatSource,
			path:   path,
		},
		url:       url,
		urlHash:   urlHash,
		cacheFile: cache,
	}, cache, modTime
}

const remoteRuleSetFixture = `{"version":1,"rules":[{"domain":["example.com"]}]}`

func TestRemoteRuleSetCachedFileMatchesRecord(t *testing.T) {
	t.Parallel()

	content := []byte(remoteRuleSetFixture)
	saved := &adapter.SavedBinary{Hash: hash.MakeHash(content), LastUpdated: time.Unix(1760000000, 0), LastEtag: `"etag"`}
	ruleSet, cache, _ := newCachedRemoteRuleSet(t, content, saved)
	loaded, err := ruleSet.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, saved.LastUpdated, ruleSet.lastUpdated)
	require.Equal(t, `"etag"`, ruleSet.lastEtag)
	require.Empty(t, cache.stored)
}

// A file replaced behind the cache record (another core version sharing the
// directory, or an external update) is loaded from disk instead of failing
// validation and forcing a download at startup.
func TestRemoteRuleSetLoadsFileReplacedBehindRecord(t *testing.T) {
	t.Parallel()

	content := []byte(remoteRuleSetFixture)
	saved := &adapter.SavedBinary{Hash: hash.MakeHash([]byte("previous file")), LastUpdated: time.Unix(1760000000, 0), LastEtag: `"previous"`}
	ruleSet, cache, modTime := newCachedRemoteRuleSet(t, content, saved)
	loaded, err := ruleSet.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, uint64(1), ruleSet.ruleCount)
	require.Equal(t, modTime, ruleSet.lastUpdated)
	require.Empty(t, ruleSet.lastEtag, "the old ETag describes another file")
	require.Equal(t, hash.MakeHash(content), ruleSet.hash)
	require.Len(t, cache.stored, 1)
	require.Equal(t, &adapter.SavedBinary{Hash: hash.MakeHash(content), LastUpdated: modTime, URLHash: saved.URLHash}, cache.stored[0])
}

func TestRemoteRuleSetRefetchesUnreadableReplacedFile(t *testing.T) {
	t.Parallel()

	saved := &adapter.SavedBinary{Hash: hash.MakeHash([]byte("previous file"))}
	ruleSet, cache, _ := newCachedRemoteRuleSet(t, []byte(`{"version":1,"rules":[`), saved)
	loaded, err := ruleSet.loadCacheFile()
	require.Error(t, err)
	require.False(t, loaded)
	require.Empty(t, cache.stored)
}
