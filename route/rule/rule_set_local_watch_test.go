package rule

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func matchLocalRuleSetDomain(ruleSet *LocalRuleSet, domain string) bool {
	return ruleSet.Match(&adapter.InboundContext{Domain: domain, Destination: M.Socksaddr{Fqdn: domain}})
}

// Editors save atomically: they write a temporary file and rename it over the
// original, which changes the inode the watcher was attached to.
func TestLocalRuleSetReloadsAfterAtomicRename(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "rules.json")
	writeRules := func(domain string) {
		temporaryPath := filepath.Join(directory, ".rules.json.tmp")
		require.NoError(t, os.WriteFile(temporaryPath, []byte(`{"version":3,"rules":[{"domain":["`+domain+`"]}]}`), 0o644))
		require.NoError(t, os.Rename(temporaryPath, path))
	}
	writeRules("before.example")
	ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "test", option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Format: C.RuleSetFormatSource,
		Path:   path,
	})
	require.NoError(t, err)
	defer ruleSet.Close()
	require.NoError(t, ruleSet.StartContext(context.Background(), nil))
	require.True(t, matchLocalRuleSetDomain(ruleSet, "before.example"))

	for _, domain := range []string{"after.example", "again.example"} {
		writeRules(domain)
		require.Eventually(t, func() bool {
			return matchLocalRuleSetDomain(ruleSet, domain)
		}, 5*time.Second, 20*time.Millisecond, domain)
	}
}
