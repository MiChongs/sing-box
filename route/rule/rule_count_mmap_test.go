//go:build unix

package rule

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// iOS 把规则集转成 mmap 后加载，域名/IP 只剩压缩结构，计数同样要完整展开。
func TestRuleSetRuleCountMmap(t *testing.T) {
	t.Parallel()
	compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(ruleCountTestSource))
	require.NoError(t, err)
	file, err := os.Create(filepath.Join(t.TempDir(), "rule-set.mmap"))
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, srs.WriteMmap(file, compat))
	mmap, err := srs.ReadMmap(file)
	require.NoError(t, err)
	plain, err := mmap.Upgrade()
	require.NoError(t, err)
	ruleSet := newRuleCountTestRuleSet(C.RuleSetFormatBinary)
	require.NoError(t, ruleSet.reloadRules(plain.Rules, ruleSet))
	require.Equal(t, uint64(ruleCountTestExpected), ruleSet.RuleCount())
}
