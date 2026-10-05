package rule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAbstractRuleStatistics(t *testing.T) {
	var rule abstractRule
	require.Zero(t, rule.HitCount())
	require.Zero(t, rule.MissCount())
	// 与 mihomo 一致：从未命中时读出 Unix 纪元
	require.True(t, rule.HitAt().Equal(time.Unix(0, 0)))
	require.True(t, rule.MissAt().Equal(time.Unix(0, 0)))

	before := time.Now()
	rule.Hit()
	rule.Hit()
	rule.Miss()
	require.Equal(t, uint64(2), rule.HitCount())
	require.Equal(t, uint64(1), rule.MissCount())
	// atomicTime 丢弃单调时钟，用 Round(0) 按墙钟比较
	require.False(t, rule.HitAt().Before(before.Round(0)))
	require.False(t, rule.MissAt().Before(before.Round(0)))
	require.False(t, rule.HitAt().After(time.Now().Round(0)))
}

func TestAbstractRuleSetDisabled(t *testing.T) {
	var rule abstractRule
	rule.SetDisabled(true)
	require.True(t, rule.Disabled())
	rule.SetDisabled(true)
	require.True(t, rule.Disabled())
	rule.SetDisabled(false)
	require.False(t, rule.Disabled())
	rule.ChangeStatus()
	require.True(t, rule.Disabled())
}
