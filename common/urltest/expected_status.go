package urltest

import (
	"errors"
	"strconv"
	"strings"
)

// StatusMatcher 判定一个 HTTP 响应状态码是否被 urltest 视为 "成功"。
// 对齐 mihomo/clash-meta 的 expected-status 字段语法，Clash 用户可以直接
// 搬运配置:
//
//   "204"              单个状态码
//   "200"              单个状态码
//   "200-299"          范围（闭区间）
//   "200/204"          多值列表（/ 分隔）
//   "200-299/301-302"  范围 + 列表组合
//   "*" 或 ""          任意成功语义（见 Default 逻辑）
//
// 为什么 "" 不等于 "match anything": mihomo 对 empty 值 与 "*" 的处理
// 有差别 —— empty 走默认（多数实现是 200-299/301-308），"*" 是完全不管。
// 我们在这里把 empty 视为 nil matcher，上层拿到 nil 时回退到旧的硬编码
// 行为（gstatic.com/generate_204 要求 204，其他 < 400 即可）。
type StatusMatcher struct {
	// 显式 ranges：[lo, hi] 闭区间。空 slice = matchAny。
	ranges [][2]int
	// matchAny: expected_status="*" 时 true，其他语法构造出来的 matcher 是 false
	matchAny bool
}

// MatchAny 返回一个对所有状态码都 OK 的 matcher。语义等同 expected-status="*"。
func MatchAny() *StatusMatcher {
	return &StatusMatcher{matchAny: true}
}

// ParseExpectedStatus 按 mihomo 语法解析 expected-status 配置字符串。
// 规则:
//   - 空串 / "*"   → MatchAny()
//   - "200"        → [200, 200]
//   - "200-299"    → [200, 299]
//   - "a/b/c"      → 对每段递归解析并合并
//
// 失败返回 error；配置阶段错误立即暴露给用户。
//
// 单个状态码越界 (< 100 或 > 599) / 范围 lo > hi / 非数字会报错。
func ParseExpectedStatus(s string) (*StatusMatcher, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return MatchAny(), nil
	}
	m := &StatusMatcher{}
	for _, part := range strings.Split(s, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '-'); idx > 0 {
			lo, errLo := strconv.Atoi(strings.TrimSpace(part[:idx]))
			hi, errHi := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if errLo != nil || errHi != nil {
				return nil, errors.New("urltest: invalid expected-status range: " + part)
			}
			if !validCode(lo) || !validCode(hi) || lo > hi {
				return nil, errors.New("urltest: out-of-range expected-status: " + part)
			}
			m.ranges = append(m.ranges, [2]int{lo, hi})
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, errors.New("urltest: invalid expected-status: " + part)
		}
		if !validCode(n) {
			return nil, errors.New("urltest: out-of-range expected-status: " + part)
		}
		m.ranges = append(m.ranges, [2]int{n, n})
	}
	if len(m.ranges) == 0 {
		return MatchAny(), nil
	}
	return m, nil
}

// Match 查询状态码是否通过。
func (m *StatusMatcher) Match(code int) bool {
	if m == nil || m.matchAny {
		return true
	}
	for _, r := range m.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}

// String 供日志/错误信息打印用。empty matcher 返回 "*"，方便排障时看。
func (m *StatusMatcher) String() string {
	if m == nil || m.matchAny {
		return "*"
	}
	var b strings.Builder
	for i, r := range m.ranges {
		if i > 0 {
			b.WriteByte('/')
		}
		if r[0] == r[1] {
			b.WriteString(strconv.Itoa(r[0]))
		} else {
			b.WriteString(strconv.Itoa(r[0]))
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(r[1]))
		}
	}
	return b.String()
}

func validCode(n int) bool { return n >= 100 && n <= 599 }
