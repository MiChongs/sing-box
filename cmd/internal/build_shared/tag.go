package build_shared

import (
	"strings"

	"github.com/sagernet/sing-box/common/badversion"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/shell"
)

// normalizeTag 将 git tag 中遗留的 reF1nd fork 标识统一替换为当前 fork 标识 xiaobaf14g。
// 保证所有构建产物（二进制内嵌版本字符串、压缩包文件名、CHANGELOG 等）后缀一致，
// 避免从上游/reF1nd 分支同步 tag 后版本字符串混乱。
func normalizeTag(tag string) string {
	return strings.ReplaceAll(tag, "reF1nd", "xiaobaf14g")
}

func ReadTag() (string, error) {
	currentTag, err := shell.Exec("git", "describe", "--tags").ReadOutput()
	if err != nil {
		return currentTag, err
	}
	currentTag = normalizeTag(currentTag)
	currentTagRev, _ := shell.Exec("git", "describe", "--tags", "--abbrev=0").ReadOutput()
	currentTagRev = normalizeTag(currentTagRev)
	if currentTagRev == currentTag {
		return currentTag[1:], nil
	}
	shortCommit, _ := shell.Exec("git", "rev-parse", "--short", "HEAD").ReadOutput()
	version := badversion.Parse(currentTagRev[1:])
	return version.String() + "-" + shortCommit, nil
}

func ReadTagVersionRev() (badversion.Version, error) {
	currentTagRev := common.Must1(shell.Exec("git", "describe", "--tags", "--abbrev=0").ReadOutput())
	currentTagRev = normalizeTag(currentTagRev)
	return badversion.Parse(currentTagRev[1:]), nil
}

func ReadTagVersion() (badversion.Version, error) {
	currentTag := common.Must1(shell.Exec("git", "describe", "--tags").ReadOutput())
	currentTagRev := common.Must1(shell.Exec("git", "describe", "--tags", "--abbrev=0").ReadOutput())
	currentTag = normalizeTag(currentTag)
	currentTagRev = normalizeTag(currentTagRev)
	version := badversion.Parse(currentTagRev[1:])
	if currentTagRev != currentTag {
		if version.PreReleaseIdentifier == "" {
			version.Patch++
		}
	}
	return version, nil
}
