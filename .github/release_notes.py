#!/usr/bin/env python3
"""生成 xiaobaf14g GitHub Release 正文，输出到 stdout。

提交只取 first-parent 链：上游同步以合并提交进入分支，其中成百上千的上游
提交不逐条列出，只显示同步到的版本。产物文件名、大小和校验值 GitHub 的
Assets 区已经列出，正文只给按平台汇总的下载指引。
"""

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

MAIN_SECTIONS = [
    ("feat", "✨ 新功能"),
    ("fix", "🐛 问题修复"),
    ("perf", "⚡ 性能优化"),
    ("refactor", "♻️ 重构"),
]
OTHER_ICONS = {
    "docs": "📝",
    "documentation": "📝",
    "ci": "🔧",
    "build": "🔧",
    "test": "🧪",
    "tests": "🧪",
}
CONVENTIONAL = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s*(?P<subject>.+)$", re.I)
KNOWN_TYPES = {"feat", "fix", "perf", "refactor", "docs", "documentation", "ci", "build", "test", "tests", "chore", "style", "revert"}
UPSTREAM_VERSION = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)*")
MAX_ENTRIES = 100

PLATFORMS = [
    ("windows", "Windows"),
    ("darwin", "macOS"),
    ("linux", "Linux"),
    ("android", "Android"),
    ("freebsd", "FreeBSD"),
]
VARIANT_TOKENS = {"ebpf", "easytier", "v3", "v4", "glibc", "musl", "softfloat"}
ARCH_ORDER = ["amd64", "x64", "arm64", "arm64-v8a", "armeabi-v7a", "386", "x86_64", "x86", "arm-v7", "universal"]


def env(name, default=""):
    return os.environ.get(name, "") or default


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def resolve_range(tag):
    # workflow_dispatch 时 tag 要到发布那一步才创建，用当前检出的提交代替。
    try:
        target = git("rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}").strip()
    except subprocess.CalledProcessError:
        target = git("rev-parse", "HEAD").strip()
    previous = env("PREV")
    if not previous:
        # 只认祖先链上的 xiaobaf14g tag：同步进来的上游 tag 历史被改写过，
        # 与当前 tag 没有近的共同祖先。
        try:
            previous = git("describe", "--tags", "--abbrev=0", "--match", "v*-xiaobaf14g*", f"{target}^").strip()
        except subprocess.CalledProcessError:
            previous = ""
    return target, previous


def first_parent_log(target, previous, merges):
    revision = f"{previous}..{target}" if previous else target
    args = ["log", "--first-parent", "--format=%H%x1f%s", revision]
    args.insert(2, "--merges" if merges else "--no-merges")
    lines = git(*args).splitlines()
    return [line.split("\x1f", 1) for line in lines if line]


def commit_link(server, repo, sha):
    return f"[`{sha[:7]}`]({server}/{repo}/commit/{sha})"


def upstream_entry(subject):
    match = UPSTREAM_VERSION.search(subject)
    if not match:
        return re.sub(r"^merge(\(\d+\))?:\s*", "", subject, flags=re.I)
    version = match.group(0)
    if "ref1nd" in subject.lower():
        name, repo = "reF1nd", "reF1nd/sing-box"
    else:
        name, repo = "SagerNet", "SagerNet/sing-box"
    return f"{name} [`{version}`](https://github.com/{repo}/releases/tag/{version})"


def commit_entry(subject, link, icon=""):
    match = CONVENTIONAL.match(subject)
    prefix = f"{icon} " if icon else ""
    if not match or match.group("type").lower() not in KNOWN_TYPES:
        return f"- {prefix}{subject} {link}"
    text = match.group("subject")
    if match.group("scope"):
        text = f"**{match.group('scope')}**：{text}"
    if match.group("breaking"):
        text += " ⚠️ 不兼容变更"
    return f"- {prefix}{text} {link}"


def commit_type(subject):
    match = CONVENTIONAL.match(subject)
    if not match:
        return ""
    return match.group("type").lower()


def capped(entries, compare_url):
    if len(entries) <= MAX_ENTRIES:
        return entries
    rest = len(entries) - MAX_ENTRIES
    more = f"[完整对比]({compare_url})" if compare_url else "提交历史"
    return entries[:MAX_ENTRIES] + [f"- …另有 {rest} 项，见{more}"]


def ordered(names):
    known = [name for name in ARCH_ORDER if name in names]
    return known + sorted(names - set(known))


def scan_builds(builds, version):
    core = re.compile(rf"^sing-box-{re.escape(version)}-(?P<os>[a-z]+)-(?P<rest>.+?)\.(?:tar\.gz|zip)$")
    sfa = re.compile(rf"^SFA-{re.escape(version)}-(?:(?P<legacy>legacy-android-5)-)?(?P<abi>.+)\.apk$")
    sfw = re.compile(rf"^SFW-{re.escape(version)}-(?P<arch>.+)\.exe$")
    result = {
        "core": {},
        "variants": set(),
        "sfa": set(),
        "sfa_legacy": set(),
        "sfa_metadata": False,
        "sfw": set(),
        "sfl": [],
    }
    for name in sorted(path.name for path in builds.iterdir() if path.is_file()) if builds.is_dir() else []:
        if match := core.match(name):
            tokens = match.group("rest").split("-")
            result["variants"].update(token for token in tokens if token in VARIANT_TOKENS)
            arch = "-".join(token for token in tokens if token not in VARIANT_TOKENS)
            result["core"].setdefault(match.group("os"), set()).add(arch)
        elif match := sfa.match(name):
            result["sfa_legacy" if match.group("legacy") else "sfa"].add(match.group("abi"))
        elif name == "SFA-version-metadata.json":
            result["sfa_metadata"] = True
        elif match := sfw.match(name):
            result["sfw"].add(match.group("arch"))
        elif name.startswith("SFL-"):
            result["sfl"].append(name)
    return result


def sfl_formats(files):
    formats = []
    for suffix, label in ((".deb", "deb"), (".rpm", "rpm"), (".pkg.tar.zst", "pacman")):
        if any(name.endswith(suffix) for name in files):
            formats.append(label)
    return formats


def download_section(found, server):
    sfa_link = f"[SFA]({server}/{env('SFA_REPOSITORY')}/tree/{env('SFA_REF')})"
    sfd_url = f"{server}/{env('SFD_REPOSITORY')}/tree/{env('SFD_REF')}"
    gui = {}
    if found["sfa"]:
        gui["android"] = f"{sfa_link} " + " · ".join(ordered(found["sfa"]))
    if found["sfw"]:
        gui["windows"] = f"[SFW]({sfd_url}) " + " · ".join(ordered(found["sfw"]))
    if formats := sfl_formats(found["sfl"]):
        gui["linux"] = f"[SFL]({sfd_url}) " + " · ".join(formats)

    rows = []
    for key, label in PLATFORMS:
        architectures = found["core"].get(key)
        if not architectures and key not in gui:
            continue
        core_cell = " · ".join(ordered(architectures)) if architectures else "—"
        rows.append(f"| **{label}** | {core_cell} | {gui.get(key, '—')} |")
    if not rows:
        return []

    lines = ["### 📦 下载", "", "| 平台 | 命令行内核 | 图形客户端 |", "| :-- | :-- | :-- |", *rows, ""]
    legend = []
    if "ebpf" in found["variants"]:
        legend.append("`-ebpf` 含 eBPF 入站")
    if "easytier" in found["variants"]:
        legend.append("`-easytier` 含 EasyTier（实验性）")
    if found["variants"] & {"v3", "v4"}:
        legend.append("`-v3` / `-v4` 需较新的 x86-64 CPU")
    if found["sfa_legacy"]:
        legend.append("`legacy-android-5` 支持 Android 5+")
    if legend:
        lines += ["<sub>" + " · ".join(legend) + "</sub>", ""]
    tips = []
    if found["sfa"]:
        tips.append("SFA 包名 `io.reF1nd.sfa`，不能覆盖安装其他签名的同包名应用")
    if found["sfw"]:
        tips.append("SFW 为自签名，SmartScreen 提示未知发布者属正常")
    if found["sfl"]:
        tips.append("SFL 签名公钥见 `SFL-signing-key.asc`")
    tips.append("校验值见 `SHA256SUMS`")
    lines += ["<sub>" + " · ".join(tips) + "</sub>", ""]
    return lines


def build_problems(found, run_url):
    failed, skipped = [], []
    if env("EXPERIMENTAL_RES") != "success":
        failed.append("桌面实验版")
    if env("SKIP_ANDROID") == "true":
        skipped.append("Android")
    else:
        if env("ANDROID_RES") != "success":
            failed.append("Android 内核")
        if env("ANDROID_EXPERIMENTAL") != "success":
            failed.append("Android 实验版")
    if env("SKIP_GUI") == "true":
        skipped.append("图形客户端")
    else:
        # 产物不齐全也算失败：SFA 需要普通版、Android 5 版与 version metadata，
        # SFW 每个架构一个安装包，SFL 每个架构 deb / rpm / pacman 各一个。
        if not (found["sfa"] and found["sfa_legacy"] and found["sfa_metadata"]):
            failed.append("SFA")
        if len(found["sfw"]) != 3:
            failed.append("SFW")
        if len([name for name in found["sfl"] if not name.endswith(".asc")]) != 9:
            failed.append("SFL")
    lines = []
    if failed:
        lines.append(f"> ⚠️ **以下构建失败或不完整，未全部附带**：{'、'.join(failed)} · [构建日志]({run_url})")
    if skipped:
        if lines:
            lines.append(">")
        lines.append(f"> ⏭️ 本次跳过：{'、'.join(skipped)}")
    return lines + [""] if lines else []


def main():
    tag = env("TAG")
    server = env("SERVER_URL", "https://github.com")
    repo = env("REPO", "MiChongs/sing-box")
    run_url = f"{server}/{repo}/actions/runs/{env('RUN_ID')}"
    version = tag.removeprefix("v")
    base_version = re.sub(r"-xiaobaf14g\.\d+$", "", version)

    target, previous = resolve_range(tag)
    compare_url = f"{server}/{repo}/compare/{previous}...{tag}" if previous else ""

    meta = [f"基于 SagerNet **{base_version}**", "预发布" if env("IS_PRE") == "true" else "正式版"]
    meta.append(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    if compare_url:
        meta.append(f"[完整变更]({compare_url})")
    lines = [" · ".join(meta), ""]

    found = scan_builds(Path(env("BUILDS_DIR", "builds")), version)
    lines += build_problems(found, run_url)

    upstream = [f"- {upstream_entry(subject)}" for _, subject in first_parent_log(target, previous, True)] if previous else []
    if upstream:
        lines += ["### ⬆️ 上游同步", "", *upstream, ""]

    commits = first_parent_log(target, previous, False)
    for key, title in MAIN_SECTIONS:
        entries = [commit_entry(subject, commit_link(server, repo, sha)) for sha, subject in commits if commit_type(subject) == key]
        if entries:
            lines += [f"### {title}", "", *capped(entries, compare_url), ""]

    main_types = {key for key, _ in MAIN_SECTIONS}
    others = [
        commit_entry(subject, commit_link(server, repo, sha), OTHER_ICONS.get(commit_type(subject), "🧹"))
        for sha, subject in commits
        if commit_type(subject) not in main_types
    ]
    if others:
        lines += [f"<details><summary>其他改动（{len(others)}）</summary>", "", *capped(others, compare_url), "", "</details>", ""]
    if not upstream and not commits:
        lines += ["_本次没有代码改动。_", ""]

    lines += download_section(found, server)
    print("\n".join(lines).rstrip())


if __name__ == "__main__":
    main()
