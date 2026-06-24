#!/usr/bin/env bash
# 本地多平台并行构建 — 与 .github/workflows/xiaobaf14g-release.yml 的
# desktop matrix 对齐。CGO=0 纯交叉编译路径；CGO=1 (linux-amd64-v3-glibc,
# linux-arm64-musl, android) 跳过 — 本地缺工具链。
#
# 用法: bash build-all.sh
# 输出: dist/sing-box-<version>-<goos>-<goarch><suffix>[.exe]

set -euo pipefail

VERSION="${VERSION:-$(go run ./cmd/internal/read_tag 2>/dev/null || echo dev)}"
DIST="${DIST:-dist}"

TAGS_WINDOWS='with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_purego,with_xhttp,badlinkname,tfogo_checklinkname0'
TAGS_FREEBSD='with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_ccm,with_ocm,with_cloudflared,with_xhttp,badlinkname,tfogo_checklinkname0'
TAGS_OTHERS='with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_xhttp,badlinkname,tfogo_checklinkname0'

LDFLAGS="-s -w -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -buildid= -X github.com/sagernet/sing-box/constant.Version=${VERSION}"

mkdir -p "$DIST" logs
rm -f logs/*.log

# 目标矩阵: goos goarch suffix tags_src ext extra_env
TARGETS=(
  # Windows
  "windows amd64 '' windows .exe ''"
  "windows arm64 '' windows .exe ''"
  "windows 386   '' windows .exe ''"
  # Linux (CGO=0; v3-glibc/arm64-musl 走 CI)
  "linux amd64 '' others '' ''"
  "linux arm64 '' others '' ''"
  "linux 386   '' others '' ''"
  "linux arm   -v7         others '' GOARM=7"
  "linux mipsle   -softfloat others '' GOMIPS=softfloat"
  "linux mips64le -softfloat others '' GOMIPS=softfloat"
  "linux riscv64 '' others '' ''"
  "linux loong64 '' others '' ''"
  # macOS
  "darwin amd64 '' others '' ''"
  "darwin arm64 '' others '' ''"
  # FreeBSD (drop with_tailscale)
  "freebsd amd64 '' freebsd '' ''"
  "freebsd arm64 '' freebsd '' ''"
)

build_one() {
  local goos="$1" goarch="$2" suffix="$3" tags_src="$4" ext="$5" extra_env="$6"
  # Strip placeholder quotes
  [[ "$suffix" == "''" ]] && suffix=''
  [[ "$ext"    == "''" ]] && ext=''
  [[ "$extra_env" == "''" ]] && extra_env=''

  local tags
  case "$tags_src" in
    windows) tags="$TAGS_WINDOWS" ;;
    freebsd) tags="$TAGS_FREEBSD" ;;
    others)  tags="$TAGS_OTHERS"  ;;
  esac

  local name="sing-box-${VERSION}-${goos}-${goarch}${suffix}"
  local bin="${DIST}/${name}${ext}"
  local log="logs/${goos}-${goarch}${suffix}.log"

  {
    echo "[$(date +%H:%M:%S)] BEGIN $name (tags=$tags_src env=$extra_env)"
    local extra_args=""
    if [[ -n "$extra_env" ]]; then
      extra_args="$extra_env"
    fi
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" $extra_args \
      go build -trimpath -buildvcs=false \
        -tags "$tags" \
        -ldflags "$LDFLAGS" \
        -o "$bin" ./cmd/sing-box
    echo "[$(date +%H:%M:%S)] DONE  $name"
    ls -lh "$bin"
  } >"$log" 2>&1 \
    && echo "✓ $name" \
    || { echo "✗ $name (see $log)"; return 1; }
}

export -f build_one
export VERSION DIST LDFLAGS TAGS_WINDOWS TAGS_FREEBSD TAGS_OTHERS

echo "== building ${#TARGETS[@]} targets in parallel =="
echo

pids=()
for t in "${TARGETS[@]}"; do
  eval "build_one $t" &
  pids+=("$!")
done

fail=0
for pid in "${pids[@]}"; do
  wait "$pid" || fail=$((fail+1))
done

echo
echo "== summary =="
ls -lh "$DIST" 2>/dev/null
echo
if (( fail > 0 )); then
  echo "FAILED: $fail / ${#TARGETS[@]}"
  exit 1
fi
echo "ALL ${#TARGETS[@]} TARGETS OK"
