#!/usr/bin/env bash
# CLS-Certify 版本检查工具
# 通过 GitHub Raw URL 检查远程仓库是否有新版本
#
# 用法:
#   bash tools/check-update.sh          # 人类可读输出
#   bash tools/check-update.sh --json   # JSON 输出
#
# build 格式: YYYYMMDD.NNNN（如 20260317.0002）

set -euo pipefail

# ─── 参数 ───
OUTPUT_JSON=false
for arg in "$@"; do
  case "$arg" in
    --json) OUTPUT_JSON=true ;;
  esac
done

# ─── 常量 ───
RAW_URL="https://raw.githubusercontent.com/catrefuse/cls-certify/main/SKILL.md"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_FILE="$SCRIPT_DIR/../SKILL.md"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── 读取本地版本 ───
read_local_version() {
  if [[ ! -f "$SKILL_FILE" ]]; then
    echo "ERROR: SKILL.md not found at $SKILL_FILE" >&2
    return 1
  fi

  LOCAL_VERSION=$(sed -n 's/^version: *//p' "$SKILL_FILE" | head -1 | tr -d '[:space:]')
  LOCAL_BUILD=$(sed -n 's/^build: *//p' "$SKILL_FILE" | head -1 | tr -d '[:space:]')

  if [[ -z "$LOCAL_VERSION" || -z "$LOCAL_BUILD" ]]; then
    echo "ERROR: Could not parse version/build from SKILL.md" >&2
    return 1
  fi
}

# ─── 读取远程版本 ───
read_remote_version() {
  if ! command -v curl &>/dev/null; then
    echo "SKIP: curl not installed" >&2
    return 1
  fi

  local content
  content=$(curl -fsSL --connect-timeout 5 --max-time 10 "$RAW_URL" 2>/dev/null) || return 1

  REMOTE_VERSION=$(echo "$content" | sed -n 's/^version: *//p' | head -1 | tr -d '[:space:]')
  REMOTE_BUILD=$(echo "$content" | sed -n 's/^build: *//p' | head -1 | tr -d '[:space:]')

  if [[ -z "$REMOTE_VERSION" || -z "$REMOTE_BUILD" ]]; then
    echo "SKIP: Could not parse remote version/build" >&2
    return 1
  fi
}

# ─── 比较 build 号 ───
# build 格式: YYYYMMDD.NNNN（如 20260317.0002）
# 零填充序号保证字符串比较等价于数值比较
is_remote_newer() {
  [[ "$REMOTE_BUILD" > "$LOCAL_BUILD" ]]
}

# ─── 主逻辑 ───
main() {
  read_local_version || exit 0

  local update_available=false
  local remote_ok=true

  if ! read_remote_version; then
    remote_ok=false
    REMOTE_VERSION=""
    REMOTE_BUILD=""
  fi

  if [[ "$remote_ok" == true ]] && is_remote_newer; then
    update_available=true
  fi

  if [[ "$OUTPUT_JSON" == true ]]; then
    cat <<EOF
{
  "tool": "cls-check-update",
  "local_version": "$LOCAL_VERSION",
  "local_build": "$LOCAL_BUILD",
  "remote_version": "${REMOTE_VERSION:-unknown}",
  "remote_build": "${REMOTE_BUILD:-unknown}",
  "update_available": $update_available,
  "update_command": "cd $PROJECT_DIR && git pull"
}
EOF
  else
    echo "CLS-Certify 版本检查"
    echo "  本地: v$LOCAL_VERSION (build $LOCAL_BUILD)"
    if [[ "$remote_ok" == true ]]; then
      echo "  远程: v$REMOTE_VERSION (build $REMOTE_BUILD)"
      if [[ "$update_available" == true ]]; then
        echo "  ⚠ 有新版本可用！运行以下命令更新："
        echo "    cd $PROJECT_DIR && git pull"
      else
        echo "  ✓ 已是最新版本"
      fi
    else
      echo "  远程: 检查跳过（网络不可用）"
    fi
  fi

  if [[ "$update_available" == true ]]; then
    return 1
  fi
  return 0
}

main
