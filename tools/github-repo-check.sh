#!/usr/bin/env bash
# CLS-Certify GitHub 仓库信誉检查工具
# 通过 gh api 评估 GitHub 仓库和作者的信誉，输出 T1/T2/T3 来源分级
#
# 用法:
#   ./tools/github-repo-check.sh <github_url_or_owner/repo> [--json]
#
# 示例:
#   ./tools/github-repo-check.sh https://github.com/vercel/next.js
#   ./tools/github-repo-check.sh facebook/react --json
#   ./tools/github-repo-check.sh https://github.com/someuser/somerepo.git

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
INPUT=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── T1 白名单 ───
T1_WHITELIST=(
    "google" "microsoft" "facebook" "meta" "anthropic" "openai"
    "apache" "mozilla" "vercel" "hashicorp" "elastic" "grafana"
    "docker" "kubernetes" "aws" "azure" "alibaba" "tencent"
    "baidu" "bytedance"
)

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify GitHub 仓库信誉检查工具"
    echo ""
    echo "用法: $0 <github_url_or_owner/repo> [options]"
    echo ""
    echo "支持的输入格式:"
    echo "  https://github.com/owner/repo"
    echo "  https://github.com/owner/repo.git"
    echo "  owner/repo"
    echo ""
    echo "选项:"
    echo "  --json    输出 JSON 格式"
    echo "  -h, --help  显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) INPUT="$1"; shift ;;
    esac
done

if [[ -z "$INPUT" ]]; then
    echo "错误: 请指定 GitHub 仓库 URL 或 owner/repo"
    usage
fi

# ─── 检测 gh CLI ───
if ! command -v gh &>/dev/null; then
    echo "错误: 未找到 gh CLI 工具"
    echo "请先安装 GitHub CLI: https://cli.github.com/"
    echo "安装后运行 'gh auth login' 进行认证"
    exit 1
fi

if ! gh auth status &>/dev/null; then
    echo "错误: gh CLI 未认证"
    echo "请运行 'gh auth login' 进行认证"
    exit 1
fi

# ─── 解析输入，提取 owner 和 repo ───
parse_input() {
    local input="$1"

    # 去掉末尾的 .git
    input="${input%.git}"
    # 去掉末尾的 /
    input="${input%/}"

    if [[ "$input" =~ ^https?://github\.com/([^/]+)/([^/]+)$ ]]; then
        OWNER="${BASH_REMATCH[1]}"
        REPO="${BASH_REMATCH[2]}"
    elif [[ "$input" =~ ^([^/]+)/([^/]+)$ ]]; then
        OWNER="${BASH_REMATCH[1]}"
        REPO="${BASH_REMATCH[2]}"
    else
        echo "错误: 无法解析输入 '$input'"
        echo "支持的格式: https://github.com/owner/repo 或 owner/repo"
        exit 1
    fi
}

parse_input "$INPUT"

# ─── 获取仓库信息 ───
REPO_JSON=$(gh api "repos/${OWNER}/${REPO}" 2>/dev/null) || {
    echo "错误: 无法获取仓库信息 ${OWNER}/${REPO}"
    echo "请检查仓库是否存在，以及 gh 是否已认证"
    exit 1
}

# ─── 获取作者信息 ───
OWNER_JSON=$(gh api "users/${OWNER}" 2>/dev/null) || {
    echo "错误: 无法获取用户/组织信息 ${OWNER}"
    exit 1
}

# ─── JSON 字段提取辅助函数 ───
# 优先使用 jq，不可用时降级为 grep/sed
if command -v jq &>/dev/null; then
    json_field() {
        echo "$1" | jq -r "if .$2 == null then \"\" else .$2 | tostring end"
    }
    json_field_num() {
        echo "$1" | jq -r ".$2 // 0"
    }
else
    json_field() {
        local val
        val=$(echo "$1" | grep -o "\"$2\":[^,}]*" | head -1 | sed "s/\"$2\"://;s/^[[:space:]]*//;s/\"//g")
        if [[ "$val" == "null" || -z "$val" ]]; then
            echo ""
        else
            echo "$val"
        fi
    }
    json_field_num() {
        local val
        val=$(json_field "$1" "$2")
        if [[ -z "$val" ]]; then
            echo "0"
        else
            echo "$val"
        fi
    }
fi

# ─── 提取仓库字段 ───
STARS=$(json_field_num "$REPO_JSON" "stargazers_count")
FORKS=$(json_field_num "$REPO_JSON" "forks_count")
OPEN_ISSUES=$(json_field_num "$REPO_JSON" "open_issues_count")
REPO_CREATED=$(json_field "$REPO_JSON" "created_at")
REPO_UPDATED=$(json_field "$REPO_JSON" "pushed_at")
LICENSE_NAME=""
if command -v jq &>/dev/null; then
    LICENSE_NAME=$(echo "$REPO_JSON" | jq -r '.license.spdx_id // empty')
else
    LICENSE_NAME=$(echo "$REPO_JSON" | grep -o '"license":{[^}]*}' | grep -o '"spdx_id":"[^"]*"' | sed 's/"spdx_id":"//;s/"//')
fi
DESCRIPTION=$(json_field "$REPO_JSON" "description")
ARCHIVED=$(json_field "$REPO_JSON" "archived")

# ─── 提取作者字段 ───
OWNER_LOGIN=$(json_field "$OWNER_JSON" "login")
OWNER_TYPE=$(json_field "$OWNER_JSON" "type")
OWNER_CREATED=$(json_field "$OWNER_JSON" "created_at")
PUBLIC_REPOS=$(json_field_num "$OWNER_JSON" "public_repos")
FOLLOWERS=$(json_field_num "$OWNER_JSON" "followers")

# ─── 日期计算辅助函数 ───
# 计算某个 ISO 日期到今天的天数差
days_since() {
    local date_str="$1"
    # 只取日期部分 YYYY-MM-DD
    local date_part="${date_str%%T*}"

    local now_epoch
    local then_epoch

    if date --version &>/dev/null 2>&1; then
        # GNU date (Linux)
        now_epoch=$(date +%s)
        then_epoch=$(date -d "$date_part" +%s)
    else
        # BSD date (macOS)
        now_epoch=$(date +%s)
        then_epoch=$(date -j -f "%Y-%m-%d" "$date_part" +%s 2>/dev/null || echo "0")
    fi

    if [[ "$then_epoch" -eq 0 ]]; then
        echo "0"
        return
    fi

    local diff=$(( (now_epoch - then_epoch) / 86400 ))
    echo "$diff"
}

# ─── 计算日期差 ───
REPO_AGE_DAYS=$(days_since "$REPO_CREATED")
OWNER_AGE_DAYS=$(days_since "$OWNER_CREATED")
LAST_UPDATE_DAYS=$(days_since "$REPO_UPDATED")

# ─── 计算 fork/star 比 ───
if [[ "$STARS" -gt 0 ]]; then
    FORK_STAR_RATIO=$(awk "BEGIN { printf \"%.2f\", $FORKS / $STARS }")
else
    FORK_STAR_RATIO="0"
fi

# ─── 格式化日期显示 ───
format_date() {
    echo "${1%%T*}"
}

REPO_CREATED_DISPLAY=$(format_date "$REPO_CREATED")
REPO_UPDATED_DISPLAY=$(format_date "$REPO_UPDATED")
OWNER_CREATED_DISPLAY=$(format_date "$OWNER_CREATED")

# ─── T1/T2/T3 分级 ───
TRUST_LEVEL=""
TRUST_LEVEL_TEXT=""

# 检查是否在 T1 白名单中
in_whitelist() {
    local owner_lower
    owner_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    for w in "${T1_WHITELIST[@]}"; do
        if [[ "$owner_lower" == "$w" ]]; then
            return 0
        fi
    done
    return 1
}

if in_whitelist "$OWNER"; then
    TRUST_LEVEL="T1"
    TRUST_LEVEL_TEXT="知名大厂/顶级组织"
elif [[ "$OWNER_TYPE" == "Organization" ]] && [[ "$STARS" -gt 5000 ]] && [[ "$FOLLOWERS" -gt 500 ]] && [[ "$OWNER_AGE_DAYS" -gt 1095 ]]; then
    TRUST_LEVEL="T1"
    TRUST_LEVEL_TEXT="知名大厂/顶级组织"
elif [[ "$OWNER_TYPE" == "Organization" ]] && [[ "$STARS" -gt 100 ]]; then
    TRUST_LEVEL="T2"
    TRUST_LEVEL_TEXT="可信组织"
elif [[ "$STARS" -gt 1000 ]] && [[ "$OWNER_AGE_DAYS" -gt 365 ]] && [[ "$FOLLOWERS" -gt 50 ]]; then
    TRUST_LEVEL="T2"
    TRUST_LEVEL_TEXT="可信组织"
else
    TRUST_LEVEL="T3"
    TRUST_LEVEL_TEXT="社区/个人"
fi

# ─── 评分体系 ───
SCORE=100
FLAGS=()

# 辅助函数: 添加风险标记
add_flag() {
    local severity="$1"
    local desc="$2"
    FLAGS+=("${severity}|${desc}")
}

# Star 数评估
if [[ "$STARS" -lt 5 ]]; then
    SCORE=$((SCORE - 15))
    add_flag "medium" "Star 数较少 (<5)"
elif [[ "$STARS" -gt 1000 ]]; then
    add_flag "info" "Star 数优秀 (>1000)"
elif [[ "$STARS" -gt 50 ]]; then
    add_flag "info" "Star 数正常 (>50)"
fi

# 仓库年龄评估
if [[ "$REPO_AGE_DAYS" -lt 30 ]]; then
    SCORE=$((SCORE - 20))
    add_flag "high" "仓库非常新 (<1个月)"
elif [[ "$REPO_AGE_DAYS" -lt 180 ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "仓库较新 (<6个月)"
elif [[ "$REPO_AGE_DAYS" -gt 365 ]]; then
    add_flag "low" "仓库年龄正常 (>1年)"
fi

# 账号年龄评估
if [[ "$OWNER_AGE_DAYS" -lt 90 ]]; then
    SCORE=$((SCORE - 20))
    add_flag "high" "账号非常新 (<3个月)"
elif [[ "$OWNER_AGE_DAYS" -lt 365 ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "账号较新 (<1年)"
elif [[ "$OWNER_AGE_DAYS" -gt 730 ]]; then
    add_flag "low" "账号年龄正常 (>2年)"
else
    add_flag "low" "账号年龄正常 (>1年)"
fi

# Fork/Star 比评估
FORK_STAR_SUSPICIOUS=$(awk "BEGIN { print ($FORK_STAR_RATIO > 0.8) ? 1 : 0 }")
if [[ "$FORK_STAR_SUSPICIOUS" -eq 1 ]]; then
    SCORE=$((SCORE - 15))
    add_flag "high" "Fork/Star 比异常 (>0.8)，可能存在刷量"
fi

# License 评估
if [[ -z "$LICENSE_NAME" || "$LICENSE_NAME" == "NOASSERTION" ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "无 License"
else
    add_flag "info" "License: ${LICENSE_NAME}"
fi

# Description 评估
if [[ -z "$DESCRIPTION" ]]; then
    SCORE=$((SCORE - 5))
    add_flag "low" "无 Description"
fi

# Archived 评估
if [[ "$ARCHIVED" == "true" ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "仓库已归档 (archived)"
fi

# 活跃度评估
if [[ "$LAST_UPDATE_DAYS" -gt 365 ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "仓库不活跃 (>1年无更新)"
elif [[ "$LAST_UPDATE_DAYS" -lt 90 ]]; then
    add_flag "info" "仓库活跃 (<3个月内有更新)"
fi

# 公开仓库数评估
if [[ "$PUBLIC_REPOS" -lt 3 ]]; then
    SCORE=$((SCORE - 10))
    add_flag "medium" "公开仓库数较少 (<3)"
elif [[ "$PUBLIC_REPOS" -gt 10 ]]; then
    add_flag "info" "公开仓库数充足 (>10)"
fi

# Followers 评估
if [[ "$FOLLOWERS" -lt 3 ]]; then
    SCORE=$((SCORE - 5))
    add_flag "low" "Followers 较少 (<3)"
elif [[ "$FOLLOWERS" -gt 50 ]]; then
    add_flag "info" "Followers 充足 (>50)"
fi

# 确保 score 不低于 0
if [[ "$SCORE" -lt 0 ]]; then
    SCORE=0
fi

# ─── 风险等级映射 ───
if [[ "$SCORE" -ge 80 ]]; then
    RISK_LEVEL="low"
elif [[ "$SCORE" -ge 60 ]]; then
    RISK_LEVEL="medium"
elif [[ "$SCORE" -ge 40 ]]; then
    RISK_LEVEL="high"
else
    RISK_LEVEL="critical"
fi

# ─── 输出结果 ───
if $OUTPUT_JSON; then
    # 构建 flags JSON 数组
    FLAGS_JSON=""
    for flag in "${FLAGS[@]}"; do
        local_severity="${flag%%|*}"
        local_desc="${flag#*|}"
        # 转义 JSON 特殊字符
        local_desc=$(echo "$local_desc" | sed 's/"/\\"/g')
        if [[ -n "$FLAGS_JSON" ]]; then
            FLAGS_JSON="${FLAGS_JSON},"
        fi
        FLAGS_JSON="${FLAGS_JSON}{\"severity\":\"${local_severity}\",\"description\":\"${local_desc}\"}"
    done

    # 转义 description
    DESC_ESCAPED=""
    if [[ -n "$DESCRIPTION" ]]; then
        DESC_ESCAPED=$(echo "$DESCRIPTION" | sed 's/"/\\"/g')
    fi

    # 输出 JSON
    cat <<JSONEOF
{
  "tool": "cls-github-repo-check",
  "repo": "${OWNER}/${REPO}",
  "trust_level": "${TRUST_LEVEL}",
  "trust_level_text": "${TRUST_LEVEL_TEXT}",
  "score": ${SCORE},
  "risk_level": "${RISK_LEVEL}",
  "repo_info": {
    "stars": ${STARS},
    "forks": ${FORKS},
    "fork_star_ratio": ${FORK_STAR_RATIO},
    "created_at": "${REPO_CREATED_DISPLAY}",
    "updated_at": "${REPO_UPDATED_DISPLAY}",
    "license": "${LICENSE_NAME}",
    "description": "${DESC_ESCAPED}",
    "archived": ${ARCHIVED},
    "open_issues": ${OPEN_ISSUES}
  },
  "owner_info": {
    "login": "${OWNER_LOGIN}",
    "type": "${OWNER_TYPE}",
    "created_at": "${OWNER_CREATED_DISPLAY}",
    "public_repos": ${PUBLIC_REPOS},
    "followers": ${FOLLOWERS}
  },
  "flags": [${FLAGS_JSON}]
}
JSONEOF
else
    # CLI 输出
    echo ""
    echo -e "${BOLD}CLS-Certify GitHub 仓库信誉检查${RESET}"
    echo "────────────────────────────────────────"
    echo -e "仓库: ${CYAN}${OWNER}/${REPO}${RESET}"
    echo -e "来源分级: ${BOLD}${TRUST_LEVEL}${RESET} (${TRUST_LEVEL_TEXT})"

    # 根据风险等级选择颜色
    RISK_COLOR="$GREEN"
    case "$RISK_LEVEL" in
        critical) RISK_COLOR="$RED" ;;
        high)     RISK_COLOR="$RED" ;;
        medium)   RISK_COLOR="$YELLOW" ;;
        low)      RISK_COLOR="$GREEN" ;;
    esac
    echo -e "信誉评分: ${RISK_COLOR}${SCORE}/100${RESET} (${RISK_LEVEL})"
    echo "────────────────────────────────────────"

    echo "仓库信息:"
    echo "  Stars: ${STARS}"
    echo "  Forks: ${FORKS}"
    echo "  创建时间: ${REPO_CREATED_DISPLAY}"
    echo "  最近更新: ${REPO_UPDATED_DISPLAY}"
    if [[ -n "$LICENSE_NAME" && "$LICENSE_NAME" != "NOASSERTION" ]]; then
        echo "  License: ${LICENSE_NAME}"
    else
        echo "  License: 无"
    fi
    if [[ -n "$DESCRIPTION" ]]; then
        echo "  Description: ${DESCRIPTION}"
    else
        echo "  Description: 无"
    fi
    echo ""

    echo "作者信息:"
    echo "  ${OWNER_LOGIN} (${OWNER_TYPE})"
    echo "  账号创建: ${OWNER_CREATED_DISPLAY}"
    echo "  公开仓库: ${PUBLIC_REPOS}"
    echo "  Followers: ${FOLLOWERS}"
    echo ""

    echo "风险标记:"
    for flag in "${FLAGS[@]}"; do
        local_severity="${flag%%|*}"
        local_desc="${flag#*|}"
        case "$local_severity" in
            critical) flag_color="$RED" ;;
            high)     flag_color="$RED" ;;
            medium)   flag_color="$YELLOW" ;;
            low)      flag_color="$GREEN" ;;
            info)     flag_color="$CYAN" ;;
            *)        flag_color="$RESET" ;;
        esac
        echo -e "  ${flag_color}[${local_severity}]${RESET} ${local_desc}"
    done
    echo "────────────────────────────────────────"
    echo ""
fi
