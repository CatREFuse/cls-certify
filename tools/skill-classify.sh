#!/usr/bin/env bash
# CLS-Certify Skill 分类判定工具
# 根据 code-stats.sh 的输出自动判定 skill 类型，生成对应的检查策略
#
# 用法:
#   ./tools/skill-classify.sh <skill_path> --stats <code-stats.json> [--json] [--scan-mode auto|full|quick]
#
# 示例:
#   ./tools/skill-classify.sh ./my-skill --stats /tmp/code-stats.json --json
#   ./tools/skill-classify.sh ./my-skill --stats /tmp/code-stats.json --scan-mode quick --json

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
TARGET=""
STATS_FILE=""
SCAN_MODE="auto"

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── 分类阈值 ───
HEAVY_EXEC_LINES=200
HEAVY_CODE_FILES=10
HEAVY_EXEC_SIZE=102400  # 100KB
OVERSIZED_THRESHOLD=51200  # 50KB

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify Skill 分类判定工具"
    echo ""
    echo "用法: $0 <skill_path> --stats <code-stats.json> [options]"
    echo ""
    echo "选项:"
    echo "  --stats <file>         code-stats.sh 的 JSON 输出文件（必需）"
    echo "  --scan-mode <mode>     扫描模式: auto（默认）| full | quick"
    echo "  --json                 输出 JSON 格式"
    echo "  -h, --help             显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stats) STATS_FILE="$2"; shift 2 ;;
        --scan-mode) SCAN_MODE="$2"; shift 2 ;;
        --json) OUTPUT_JSON=true; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "错误: 请指定 skill 路径" >&2
    exit 1
fi

if [[ -z "$STATS_FILE" || ! -f "$STATS_FILE" ]]; then
    echo "错误: 请通过 --stats 指定有效的 code-stats.json 文件" >&2
    exit 1
fi

# ─── 从 JSON 中提取数值（纯 bash + awk，无需 jq） ───
json_get_number() {
    local key="$1"
    awk -F"[,:}]" -v k="\"$key\"" '
    {
        for(i=1; i<=NF; i++) {
            gsub(/[[:space:]]/, "", $i)
            if ($i == k) {
                gsub(/[[:space:]\"]/, "", $(i+1))
                print $(i+1)
                exit
            }
        }
    }' "$STATS_FILE"
}

# 从 JSON 中提取布尔值
json_get_bool() {
    local key="$1"
    local val
    val=$(json_get_number "$key")
    if [[ "$val" == "true" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ─── 提取关键指标 ───
TOTAL_FILES=$(json_get_number "total_files")
TOTAL_LINES=$(json_get_number "total_lines")
TOTAL_SIZE_BYTES=$(json_get_number "total_size_bytes")
EXECUTABLE_LINES=$(json_get_number "executable_lines")
EXECUTABLE_SIZE_BYTES=$(json_get_number "executable_size_bytes")
HAS_REFERENCES_DIR=$(json_get_bool "has_references_dir")
HIGH_RISK=$(json_get_number "high_risk")
MEDIUM_RISK=$(json_get_number "medium_risk")

# 默认值
TOTAL_FILES=${TOTAL_FILES:-0}
TOTAL_LINES=${TOTAL_LINES:-0}
TOTAL_SIZE_BYTES=${TOTAL_SIZE_BYTES:-0}
EXECUTABLE_LINES=${EXECUTABLE_LINES:-0}
EXECUTABLE_SIZE_BYTES=${EXECUTABLE_SIZE_BYTES:-0}
HAS_REFERENCES_DIR=${HAS_REFERENCES_DIR:-false}
HIGH_RISK=${HIGH_RISK:-0}
MEDIUM_RISK=${MEDIUM_RISK:-0}

# ─── 检查是否所有文件都是 .md ───
check_all_md() {
    # 从 files 数组中提取语言字段，检查是否全部是 Markdown
    local non_md
    non_md=$(awk -F'"language":"' '{
        for(i=2; i<=NF; i++) {
            lang = $i
            sub(/".*/, "", lang)
            if (lang != "Markdown") { print lang; exit }
        }
    }' "$STATS_FILE")
    [[ -z "$non_md" ]]
}

# ─── 计算代码文件数（排除 Markdown/JSON/YAML/TOML/HTML/CSS/Other） ───
count_code_files() {
    awk -F'"language":"' '{
        count=0
        for(i=2; i<=NF; i++) {
            lang = $i
            sub(/".*/, "", lang)
            if (lang != "Markdown" && lang != "JSON" && lang != "YAML" && lang != "TOML" && lang != "HTML" && lang != "CSS" && lang != "Other") {
                count++
            }
        }
        print count
    }' "$STATS_FILE"
}

CODE_FILES_COUNT=$(count_code_files)

# ─── 分类判定 ───
TIER=""
TIER_NAME=""
REASONS=""

add_reason() {
    if [[ -n "$REASONS" ]]; then
        REASONS="${REASONS}|$1"
    else
        REASONS="$1"
    fi
}

# scan_mode 优先覆盖
if [[ "$SCAN_MODE" == "full" ]]; then
    TIER="T-FULL"
    TIER_NAME="强制全量扫描"
    add_reason "scan_mode 设为 full，忽略自动分类"

elif [[ "$SCAN_MODE" == "quick" ]]; then
    TIER="T-QUICK"
    TIER_NAME="快速扫描"
    add_reason "scan_mode 设为 quick，使用最精简策略"

else
    # ─── 自动判定: T-MD → T-HEAVY → T-REF → T-LITE ───

    # 1. 判定 T-MD
    ALL_MD=false
    if check_all_md; then
        ALL_MD=true
    fi

    if $ALL_MD && [[ $HIGH_RISK -eq 0 ]] && [[ $MEDIUM_RISK -eq 0 ]]; then
        TIER="T-MD"
        TIER_NAME="纯 Markdown Skill"
        add_reason "所有文件均为 Markdown"
        add_reason "无 medium/high 风险代码块"

    # 2. 判定 T-HEAVY
    elif [[ $EXECUTABLE_LINES -gt $HEAVY_EXEC_LINES ]]; then
        TIER="T-HEAVY"
        TIER_NAME="大型代码 Skill"
        add_reason "可执行代码行数: ${EXECUTABLE_LINES} (>${HEAVY_EXEC_LINES})"

    elif [[ $CODE_FILES_COUNT -gt $HEAVY_CODE_FILES ]]; then
        TIER="T-HEAVY"
        TIER_NAME="大型代码 Skill"
        add_reason "代码文件数: ${CODE_FILES_COUNT} (>${HEAVY_CODE_FILES})"

    elif [[ $EXECUTABLE_SIZE_BYTES -gt $HEAVY_EXEC_SIZE ]]; then
        TIER="T-HEAVY"
        TIER_NAME="大型代码 Skill"
        add_reason "可执行代码体积: ${EXECUTABLE_SIZE_BYTES} bytes (>${HEAVY_EXEC_SIZE})"

    # 3. 判定 T-REF
    elif [[ "$HAS_REFERENCES_DIR" == "true" ]]; then
        TIER="T-REF"
        TIER_NAME="引用代码 Skill"
        add_reason "存在 references/ 目录且包含代码文件"

    elif [[ $((HIGH_RISK + MEDIUM_RISK)) -gt 0 ]] && [[ $EXECUTABLE_LINES -le $HEAVY_EXEC_LINES ]]; then
        TIER="T-REF"
        TIER_NAME="引用代码 Skill"
        add_reason "MD 包含 ${HIGH_RISK} 个 high + ${MEDIUM_RISK} 个 medium 风险代码块"

    # 4. 兜底 T-LITE
    else
        TIER="T-LITE"
        TIER_NAME="轻量代码 Skill"
        add_reason "可执行代码行: ${EXECUTABLE_LINES} (≤${HEAVY_EXEC_LINES})"
        add_reason "代码文件数: ${CODE_FILES_COUNT} (≤${HEAVY_CODE_FILES})"
        add_reason "无 references/ 目录"
    fi
fi

# ─── 策略映射 ───
# 策略值: full / skip / md-only / targeted / lite / full+ref

get_strategy() {
    local tier="$1"
    case "$tier" in
        T-MD)
            cat <<'STRATEGY'
{
  "threat_scan":"md-only",
  "secret_scan":"skip",
  "entropy_detect":"skip",
  "url_audit":"md-only",
  "dep_audit":"skip",
  "github_repo_check":"full",
  "dim1_static":"md-only",
  "dim2_dynamic":"skip",
  "dim3_dependency":"skip",
  "dim4_network":"md-only",
  "dim5_privacy":"lite",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
        T-LITE)
            cat <<'STRATEGY'
{
  "threat_scan":"full",
  "secret_scan":"full",
  "entropy_detect":"full",
  "url_audit":"full",
  "dep_audit":"full",
  "github_repo_check":"full",
  "dim1_static":"full",
  "dim2_dynamic":"full",
  "dim3_dependency":"full",
  "dim4_network":"full",
  "dim5_privacy":"full",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
        T-REF)
            cat <<'STRATEGY'
{
  "threat_scan":"full",
  "secret_scan":"full",
  "entropy_detect":"full",
  "url_audit":"full",
  "dep_audit":"full",
  "github_repo_check":"full",
  "dim1_static":"full",
  "dim2_dynamic":"full",
  "dim3_dependency":"full",
  "dim4_network":"full+ref",
  "dim5_privacy":"full",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
        T-HEAVY)
            cat <<'STRATEGY'
{
  "threat_scan":"full",
  "secret_scan":"full",
  "entropy_detect":"full",
  "url_audit":"full",
  "dep_audit":"full",
  "github_repo_check":"full",
  "dim1_static":"targeted",
  "dim2_dynamic":"targeted",
  "dim3_dependency":"full",
  "dim4_network":"full",
  "dim5_privacy":"full",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
        T-FULL)
            # scan_mode=full 强制全量
            cat <<'STRATEGY'
{
  "threat_scan":"full",
  "secret_scan":"full",
  "entropy_detect":"full",
  "url_audit":"full",
  "dep_audit":"full",
  "github_repo_check":"full",
  "dim1_static":"full",
  "dim2_dynamic":"full",
  "dim3_dependency":"full",
  "dim4_network":"full",
  "dim5_privacy":"full",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
        T-QUICK)
            # scan_mode=quick 最精简（等同 T-MD）
            cat <<'STRATEGY'
{
  "threat_scan":"md-only",
  "secret_scan":"skip",
  "entropy_detect":"skip",
  "url_audit":"md-only",
  "dep_audit":"skip",
  "github_repo_check":"full",
  "dim1_static":"md-only",
  "dim2_dynamic":"skip",
  "dim3_dependency":"skip",
  "dim4_network":"md-only",
  "dim5_privacy":"lite",
  "dim6_reputation":"full",
  "agent_verify":"full"
}
STRATEGY
            ;;
    esac
}

STRATEGY_JSON=$(get_strategy "$TIER")

# ─── 生成 scan_targets ───
get_scan_targets() {
    local tier="$1"
    local skill_path="$2"

    # 查找 SKILL.md 路径
    local skill_md=""
    if [[ -f "$skill_path/SKILL.md" ]]; then
        skill_md="$skill_path/SKILL.md"
    elif [[ -f "$skill_path/skill.md" ]]; then
        skill_md="$skill_path/skill.md"
    fi

    case "$tier" in
        T-MD|T-QUICK)
            # 工具仅扫描 SKILL.md
            local target="${skill_md:-$skill_path}"
            printf '{"threat_scan_target":"%s","secret_scan_target":"%s","url_audit_target":"%s","dep_audit_target":"%s"}' \
                "$target" "$target" "$target" "$skill_path"
            ;;
        *)
            # 工具扫描整个目录
            printf '{"threat_scan_target":"%s","secret_scan_target":"%s","url_audit_target":"%s","dep_audit_target":"%s"}' \
                "$skill_path" "$skill_path" "$skill_path" "$skill_path"
            ;;
    esac
}

SCAN_TARGETS_JSON=$(get_scan_targets "$TIER" "$TARGET")

# ─── 构建跳过维度列表 ───
get_skipped_dims() {
    local tier="$1"
    case "$tier" in
        T-MD|T-QUICK)
            echo '"dim2_dynamic","dim3_dependency"'
            ;;
        *)
            echo ""
            ;;
    esac
}

SKIPPED_DIMS=$(get_skipped_dims "$TIER")

# ─── 输出 ───
if $OUTPUT_JSON; then
    # 构建 reasons JSON 数组
    REASONS_JSON=""
    IFS='|' read -ra reason_arr <<< "$REASONS"
    for r in "${reason_arr[@]}"; do
        escaped_r=$(echo "$r" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [[ -n "$REASONS_JSON" ]]; then
            REASONS_JSON="${REASONS_JSON},\"${escaped_r}\""
        else
            REASONS_JSON="\"${escaped_r}\""
        fi
    done

    # 去掉 strategy JSON 中的换行和多余空格
    STRATEGY_COMPACT=$(echo "$STRATEGY_JSON" | tr -d '\n' | sed 's/  */ /g')

    printf '{"tool":"cls-skill-classify","tier":"%s","tier_name":"%s","scan_mode":"%s","classification_reasons":[%s],"metrics":{"total_files":%d,"total_lines":%d,"total_size_bytes":%d,"executable_lines":%d,"executable_size_bytes":%d,"code_files_count":%d,"has_references_dir":%s,"high_risk_blocks":%d,"medium_risk_blocks":%d},"strategy":%s,"scan_targets":%s,"skipped_dimensions":[%s]}\n' \
        "$TIER" "$TIER_NAME" "$SCAN_MODE" "$REASONS_JSON" \
        "$TOTAL_FILES" "$TOTAL_LINES" "$TOTAL_SIZE_BYTES" \
        "$EXECUTABLE_LINES" "$EXECUTABLE_SIZE_BYTES" "$CODE_FILES_COUNT" \
        "$HAS_REFERENCES_DIR" "$HIGH_RISK" "$MEDIUM_RISK" \
        "$STRATEGY_COMPACT" "$SCAN_TARGETS_JSON" "$SKIPPED_DIMS"
else
    # ─── CLI 输出 ───
    echo ""
    echo -e "${BOLD}CLS-Certify Skill 分类判定${RESET}"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo "────────────────────────────────────────"

    # Tier 颜色
    tier_color="$GREEN"
    case "$TIER" in
        T-HEAVY) tier_color="$YELLOW" ;;
        T-REF)   tier_color="$CYAN" ;;
        T-FULL)  tier_color="$YELLOW" ;;
    esac

    echo -e "${BOLD}分类结果:${RESET}  ${tier_color}${TIER}${RESET} — ${TIER_NAME}"
    echo -e "${BOLD}扫描模式:${RESET}  ${SCAN_MODE}"
    echo ""

    echo -e "${BOLD}判定依据:${RESET}"
    IFS='|' read -ra reason_arr <<< "$REASONS"
    for r in "${reason_arr[@]}"; do
        echo "  - $r"
    done

    echo ""
    echo -e "${BOLD}关键指标:${RESET}"
    printf "  总文件数:       %d\n" "$TOTAL_FILES"
    printf "  总行数:         %d\n" "$TOTAL_LINES"
    printf "  总体积:         %d bytes\n" "$TOTAL_SIZE_BYTES"
    printf "  可执行代码行:   %d\n" "$EXECUTABLE_LINES"
    printf "  可执行代码量:   %d bytes\n" "$EXECUTABLE_SIZE_BYTES"
    printf "  代码文件数:     %d\n" "$CODE_FILES_COUNT"
    printf "  references/:    %s\n" "$HAS_REFERENCES_DIR"
    printf "  High 风险块:    %d\n" "$HIGH_RISK"
    printf "  Medium 风险块:  %d\n" "$MEDIUM_RISK"

    echo ""
    echo -e "${BOLD}检查策略:${RESET}"
    echo "$STRATEGY_JSON" | while IFS= read -r line; do
        # 简化显示
        line=$(echo "$line" | sed 's/[{}]//g; s/^[[:space:]]*//')
        [[ -z "$line" ]] && continue
        key=$(echo "$line" | sed 's/"//g; s/:.*//')
        val=$(echo "$line" | sed 's/.*://; s/"//g; s/,//; s/^[[:space:]]*//')
        [[ -z "$key" ]] && continue

        val_color="$GREEN"
        case "$val" in
            skip)     val_color="$RED" ;;
            targeted) val_color="$YELLOW" ;;
            md-only)  val_color="$CYAN" ;;
            lite)     val_color="$CYAN" ;;
            full+ref) val_color="$YELLOW" ;;
        esac

        printf "  %-20s ${val_color}%s${RESET}\n" "$key" "$val"
    done

    if [[ -n "$SKIPPED_DIMS" ]]; then
        echo ""
        echo -e "${RED}${BOLD}跳过维度:${RESET} ${SKIPPED_DIMS}"
    fi

    echo ""
fi
