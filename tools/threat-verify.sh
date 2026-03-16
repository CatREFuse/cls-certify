#!/usr/bin/env bash
# CLS-Certify 威胁意图验证工具（Step 2）
# 读取 threat-scan.sh 的候选 JSON 输出，生成结构化验证 prompt 供 Agent 判定意图
#
# 两步检测流程:
#   Step 1: ./tools/threat-scan.sh <target> --json --context 3 > candidates.json
#   Step 2: ./tools/threat-verify.sh candidates.json
#           → 输出验证 prompt，Agent 逐条判定后输出最终结果
#
# 用法:
#   ./tools/threat-verify.sh <candidates.json> [--json]
#
# Agent 判定选项:
#   A) confirmed    — 确认威胁，实际执行危险操作
#   B) false_positive — 误报，文档描述/列举检测规则
#   C) low_risk     — 测试/示例代码中的引用，低风险
#   D) comment      — 注释中的说明文字，误报

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
CANDIDATES_FILE=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 威胁意图验证工具（Step 2）"
    echo ""
    echo "用法: $0 <candidates.json> [--json]"
    echo ""
    echo "读取 threat-scan.sh --json 的输出，生成验证 prompt 供 Agent 判定每条候选的真实意图。"
    echo ""
    echo "选项:"
    echo "  --json    输出 JSON 格式的验证 prompt"
    echo "  -h        显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) CANDIDATES_FILE="$1"; shift ;;
    esac
done

if [[ -z "$CANDIDATES_FILE" ]]; then
    echo "错误: 请指定 candidates.json 文件"
    usage
fi

if [[ ! -f "$CANDIDATES_FILE" ]]; then
    echo "错误: $CANDIDATES_FILE 不存在"
    exit 1
fi

# ─── 检查 jq 是否可用 ───
HAS_JQ=false
if command -v jq &>/dev/null; then
    HAS_JQ=true
fi

# ─── 提取 JSON 字段（jq 优先，降级到 grep/sed） ───
json_field() {
    local json="$1"
    local field="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$field // empty" 2>/dev/null
    else
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed "s/\"$field\"[[:space:]]*:[[:space:]]*\"//" | sed 's/"$//'
    fi
}

json_field_num() {
    local json="$1"
    local field="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$field // 0" 2>/dev/null
    else
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*[0-9]*" | head -1 | sed "s/\"$field\"[[:space:]]*:[[:space:]]*//"
    fi
}

json_array_strings() {
    local json="$1"
    local field="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$field[]? // empty" 2>/dev/null
    else
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\[.*\]" | head -1 | \
            sed "s/\"$field\"[[:space:]]*:[[:space:]]*\[//" | sed 's/\]$//' | \
            sed 's/","/\n/g' | sed 's/^"//;s/"$//'
    fi
}

# ─── 读取候选数量 ───
if $HAS_JQ; then
    TOTAL=$(jq '.total_findings // 0' "$CANDIDATES_FILE" 2>/dev/null)
    TARGET=$(jq -r '.target // ""' "$CANDIDATES_FILE" 2>/dev/null)
else
    TOTAL=$(grep -o '"total_findings"[[:space:]]*:[[:space:]]*[0-9]*' "$CANDIDATES_FILE" | head -1 | sed 's/.*: *//')
    TARGET=$(grep -o '"target"[[:space:]]*:[[:space:]]*"[^"]*"' "$CANDIDATES_FILE" | head -1 | sed 's/"target"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')
fi

if [[ -z "$TOTAL" || "$TOTAL" == "0" ]]; then
    if ! $OUTPUT_JSON; then
        echo -e "${GREEN}无候选威胁需要验证${RESET}"
    else
        printf '{"tool":"cls-threat-verify","target":"%s","total_candidates":0,"prompts":[]}\n' "$TARGET"
    fi
    exit 0
fi

# ─── 生成验证 prompt ───
if ! $OUTPUT_JSON; then
    echo ""
    echo -e "${BOLD}CLS-Certify 威胁意图验证${RESET}"
    echo -e "候选来源: ${CYAN}${CANDIDATES_FILE}${RESET}"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo -e "候选数量: ${YELLOW}${TOTAL}${RESET}"
    echo "════════════════════════════════════════"
    echo ""
    echo "请逐条判断以下候选威胁的真实意图："
    echo ""
fi

JSON_PROMPTS=""

# 逐条提取 findings 并生成 prompt
if $HAS_JQ; then
    findings_count=$(jq '.findings | length' "$CANDIDATES_FILE" 2>/dev/null)
else
    findings_count=$TOTAL
fi

for ((i=0; i<findings_count; i++)); do
    if $HAS_JQ; then
        finding=$(jq ".findings[$i]" "$CANDIDATES_FILE" 2>/dev/null)
        f_id=$(echo "$finding" | jq -r '.id')
        f_file=$(echo "$finding" | jq -r '.file')
        f_line=$(echo "$finding" | jq -r '.line')
        f_severity=$(echo "$finding" | jq -r '.severity')
        f_category=$(echo "$finding" | jq -r '.category')
        f_pattern_id=$(echo "$finding" | jq -r '.pattern_id')
        f_pattern_name=$(echo "$finding" | jq -r '.pattern_name')
        f_description=$(echo "$finding" | jq -r '.description')
        f_evidence=$(echo "$finding" | jq -r '.evidence')

        # 获取上下文行
        ctx_before=$(echo "$finding" | jq -r '.context_before[]? // empty' 2>/dev/null)
        ctx_after=$(echo "$finding" | jq -r '.context_after[]? // empty' 2>/dev/null)
    else
        # 简化的非 jq 解析（提取第 i 个 finding 的关键字段）
        # 这里用 awk 提取第 i+1 个 THREAT-xxx 块
        f_id="THREAT-$(printf '%03d' $((i+1)))"
        f_file="(需要 jq 解析)"
        f_line="?"
        f_severity="?"
        f_category="?"
        f_pattern_name="?"
        f_description="?"
        f_evidence="?"
        ctx_before=""
        ctx_after=""
    fi

    if ! $OUTPUT_JSON; then
        # CLI 格式输出
        echo -e "${BOLD}=== 候选 ${f_id} ===${RESET}"
        echo -e "文件: ${CYAN}${f_file}:${f_line}${RESET}"
        echo -e "模式: ${MAGENTA}${f_category}${RESET} / ${DIM}${f_pattern_name}${RESET}"
        echo -e "严重性: ${RED}${f_severity}${RESET}"
        echo -e "描述: ${f_description}"
        echo ""
        echo -e "${DIM}上下文:${RESET}"

        # 显示 context_before
        local_line_start=$((f_line - 3))
        [[ $local_line_start -lt 1 ]] && local_line_start=1
        local_ln=$local_line_start
        if [[ -n "$ctx_before" ]]; then
            while IFS= read -r ctx_line; do
                printf "  ${DIM}%4d │ %s${RESET}\n" "$local_ln" "$ctx_line"
                local_ln=$((local_ln + 1))
            done <<< "$ctx_before"
        fi

        # 显示命中行
        printf "  ${RED}%4d │ %s${RESET}  ${RED}← 命中${RESET}\n" "$f_line" "$f_evidence"

        # 显示 context_after
        local_ln=$((f_line + 1))
        if [[ -n "$ctx_after" ]]; then
            while IFS= read -r ctx_line; do
                printf "  ${DIM}%4d │ %s${RESET}\n" "$local_ln" "$ctx_line"
                local_ln=$((local_ln + 1))
            done <<< "$ctx_after"
        fi

        echo ""
        echo -e "  ${BOLD}请判断此处的意图:${RESET}"
        echo -e "  ${GREEN}A)${RESET} confirmed      — 确认威胁，实际执行危险操作"
        echo -e "  ${YELLOW}B)${RESET} false_positive — 误报，文档描述/列举检测规则"
        echo -e "  ${CYAN}C)${RESET} low_risk       — 测试/示例代码引用，低风险"
        echo -e "  ${DIM}D)${RESET} comment        — 注释中的说明文字，误报"
        echo ""
        echo "────────────────────────────────────────"
        echo ""
    else
        # JSON 格式输出
        prompt_text="候选 ${f_id}: 文件 ${f_file}:${f_line}, 模式 ${f_category}/${f_pattern_name}(${f_severity}), 匹配行: ${f_evidence}"

        escaped_prompt=$(printf '%s' "$prompt_text" | sed 's/"/\\"/g')
        escaped_id=$(printf '%s' "$f_id" | sed 's/"/\\"/g')
        escaped_file2=$(printf '%s' "$f_file" | sed 's/"/\\"/g')
        escaped_evidence2=$(printf '%s' "$f_evidence" | sed 's/"/\\"/g')
        escaped_category=$(printf '%s' "$f_category" | sed 's/"/\\"/g')
        escaped_pattern=$(printf '%s' "$f_pattern_name" | sed 's/"/\\"/g')

        # 获取原始 context JSON 数组
        if $HAS_JQ; then
            ctx_before_json=$(echo "$finding" | jq -c '.context_before // []')
            ctx_after_json=$(echo "$finding" | jq -c '.context_after // []')
        else
            ctx_before_json="[]"
            ctx_after_json="[]"
        fi

        item=$(printf '{"id":"%s","file":"%s","line":%s,"severity":"%s","category":"%s","pattern_name":"%s","evidence":"%s","context_before":%s,"context_after":%s,"intent":"pending","options":["confirmed","false_positive","low_risk","comment"]}' \
            "$escaped_id" "$escaped_file2" "$f_line" "$f_severity" "$escaped_category" "$escaped_pattern" "$escaped_evidence2" "$ctx_before_json" "$ctx_after_json")

        if [[ -n "$JSON_PROMPTS" ]]; then
            JSON_PROMPTS="${JSON_PROMPTS},${item}"
        else
            JSON_PROMPTS="$item"
        fi
    fi
done

# ─── 输出结果 ───
if $OUTPUT_JSON; then
    printf '{"tool":"cls-threat-verify","target":"%s","total_candidates":%s,"prompts":[%s]}\n' \
        "$TARGET" "$TOTAL" "$JSON_PROMPTS"
else
    echo ""
    echo -e "${BOLD}验证指南${RESET}"
    echo "Agent 应逐条审查上述候选，根据上下文判断关键词的真实意图。"
    echo "判定结果将用于过滤误报，仅 confirmed 的威胁会进入最终评分。"
    echo ""
fi
