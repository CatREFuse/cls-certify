#!/usr/bin/env bash
# CLS-Certify 熵值检测工具
# 扫描文件中的高熵字符串，识别可能的硬编码密钥、Token 等敏感信息
#
# 用法:
#   ./tools/entropy-detect.sh <file_or_dir> [--threshold 4.5] [--min-length 20] [--context 3] [--json]
#
# 示例:
#   ./tools/entropy-detect.sh ./src/
#   ./tools/entropy-detect.sh config.js --threshold 4.0 --min-length 16
#   ./tools/entropy-detect.sh ./src/ --json
#   ./tools/entropy-detect.sh ./src/ --context 5

set -euo pipefail

# ─── 默认参数 ───
THRESHOLD="4.5"
MIN_LENGTH="20"
CONTEXT_LINES=3
OUTPUT_JSON=false
TARGET=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── 排除的文件模式 ───
EXCLUDE_PATTERNS=(
    "*.test.js" "*.spec.js" "*.test.ts" "*.spec.ts"
    "*test*.py" "__tests__/*" "__pycache__/*"
    "*.md" "*.txt" "*.lock" "*.sum"
    "CHANGELOG*" "LICENSE*" "README*"
    "node_modules/*" ".git/*" "vendor/*" "dist/*" "build/*"
    "*.min.js" "*.min.css" "*.map"
    "*.png" "*.jpg" "*.jpeg" "*.gif" "*.svg" "*.ico"
    "*.woff" "*.woff2" "*.ttf" "*.eot"
    "*.zip" "*.tar" "*.gz" "*.pdf"
)

# ─── 误报关键词（不区分大小写） ───
FALSE_POSITIVE_WORDS="example|sample|test|dummy|placeholder|your_key_here|xxx|TODO|FIXME|lorem|ipsum|abcdef|000000|111111|123456"

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 熵值检测工具"
    echo ""
    echo "用法: $0 <file_or_dir> [options]"
    echo ""
    echo "选项:"
    echo "  --threshold <float>    熵值阈值 (默认: 4.5)"
    echo "  --min-length <int>     最小字符串长度 (默认: 20)"
    echo "  --context <int>        上下文行数 (默认: 3)"
    echo "  --json                 输出 JSON 格式"
    echo "  -h, --help             显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --min-length) MIN_LENGTH="$2"; shift 2 ;;
        --context) CONTEXT_LINES="$2"; shift 2 ;;
        --json) OUTPUT_JSON=true; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "错误: 请指定要扫描的文件或目录"
    usage
fi

if [[ ! -e "$TARGET" ]]; then
    echo "错误: $TARGET 不存在"
    exit 1
fi

# ─── 计算 Shannon 熵 ───
# 输入: 字符串
# 输出: 熵值 (浮点数)
calc_entropy() {
    local str="$1"
    local len=${#str}
    if [[ $len -eq 0 ]]; then
        echo "0"
        return
    fi

    # 统计每个字符出现次数，计算熵值
    awk -v str="$str" -v len="$len" 'BEGIN {
        split(str, chars, "")
        for (i = 1; i <= len; i++) {
            freq[chars[i]]++
        }
        entropy = 0.0
        for (c in freq) {
            p = freq[c] / len
            if (p > 0) {
                entropy -= p * (log(p) / log(2))
            }
        }
        printf "%.4f", entropy
    }'
}

# ─── 判断严重性 ───
get_severity() {
    local entropy="$1"
    awk -v e="$entropy" 'BEGIN {
        if (e >= 5.5) print "critical"
        else if (e >= 5.0) print "high"
        else if (e >= 4.5) print "medium"
        else print "low"
    }'
}

# ─── 判断是否为误报 ───
is_false_positive() {
    local str="$1"
    # 检查是否包含误报关键词
    echo "$str" | grep -qiE "$FALSE_POSITIVE_WORDS" && return 0
    # 全是同一字符重复
    local unique_chars
    unique_chars=$(echo "$str" | fold -w1 | sort -u | wc -l | tr -d ' ')
    [[ "$unique_chars" -le 2 ]] && return 0
    return 1
}

# ─── 从一行中提取候选字符串 ───
# 提取引号内的字符串和赋值右侧的连续非空白串
extract_candidates() {
    local line="$1"
    local ml="$MIN_LENGTH"

    # 提取双引号中的字符串
    echo "$line" | sed -n 's/[^"]*"\([^"]*\)".*/\1/p' | while IFS= read -r s; do
        [[ ${#s} -ge $ml ]] && echo "$s"
    done

    # 提取单引号中的字符串
    echo "$line" | sed -n "s/[^']*'\\([^']*\\)'.*/\\1/p" | while IFS= read -r s; do
        [[ ${#s} -ge $ml ]] && echo "$s"
    done

    # 提取 = 后面的连续非空白字符串（常见于 env / config / .env 文件）
    echo "$line" | grep -oE '=[A-Za-z0-9_/+.=-]{20,}' | sed 's/^=//' | while IFS= read -r s; do
        [[ ${#s} -ge $ml ]] && echo "$s"
    done
}

# ─── JSON 转义辅助函数 ───
json_escape_str() {
    local s="$1"
    s=$(echo "$s" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g')
    # 处理换行（正常不会出现在单行里，但保险起见）
    s=$(printf '%s' "$s" | tr '\n' ' ')
    echo "$s"
}

# ─── 扫描单个文件 ───
TOTAL_FINDINGS=0
JSON_ITEMS=""

scan_file() {
    local file="$1"

    # 将文件读入数组（兼容 bash 3.2）
    local file_lines=()
    local total_lines=0
    while IFS= read -r _fline || [[ -n "$_fline" ]]; do
        file_lines+=("$_fline")
        total_lines=$((total_lines + 1))
    done < "$file"

    local line_idx=0
    while [[ $line_idx -lt $total_lines ]]; do
        local line="${file_lines[$line_idx]}"
        local line_num=$((line_idx + 1))

        # 跳过注释行
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//')
        case "$trimmed" in
            '#'*|'//'*|'/*'*|'*'*|'--'*)
                line_idx=$((line_idx + 1))
                continue
                ;;
        esac

        # 提取候选字符串
        while IFS= read -r candidate; do
            [[ -z "$candidate" ]] && continue

            # 跳过误报
            is_false_positive "$candidate" && continue

            # 计算熵值
            local entropy
            entropy=$(calc_entropy "$candidate")

            # 与阈值比较
            local above
            above=$(awk -v e="$entropy" -v t="$THRESHOLD" 'BEGIN { print (e >= t) ? 1 : 0 }')

            if [[ "$above" -eq 1 ]]; then
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                local severity
                severity=$(get_severity "$entropy")

                # 截断显示
                local display_str="$candidate"
                if [[ ${#display_str} -gt 60 ]]; then
                    display_str="${display_str:0:40}...${display_str: -10}"
                fi

                # ─── 收集上下文行 ───
                local ctx_before=()
                local ctx_after=()
                local ctx_start=$((line_idx - CONTEXT_LINES))
                local ctx_end=$((line_idx + CONTEXT_LINES))
                if [[ $ctx_start -lt 0 ]]; then
                    ctx_start=0
                fi
                if [[ $ctx_end -ge $total_lines ]]; then
                    ctx_end=$((total_lines - 1))
                fi

                # 前面的上下文
                local ci=$ctx_start
                while [[ $ci -lt $line_idx ]]; do
                    ctx_before+=("${file_lines[$ci]}")
                    ci=$((ci + 1))
                done

                # 后面的上下文
                ci=$((line_idx + 1))
                while [[ $ci -le $ctx_end ]]; do
                    ctx_after+=("${file_lines[$ci]}")
                    ci=$((ci + 1))
                done

                if $OUTPUT_JSON; then
                    local escaped_evidence
                    escaped_evidence=$(json_escape_str "$display_str")

                    # 构建 context_before JSON 数组
                    local json_ctx_before="["
                    local bi=0
                    while [[ $bi -lt ${#ctx_before[@]} ]]; do
                        local escaped_ctx
                        escaped_ctx=$(json_escape_str "${ctx_before[$bi]}")
                        if [[ $bi -gt 0 ]]; then
                            json_ctx_before="${json_ctx_before},"
                        fi
                        json_ctx_before="${json_ctx_before}\"${escaped_ctx}\""
                        bi=$((bi + 1))
                    done
                    json_ctx_before="${json_ctx_before}]"

                    # 构建 context_after JSON 数组
                    local json_ctx_after="["
                    local ai=0
                    while [[ $ai -lt ${#ctx_after[@]} ]]; do
                        local escaped_ctx
                        escaped_ctx=$(json_escape_str "${ctx_after[$ai]}")
                        if [[ $ai -gt 0 ]]; then
                            json_ctx_after="${json_ctx_after},"
                        fi
                        json_ctx_after="${json_ctx_after}\"${escaped_ctx}\""
                        ai=$((ai + 1))
                    done
                    json_ctx_after="${json_ctx_after}]"

                    local item
                    item=$(printf '{"id":"ENTROPY-%03d","file":"%s","line":%d,"entropy":%.4f,"severity":"%s","evidence":"%s","length":%d,"context_before":%s,"context_after":%s,"verified":false}' \
                        "$TOTAL_FINDINGS" "$file" "$line_num" "$entropy" "$severity" "$escaped_evidence" "${#candidate}" "$json_ctx_before" "$json_ctx_after")
                    if [[ -n "$JSON_ITEMS" ]]; then
                        JSON_ITEMS="${JSON_ITEMS},${item}"
                    else
                        JSON_ITEMS="$item"
                    fi
                else
                    local color
                    case "$severity" in
                        critical) color="$RED" ;;
                        high)     color="$RED" ;;
                        medium)   color="$YELLOW" ;;
                        *)        color="$GREEN" ;;
                    esac

                    # 输出上下文 before（DIM）
                    local bi=0
                    local ctx_line_num=$((line_num - ${#ctx_before[@]}))
                    while [[ $bi -lt ${#ctx_before[@]} ]]; do
                        printf "  ${DIM}%5d │ %s${RESET}\n" "$ctx_line_num" "${ctx_before[$bi]}"
                        ctx_line_num=$((ctx_line_num + 1))
                        bi=$((bi + 1))
                    done

                    # 输出匹配行（带颜色和严重性标记）
                    printf "  ${color}%5d │ %s${RESET}  ${color}← [%s]${RESET}\n" "$line_num" "$line" "$severity"

                    # 输出上下文 after（DIM）
                    local ai=0
                    ctx_line_num=$((line_num + 1))
                    while [[ $ai -lt ${#ctx_after[@]} ]]; do
                        printf "  ${DIM}%5d │ %s${RESET}\n" "$ctx_line_num" "${ctx_after[$ai]}"
                        ctx_line_num=$((ctx_line_num + 1))
                        ai=$((ai + 1))
                    done

                    # 输出熵值详情
                    printf "         ${color}[%s]${RESET} entropy=%.4f  len=%d  %s\n\n" \
                        "$severity" "$entropy" "${#candidate}" "$display_str"
                fi
            fi
        done < <(extract_candidates "$line")

        line_idx=$((line_idx + 1))
    done
}

# ─── 构建 find 排除参数 ───
build_find_excludes() {
    local excludes=()
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        excludes+=("-not" "-path" "'*/$pattern'")
    done
    echo "${excludes[@]}"
}

# ─── 主流程 ───
if ! $OUTPUT_JSON; then
    echo ""
    echo -e "${BOLD}CLS-Certify 熵值检测${RESET}"
    echo -e "阈值: ${CYAN}${THRESHOLD}${RESET}  最小长度: ${CYAN}${MIN_LENGTH}${RESET}  上下文: ${CYAN}${CONTEXT_LINES}${RESET} 行"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo "────────────────────────────────────────"
fi

if [[ -f "$TARGET" ]]; then
    scan_file "$TARGET"
elif [[ -d "$TARGET" ]]; then
    excludes=$(build_find_excludes)
    while IFS= read -r file; do
        scan_file "$file"
    done < <(eval "find '$TARGET' -type f -size -1M $excludes" 2>/dev/null)
fi

# ─── 输出结果 ───
if $OUTPUT_JSON; then
    printf '{"tool":"cls-entropy-detect","threshold":%s,"min_length":%s,"context_lines":%d,"target":"%s","total_findings":%d,"findings":[%s]}\n' \
        "$THRESHOLD" "$MIN_LENGTH" "$CONTEXT_LINES" "$TARGET" "$TOTAL_FINDINGS" "$JSON_ITEMS"
else
    echo "────────────────────────────────────────"
    if [[ $TOTAL_FINDINGS -eq 0 ]]; then
        echo -e "${GREEN}未发现高熵字符串${RESET}"
    else
        echo -e "${YELLOW}共发现 ${BOLD}${TOTAL_FINDINGS}${RESET}${YELLOW} 个高熵字符串${RESET}"
    fi
    echo ""
fi

exit $( [[ $TOTAL_FINDINGS -eq 0 ]] && echo 0 || echo 1 )
