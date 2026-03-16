#!/usr/bin/env bash
# CLS-Certify 熵值检测工具
# 扫描文件中的高熵字符串，识别可能的硬编码密钥、Token 等敏感信息
#
# 用法:
#   ./tools/entropy-detect.sh <file_or_dir> [--threshold 4.5] [--min-length 20] [--json]
#
# 示例:
#   ./tools/entropy-detect.sh ./src/
#   ./tools/entropy-detect.sh config.js --threshold 4.0 --min-length 16
#   ./tools/entropy-detect.sh ./src/ --json

set -euo pipefail

# ─── 默认参数 ───
THRESHOLD="4.5"
MIN_LENGTH="20"
OUTPUT_JSON=false
TARGET=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
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
    echo "  --json                 输出 JSON 格式"
    echo "  -h, --help             显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --min-length) MIN_LENGTH="$2"; shift 2 ;;
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

# ─── 扫描单个文件 ───
TOTAL_FINDINGS=0
JSON_ITEMS=""

scan_file() {
    local file="$1"
    local line_num=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))

        # 跳过注释行
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//')
        case "$trimmed" in
            '#'*|'//'*|'/*'*|'*'*|'--'*) continue ;;
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

                if $OUTPUT_JSON; then
                    local escaped_evidence
                    escaped_evidence=$(echo "$display_str" | sed 's/"/\\"/g')
                    local item
                    item=$(printf '{"id":"ENTROPY-%03d","file":"%s","line":%d,"entropy":%.4f,"severity":"%s","evidence":"%s","length":%d}' \
                        "$TOTAL_FINDINGS" "$file" "$line_num" "$entropy" "$severity" "$escaped_evidence" "${#candidate}")
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
                    printf "  ${color}[%s]${RESET} ${BOLD}%s${RESET}:%d  entropy=%.4f  len=%d\n" \
                        "$severity" "$file" "$line_num" "$entropy" "${#candidate}"
                    printf "         %s\n\n" "$display_str"
                fi
            fi
        done < <(extract_candidates "$line")
    done < "$file"
}

# ─── 构建 find 排除参数 ───
build_find_excludes() {
    local excludes=()
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        excludes+=(-not -path "*/$pattern")
    done
    echo "${excludes[@]}"
}

# ─── 主流程 ───
if ! $OUTPUT_JSON; then
    echo ""
    echo -e "${BOLD}CLS-Certify 熵值检测${RESET}"
    echo -e "阈值: ${CYAN}${THRESHOLD}${RESET}  最小长度: ${CYAN}${MIN_LENGTH}${RESET}"
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
    printf '{"tool":"cls-entropy-detect","threshold":%s,"min_length":%s,"target":"%s","total_findings":%d,"findings":[%s]}\n' \
        "$THRESHOLD" "$MIN_LENGTH" "$TARGET" "$TOTAL_FINDINGS" "$JSON_ITEMS"
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
