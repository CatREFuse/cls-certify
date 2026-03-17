#!/usr/bin/env bash
# CLS-Certify 代码统计工具
# 统计 Skill 代码的基本信息，并提取 Markdown 中嵌入的代码块
#
# 用法:
#   ./tools/code-stats.sh <dir> [--json]
#
# 示例:
#   ./tools/code-stats.sh ./my-skill
#   ./tools/code-stats.sh ./my-skill --json

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
TARGET=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── 排除的目录模式 ───
EXCLUDE_DIRS=(
    ".git"
    "node_modules"
    "__pycache__"
    ".venv"
    "venv"
    ".env"
    "vendor"
    "dist"
    "build"
    ".next"
    ".nuxt"
    "coverage"
    ".tox"
    ".mypy_cache"
    ".pytest_cache"
)

# ─── 危险关键词 ───
DANGEROUS_KEYWORDS=(
    "eval"
    "exec"
    "system"
    "os\.system"
    "subprocess"
    "child_process"
    "rm -rf"
    "rm -f"
    "chmod 777"
    "mkfs"
    "format"
    "curl.*|.*bash"
    "wget.*&&.*sh"
    "fetch.*eval"
    "sudo"
    "doas"
    "su -"
    "dangerouslyDisableSandbox"
    "--no-verify"
)

# ─── 可执行语言列表 ───
EXEC_LANGS="bash|shell|sh|zsh|python|javascript|typescript|node|ruby|go|rust|java|php|perl"

# ─── 可执行语言判定（用于分类统计） ───
is_executable_language() {
    case "$1" in
        JavaScript|TypeScript|Python|Shell|Ruby|Go|Rust|Java|PHP) return 0 ;;
        *) return 1 ;;
    esac
}

# ─── 跨平台获取文件字节数 ───
get_file_size() {
    if [[ "$(uname)" == "Darwin" ]]; then
        stat -f%z "$1" 2>/dev/null || echo 0
    else
        stat -c%s "$1" 2>/dev/null || echo 0
    fi
}

# ─── 格式化体积 ───
format_size() {
    local bytes="$1"
    if [[ $bytes -ge 1048576 ]]; then
        awk -v b="$bytes" 'BEGIN { printf "%.1f MB", b/1048576 }'
    elif [[ $bytes -ge 1024 ]]; then
        awk -v b="$bytes" 'BEGIN { printf "%.1f KB", b/1024 }'
    else
        echo "${bytes} B"
    fi
}

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 代码统计工具"
    echo ""
    echo "用法: $0 <dir> [options]"
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
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "错误: 请指定要扫描的目录"
    usage
fi

if [[ ! -d "$TARGET" ]]; then
    echo "错误: $TARGET 不是一个有效目录"
    exit 1
fi

# ─── 临时文件 ───
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LANG_STATS_FILE="$TMP_DIR/lang_stats.txt"
BLOCKS_FILE="$TMP_DIR/blocks.txt"
FILES_LIST_FILE="$TMP_DIR/files_list.txt"

touch "$LANG_STATS_FILE" "$BLOCKS_FILE" "$FILES_LIST_FILE"

# ─── 千分位格式化 ───
format_number() {
    local n="$1"
    printf "%'d" "$n" 2>/dev/null || echo "$n"
}

# ─── 构建 find 排除参数 ───
build_find_excludes() {
    local excludes=""
    for dir in "${EXCLUDE_DIRS[@]}"; do
        excludes="$excludes -not -path '*/${dir}/*' -not -path '*/${dir}'"
    done
    echo "$excludes"
}

# ─── 扩展名 → 语言映射 ───
ext_to_language() {
    local ext="$1"
    case "$ext" in
        .js|.mjs|.cjs)      echo "JavaScript" ;;
        .ts|.tsx)            echo "TypeScript" ;;
        .py)                 echo "Python" ;;
        .sh|.bash|.zsh)      echo "Shell" ;;
        .rb)                 echo "Ruby" ;;
        .go)                 echo "Go" ;;
        .rs)                 echo "Rust" ;;
        .java)               echo "Java" ;;
        .php)                echo "PHP" ;;
        .json)               echo "JSON" ;;
        .yaml|.yml)          echo "YAML" ;;
        .toml)               echo "TOML" ;;
        .md)                 echo "Markdown" ;;
        .html|.htm)          echo "HTML" ;;
        .css|.scss|.less)    echo "CSS" ;;
        *)                   echo "Other" ;;
    esac
}

# ─── 语言 → 扩展名列表（用于 JSON 输出） ───
language_extensions() {
    local lang="$1"
    case "$lang" in
        JavaScript)  echo '".js",".mjs",".cjs"' ;;
        TypeScript)  echo '".ts",".tsx"' ;;
        Python)      echo '".py"' ;;
        Shell)       echo '".sh",".bash",".zsh"' ;;
        Ruby)        echo '".rb"' ;;
        Go)          echo '".go"' ;;
        Rust)        echo '".rs"' ;;
        Java)        echo '".java"' ;;
        PHP)         echo '".php"' ;;
        JSON)        echo '".json"' ;;
        YAML)        echo '".yaml",".yml"' ;;
        TOML)        echo '".toml"' ;;
        Markdown)    echo '".md"' ;;
        HTML)        echo '".html",".htm"' ;;
        CSS)         echo '".css",".scss",".less"' ;;
        Other)       echo '"other"' ;;
    esac
}

# ─── 收集所有文件 ───
EXCLUDES=$(build_find_excludes)
ALL_FILES=()
while IFS= read -r file; do
    [[ -n "$file" ]] && ALL_FILES+=("$file")
done < <(eval "find '$TARGET' -type f $EXCLUDES" 2>/dev/null | sort)

TOTAL_FILES=${#ALL_FILES[@]}
TOTAL_LINES=0
TOTAL_SIZE_BYTES=0
EXECUTABLE_LINES=0
EXECUTABLE_SIZE_BYTES=0
OVERSIZED_THRESHOLD=51200  # 50KB

# ─── 按语言统计（使用临时文件代替关联数组） ───
# 每个文件记录一行: 语言 行数
# FILES_LIST_FILE 格式: relpath \t lang \t lines \t size_bytes
for file in ${ALL_FILES[@]+"${ALL_FILES[@]}"}; do
    ext=""
    basename_file="${file##*/}"
    if [[ "$basename_file" == *.* ]]; then
        ext=".${basename_file##*.}"
    fi
    lang=$(ext_to_language "$ext")

    lines=$(wc -l < "$file" 2>/dev/null || echo 0)
    lines=$(echo "$lines" | tr -d ' ')
    size_bytes=$(get_file_size "$file")

    echo "$lang $lines" >> "$LANG_STATS_FILE"
    TOTAL_LINES=$((TOTAL_LINES + lines))
    TOTAL_SIZE_BYTES=$((TOTAL_SIZE_BYTES + size_bytes))

    # 累计可执行语言行数和体积
    if is_executable_language "$lang"; then
        EXECUTABLE_LINES=$((EXECUTABLE_LINES + lines))
        EXECUTABLE_SIZE_BYTES=$((EXECUTABLE_SIZE_BYTES + size_bytes))
    fi

    # 记录文件清单（相对路径 + 语言 + 行数 + 体积）
    relpath="${file#$TARGET/}"
    if [[ "$relpath" == "$file" ]]; then
        relpath="${file#$TARGET}"
    fi
    printf "%s\t%s\t%d\t%d\n" "$relpath" "$lang" "$lines" "$size_bytes" >> "$FILES_LIST_FILE"
done

# ─── 检查 references/ 目录 ───
HAS_REFERENCES_DIR=false
REF_CODE_FILES_FILE="$TMP_DIR/ref_code_files.txt"
touch "$REF_CODE_FILES_FILE"

if [[ -d "$TARGET/references" ]]; then
    while IFS= read -r rf; do
        [[ -n "$rf" ]] && {
            rf_ext=".${rf##*.}"
            rf_lang=$(ext_to_language "$rf_ext")
            if is_executable_language "$rf_lang"; then
                HAS_REFERENCES_DIR=true
                rf_rel="${rf#$TARGET/}"
                [[ "$rf_rel" == "$rf" ]] && rf_rel="${rf#$TARGET}"
                echo "$rf_rel" >> "$REF_CODE_FILES_FILE"
            fi
        }
    done < <(eval "find '$TARGET/references' -type f $EXCLUDES" 2>/dev/null | sort)
fi

# ─── 收集超大文件 ───
OVERSIZED_FILES_FILE="$TMP_DIR/oversized_files.txt"
touch "$OVERSIZED_FILES_FILE"
while IFS=$'\t' read -r f_path f_lang f_lines f_size; do
    [[ -z "$f_path" ]] && continue
    if [[ $f_size -ge $OVERSIZED_THRESHOLD ]]; then
        printf "%s\t%s\t%d\t%d\n" "$f_path" "$f_lang" "$f_lines" "$f_size" >> "$OVERSIZED_FILES_FILE"
    fi
done < "$FILES_LIST_FILE"

# ─── 用 awk 聚合语言统计，按行数降序 ───
LANG_SUMMARY_FILE="$TMP_DIR/lang_summary.txt"
awk '{
    lang=$1
    lines=$2
    lang_files[lang]++
    lang_lines[lang]+=lines
}
END {
    for (lang in lang_files) {
        printf "%d %d %s\n", lang_lines[lang], lang_files[lang], lang
    }
}' "$LANG_STATS_FILE" | sort -rn > "$LANG_SUMMARY_FILE"

# ─── Markdown 代码块提取 ───
BLOCK_COUNT=0
BLOCK_HIGH=0
BLOCK_MEDIUM=0
BLOCK_LOW=0

scan_md_blocks() {
    local file="$1"
    local relpath="${file#$TARGET/}"
    if [[ "$relpath" == "$file" ]]; then
        relpath="${file#$TARGET}"
    fi
    [[ -z "$relpath" ]] && relpath="$file"

    local in_block=false
    local block_lang=""
    local block_start=0
    local block_content=""
    local block_lines=0
    local line_num=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))

        if [[ "$in_block" == false ]]; then
            # 检测代码块开始: ``` 后跟可选的语言标记
            if echo "$line" | grep -qE '^\`\`\`[a-zA-Z0-9_+-]*'; then
                in_block=true
                block_lang=$(echo "$line" | sed -n 's/^```\([a-zA-Z0-9_+-]*\).*/\1/p')
                block_lang=$(echo "$block_lang" | tr '[:upper:]' '[:lower:]')
                [[ -z "$block_lang" ]] && block_lang="text"
                block_start=$line_num
                block_content=""
                block_lines=0
            fi
        else
            # 检测代码块结束
            if echo "$line" | grep -qE '^\`\`\`[[:space:]]*$'; then
                in_block=false
                BLOCK_COUNT=$((BLOCK_COUNT + 1))

                # 判断风险等级
                local risk="low"
                local found_keywords=""

                if echo "$block_lang" | grep -qE "^($EXEC_LANGS)$"; then
                    # 可执行语言，检查危险关键词
                    local has_danger=false
                    for kw in "${DANGEROUS_KEYWORDS[@]}"; do
                        if echo "$block_content" | grep -qE "$kw" 2>/dev/null; then
                            has_danger=true
                            # 将正则形式转为可读形式用于输出
                            local readable_kw
                            readable_kw=$(echo "$kw" | sed 's/\.\*//g; s/\\\.//g')
                            if [[ -n "$found_keywords" ]]; then
                                found_keywords="${found_keywords}^${readable_kw}"
                            else
                                found_keywords="$readable_kw"
                            fi
                        fi
                    done

                    if [[ "$has_danger" == true ]]; then
                        risk="high"
                        BLOCK_HIGH=$((BLOCK_HIGH + 1))
                    else
                        risk="medium"
                        BLOCK_MEDIUM=$((BLOCK_MEDIUM + 1))
                    fi
                else
                    risk="low"
                    BLOCK_LOW=$((BLOCK_LOW + 1))
                fi

                # 预览内容：第一行非空内容，截断到 60 字符
                local preview=""
                preview=$(echo "$block_content" | sed '/^[[:space:]]*$/d' | head -n 1)
                if [[ ${#preview} -gt 60 ]]; then
                    preview="${preview:0:57}..."
                fi

                local block_id
                block_id=$(printf "BLOCK-%03d" "$BLOCK_COUNT")

                # 将结果记录到临时文件 (TAB 分隔)
                # 格式: block_id \t relpath \t block_start \t block_lang \t risk \t block_lines \t found_keywords \t preview
                local escaped_preview
                escaped_preview=$(echo "$preview" | tr '\t' ' ')
                # 空的 found_keywords 用 _NONE_ 占位，防止 read 字段错位
                local kw_field="${found_keywords:-_NONE_}"
                printf "%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\n" \
                    "$block_id" "$relpath" "$block_start" "$block_lang" "$risk" "$block_lines" "$kw_field" "$escaped_preview" >> "$BLOCKS_FILE"
            else
                block_content="${block_content}${line}"$'\n'
                block_lines=$((block_lines + 1))
            fi
        fi
    done < "$file"
}

# 扫描所有 .md 文件
for file in ${ALL_FILES[@]+"${ALL_FILES[@]}"}; do
    if [[ "$file" == *.md ]]; then
        scan_md_blocks "$file"
    fi
done

# ─── 输出结果 ───
if $OUTPUT_JSON; then
    # ─── JSON 输出 ───

    # 构建 languages 数组
    LANGS_JSON=""
    while IFS= read -r summary_line; do
        [[ -z "$summary_line" ]] && continue
        lines_count=$(echo "$summary_line" | awk '{print $1}')
        files_count=$(echo "$summary_line" | awk '{print $2}')
        lang=$(echo "$summary_line" | awk '{$1=""; $2=""; print substr($0,3)}')

        if [[ $TOTAL_LINES -gt 0 ]]; then
            pct=$(awk -v l="$lines_count" -v t="$TOTAL_LINES" 'BEGIN { printf "%.1f", (l/t)*100 }')
        else
            pct="0.0"
        fi
        exts=$(language_extensions "$lang")

        local_json=$(printf '{"language":"%s","extensions":[%s],"files":%d,"lines":%d,"percentage":%s}' \
            "$lang" "$exts" "$files_count" "$lines_count" "$pct")

        if [[ -n "$LANGS_JSON" ]]; then
            LANGS_JSON="${LANGS_JSON},${local_json}"
        else
            LANGS_JSON="$local_json"
        fi
    done < "$LANG_SUMMARY_FILE"

    # 构建 code_blocks JSON
    JSON_BLOCKS=""
    while IFS=$'\t' read -r block_id relpath block_start block_lang risk block_lines found_keywords preview; do
        [[ -z "$block_id" ]] && continue

        # 还原占位符
        [[ "$found_keywords" == "_NONE_" ]] && found_keywords=""

        # 构建 dangerous_keywords JSON 数组
        kw_json="[]"
        if [[ -n "$found_keywords" ]]; then
            kw_json="["
            first=true
            IFS='^' read -ra kw_arr <<< "$found_keywords"
            for kw in "${kw_arr[@]}"; do
                if $first; then
                    first=false
                else
                    kw_json="${kw_json},"
                fi
                escaped_kw=$(echo "$kw" | sed 's/\\/\\\\/g; s/"/\\"/g')
                kw_json="${kw_json}\"${escaped_kw}\""
            done
            kw_json="${kw_json}]"
        fi

        escaped_preview=$(echo "$preview" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g')

        block_json=$(printf '{"id":"%s","file":"%s","line":%d,"language":"%s","risk":"%s","lines_count":%d,"dangerous_keywords":%s,"preview":"%s"}' \
            "$block_id" "$relpath" "$block_start" "$block_lang" "$risk" "$block_lines" "$kw_json" "$escaped_preview")

        if [[ -n "$JSON_BLOCKS" ]]; then
            JSON_BLOCKS="${JSON_BLOCKS},${block_json}"
        else
            JSON_BLOCKS="$block_json"
        fi
    done < "$BLOCKS_FILE"

    # 构建 files 对象数组
    FILES_JSON=""
    while IFS=$'\t' read -r f_path f_lang f_lines f_size; do
        [[ -z "$f_path" ]] && continue
        escaped_f=$(echo "$f_path" | sed 's/\\/\\\\/g; s/"/\\"/g')
        file_json=$(printf '{"path":"%s","language":"%s","lines":%d,"size_bytes":%d}' \
            "$escaped_f" "$f_lang" "$f_lines" "$f_size")
        if [[ -n "$FILES_JSON" ]]; then
            FILES_JSON="${FILES_JSON},${file_json}"
        else
            FILES_JSON="$file_json"
        fi
    done < "$FILES_LIST_FILE"

    # 构建 oversized_files 数组
    OVERSIZED_JSON=""
    while IFS=$'\t' read -r o_path o_lang o_lines o_size; do
        [[ -z "$o_path" ]] && continue
        escaped_o=$(echo "$o_path" | sed 's/\\/\\\\/g; s/"/\\"/g')
        o_json=$(printf '{"path":"%s","language":"%s","lines":%d,"size_bytes":%d}' \
            "$escaped_o" "$o_lang" "$o_lines" "$o_size")
        if [[ -n "$OVERSIZED_JSON" ]]; then
            OVERSIZED_JSON="${OVERSIZED_JSON},${o_json}"
        else
            OVERSIZED_JSON="$o_json"
        fi
    done < "$OVERSIZED_FILES_FILE"

    # 构建 reference_code_files 数组
    REF_CODE_JSON=""
    while IFS= read -r rf; do
        [[ -z "$rf" ]] && continue
        escaped_rf=$(echo "$rf" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [[ -n "$REF_CODE_JSON" ]]; then
            REF_CODE_JSON="${REF_CODE_JSON},\"${escaped_rf}\""
        else
            REF_CODE_JSON="\"${escaped_rf}\""
        fi
    done < "$REF_CODE_FILES_FILE"

    printf '{"tool":"cls-code-stats","target":"%s","total_files":%d,"total_lines":%d,"total_size_bytes":%d,"executable_lines":%d,"executable_size_bytes":%d,"has_references_dir":%s,"reference_code_files":[%s],"oversized_files":[%s],"languages":[%s],"code_blocks":{"total":%d,"high_risk":%d,"medium_risk":%d,"low_risk":%d,"blocks":[%s]},"files":[%s]}\n' \
        "$TARGET" "$TOTAL_FILES" "$TOTAL_LINES" "$TOTAL_SIZE_BYTES" \
        "$EXECUTABLE_LINES" "$EXECUTABLE_SIZE_BYTES" \
        "$HAS_REFERENCES_DIR" "$REF_CODE_JSON" "$OVERSIZED_JSON" "$LANGS_JSON" \
        "$BLOCK_COUNT" "$BLOCK_HIGH" "$BLOCK_MEDIUM" "$BLOCK_LOW" "$JSON_BLOCKS" \
        "$FILES_JSON"
else
    # ─── CLI 输出 ───
    echo ""
    echo -e "${BOLD}CLS-Certify 代码统计${RESET}"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo "────────────────────────────────────────"

    echo -e "${BOLD}文件统计:${RESET}"
    printf "  总文件数:     %s\n" "$(format_number "$TOTAL_FILES")"
    printf "  总行数:       %s\n" "$(format_number "$TOTAL_LINES")"
    printf "  总体积:       %s\n" "$(format_size "$TOTAL_SIZE_BYTES")"
    printf "  可执行代码行: %s\n" "$(format_number "$EXECUTABLE_LINES")"
    printf "  可执行代码量: %s\n" "$(format_size "$EXECUTABLE_SIZE_BYTES")"
    printf "  references/:  %s\n" "$($HAS_REFERENCES_DIR && echo '存在' || echo '无')"

    echo ""
    echo -e "${BOLD}语言分布:${RESET}"

    # 计算对齐宽度
    max_lang_len=0
    while IFS= read -r summary_line; do
        [[ -z "$summary_line" ]] && continue
        lang=$(echo "$summary_line" | awk '{$1=""; $2=""; print substr($0,3)}')
        if [[ ${#lang} -gt $max_lang_len ]]; then
            max_lang_len=${#lang}
        fi
    done < "$LANG_SUMMARY_FILE"

    while IFS= read -r summary_line; do
        [[ -z "$summary_line" ]] && continue
        lines_count=$(echo "$summary_line" | awk '{print $1}')
        files_count=$(echo "$summary_line" | awk '{print $2}')
        lang=$(echo "$summary_line" | awk '{$1=""; $2=""; print substr($0,3)}')

        if [[ $TOTAL_LINES -gt 0 ]]; then
            pct=$(awk -v l="$lines_count" -v t="$TOTAL_LINES" 'BEGIN { printf "%.1f", (l/t)*100 }')
        else
            pct="0.0"
        fi

        file_word="files"
        [[ $files_count -eq 1 ]] && file_word="file "

        printf "  %-${max_lang_len}s  %d %s  %6s lines  (%s%%)\n" \
            "$lang" "$files_count" "$file_word" "$(format_number "$lines_count")" "$pct"
    done < "$LANG_SUMMARY_FILE"

    echo ""
    echo -e "${BOLD}Markdown 代码块:${RESET}"
    printf "  总代码块数: %s\n" "$(format_number "$BLOCK_COUNT")"

    if [[ $BLOCK_COUNT -gt 0 ]]; then
        while IFS=$'\t' read -r block_id relpath block_start block_lang risk block_lines found_keywords preview; do
            [[ -z "$block_id" ]] && continue

            color=""
            case "$risk" in
                high)   color="$RED" ;;
                medium) color="$YELLOW" ;;
                low)    color="$GREEN" ;;
            esac

            display_lang="${block_lang:-text}"
            if [[ "$risk" == "high" ]]; then
                echo -e "  ${color}[${risk}]${RESET}   ${BOLD}${relpath}:${block_start}${RESET}  ${display_lang}  \"${preview}\""
            else
                echo -e "  ${color}[${risk}]${RESET}   ${BOLD}${relpath}:${block_start}${RESET}  ${display_lang}  (${block_lines} 行)"
            fi
        done < "$BLOCKS_FILE"
    fi

    # ─── 超大文件警告 ───
    oversized_count=$(wc -l < "$OVERSIZED_FILES_FILE" | tr -d ' ')
    if [[ $oversized_count -gt 0 ]]; then
        echo ""
        echo -e "${RED}${BOLD}超大文件 (>50KB):${RESET}"
        while IFS=$'\t' read -r o_path o_lang o_lines o_size; do
            [[ -z "$o_path" ]] && continue
            echo -e "  ${RED}[$(format_size "$o_size")]${RESET}  ${o_path}  (${o_lang}, ${o_lines} 行)"
        done < "$OVERSIZED_FILES_FILE"
    fi

    echo ""
    echo "────────────────────────────────────────"
    echo -e "${BOLD}文件清单 (${TOTAL_FILES} 个文件):${RESET}"
    while IFS=$'\t' read -r f_path f_lang f_lines f_size; do
        [[ -z "$f_path" ]] && continue
        printf "  %-40s  %-12s  %5d 行  %s\n" "$f_path" "$f_lang" "$f_lines" "$(format_size "$f_size")"
    done < "$FILES_LIST_FILE"
    echo ""
fi
