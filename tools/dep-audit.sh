#!/usr/bin/env bash
# CLS-Certify 依赖审计工具
# 解析项目依赖文件，检测 typosquatting（名称混淆攻击）和可疑依赖
#
# 用法:
#   ./tools/dep-audit.sh <dir> [--json]
#
# 示例:
#   ./tools/dep-audit.sh ./my-skill
#   ./tools/dep-audit.sh ./my-skill --json

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

# ─── 知名包列表 ───
KNOWN_NPM="lodash express react vue angular axios webpack babel eslint prettier typescript jest mocha chai sinon moment dayjs date-fns underscore jquery bootstrap tailwindcss next nuxt gatsby remix svelte solid vite vitest rollup esbuild playwright puppeteer cypress"
KNOWN_PIP="requests flask django numpy pandas scipy matplotlib tensorflow pytorch keras scikit-learn beautifulsoup4 sqlalchemy celery redis pillow cryptography paramiko pyyaml boto3 fastapi uvicorn gunicorn black flake8 pytest mypy"
KNOWN_GENERAL="dotenv commander yargs chalk inquirer ora glob rimraf mkdirp semver uuid nanoid"
ALL_KNOWN_PACKAGES="${KNOWN_NPM} ${KNOWN_PIP} ${KNOWN_GENERAL}"

# ─── 已知合法的含 "可疑关键词" 的包（白名单，不触发关键词检测） ───
KEYWORD_WHITELIST="@testing-library vitest jest pytest mocha chai cypress playwright @playwright test-utils testing testcontainers debug"

# ─── 可疑关键词 ───
SUSPICIOUS_KEYWORDS="test|debug|hack|exploit|malicious|backdoor"

# ─── 后缀变体 ───
VARIANT_SUFFIXES="-js -node -py -python"

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 依赖审计工具"
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
    echo "错误: 请指定要审计的目录"
    usage
fi

if [[ ! -d "$TARGET" ]]; then
    echo "错误: $TARGET 不是一个有效目录"
    exit 1
fi

# ─── Levenshtein 距离（awk 实现） ───
levenshtein() {
    local s1="$1"
    local s2="$2"
    awk -v s1="$s1" -v s2="$s2" 'BEGIN {
        m = length(s1)
        n = length(s2)
        # 初始化矩阵
        for (i = 0; i <= m; i++) d[i,0] = i
        for (j = 0; j <= n; j++) d[0,j] = j
        # 动态规划
        for (i = 1; i <= m; i++) {
            ci = substr(s1, i, 1)
            for (j = 1; j <= n; j++) {
                cj = substr(s2, j, 1)
                cost = (ci == cj) ? 0 : 1
                v_del = d[i-1,j] + 1
                v_ins = d[i,j-1] + 1
                v_rep = d[i-1,j-1] + cost
                # min(v_del, v_ins, v_rep)
                min_val = v_del
                if (v_ins < min_val) min_val = v_ins
                if (v_rep < min_val) min_val = v_rep
                d[i,j] = min_val
            }
        }
        print d[m,n]
    }'
}

# ─── 解析 package.json ───
parse_package_json() {
    local file="$1"
    local direct_pkgs=""
    local dev_pkgs=""

    if command -v jq &>/dev/null; then
        # jq 可用，优先使用
        direct_pkgs=$(jq -r '.dependencies // {} | keys[]' "$file" 2>/dev/null || true)
        dev_pkgs=$(jq -r '.devDependencies // {} | keys[]' "$file" 2>/dev/null || true)
    else
        # 回退到 grep/sed
        local in_deps=false
        local in_dev_deps=false
        local brace_depth=0
        while IFS= read -r line; do
            if echo "$line" | grep -q '"dependencies"'; then
                in_deps=true; in_dev_deps=false; brace_depth=0; continue
            fi
            if echo "$line" | grep -q '"devDependencies"'; then
                in_dev_deps=true; in_deps=false; brace_depth=0; continue
            fi
            if $in_deps || $in_dev_deps; then
                if echo "$line" | grep -q '{'; then
                    brace_depth=$((brace_depth + 1))
                fi
                if echo "$line" | grep -q '}'; then
                    brace_depth=$((brace_depth - 1))
                    if [[ $brace_depth -le 0 ]]; then
                        in_deps=false; in_dev_deps=false
                        continue
                    fi
                fi
                local pkg_name
                pkg_name=$(echo "$line" | sed -n 's/.*"\([^"]*\)"\s*:.*/\1/p')
                if [[ -n "$pkg_name" ]]; then
                    if $in_deps; then
                        direct_pkgs="${direct_pkgs}${direct_pkgs:+$'\n'}${pkg_name}"
                    else
                        dev_pkgs="${dev_pkgs}${dev_pkgs:+$'\n'}${pkg_name}"
                    fi
                fi
            fi
        done < "$file"
    fi

    local direct_count=0
    local dev_count=0
    if [[ -n "$direct_pkgs" ]]; then
        direct_count=$(echo "$direct_pkgs" | wc -l | tr -d ' ')
    fi
    if [[ -n "$dev_pkgs" ]]; then
        dev_count=$(echo "$dev_pkgs" | wc -l | tr -d ' ')
    fi

    # 输出格式: direct_count|dev_count|所有包名(换行分隔)
    local all_pkgs=""
    if [[ -n "$direct_pkgs" ]] && [[ -n "$dev_pkgs" ]]; then
        all_pkgs="${direct_pkgs}"$'\n'"${dev_pkgs}"
    elif [[ -n "$direct_pkgs" ]]; then
        all_pkgs="$direct_pkgs"
    elif [[ -n "$dev_pkgs" ]]; then
        all_pkgs="$dev_pkgs"
    fi

    echo "${direct_count}|${dev_count}"
    if [[ -n "$all_pkgs" ]]; then
        echo "$all_pkgs"
    fi
}

# ─── 解析 requirements.txt ───
parse_requirements_txt() {
    local file="$1"
    local pkgs=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        # 跳过空行和注释
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        [[ -z "$trimmed" ]] && continue
        [[ "$trimmed" == \#* ]] && continue
        # 跳过 -r, -e, --option 行
        [[ "$trimmed" == -* ]] && continue
        # 提取包名（去掉版本号、extras 等）
        local pkg_name
        pkg_name=$(echo "$trimmed" | sed -E 's/[>=<!~;].*//' | sed -E 's/\[.*\]//' | tr -d ' ')
        if [[ -n "$pkg_name" ]]; then
            pkgs="${pkgs}${pkgs:+$'\n'}${pkg_name}"
        fi
    done < "$file"

    local count=0
    if [[ -n "$pkgs" ]]; then
        count=$(echo "$pkgs" | wc -l | tr -d ' ')
    fi

    echo "${count}|0"
    if [[ -n "$pkgs" ]]; then
        echo "$pkgs"
    fi
}

# ─── 解析 Gemfile ───
parse_gemfile() {
    local file="$1"
    local pkgs=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        [[ -z "$trimmed" ]] && continue
        [[ "$trimmed" == \#* ]] && continue
        # 提取 gem 'name' 或 gem "name"
        local pkg_name
        pkg_name=$(echo "$trimmed" | sed -n "s/^gem ['\"]\\([^'\"]*\\)['\"].*/\\1/p")
        if [[ -n "$pkg_name" ]]; then
            pkgs="${pkgs}${pkgs:+$'\n'}${pkg_name}"
        fi
    done < "$file"

    local count=0
    if [[ -n "$pkgs" ]]; then
        count=$(echo "$pkgs" | wc -l | tr -d ' ')
    fi

    echo "${count}|0"
    if [[ -n "$pkgs" ]]; then
        echo "$pkgs"
    fi
}

# ─── 解析 go.mod ───
parse_go_mod() {
    local file="$1"
    local pkgs=""
    local in_require=false
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        # require ( ... ) 块
        if echo "$trimmed" | grep -qE '^require\s*\('; then
            in_require=true; continue
        fi
        if $in_require; then
            if echo "$trimmed" | grep -q '^)'; then
                in_require=false; continue
            fi
            [[ -z "$trimmed" ]] && continue
            [[ "$trimmed" == //* ]] && continue
            # 提取模块路径（第一个字段）
            local mod_path
            mod_path=$(echo "$trimmed" | awk '{print $1}')
            if [[ -n "$mod_path" ]]; then
                pkgs="${pkgs}${pkgs:+$'\n'}${mod_path}"
            fi
            continue
        fi
        # 单行 require
        local mod_path
        mod_path=$(echo "$trimmed" | sed -n 's/^require \([^ ]*\) .*/\1/p')
        if [[ -n "$mod_path" ]]; then
            pkgs="${pkgs}${pkgs:+$'\n'}${mod_path}"
        fi
    done < "$file"

    local count=0
    if [[ -n "$pkgs" ]]; then
        count=$(echo "$pkgs" | wc -l | tr -d ' ')
    fi

    echo "${count}|0"
    if [[ -n "$pkgs" ]]; then
        echo "$pkgs"
    fi
}

# ─── 解析 Cargo.toml ───
parse_cargo_toml() {
    local file="$1"
    local pkgs=""
    local in_deps=false
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        # 检测 [dependencies] 或 [dev-dependencies] 段
        if echo "$trimmed" | grep -qiE '^\[dependencies\]$'; then
            in_deps=true; continue
        fi
        if echo "$trimmed" | grep -qiE '^\[dev-dependencies\]$'; then
            in_deps=true; continue
        fi
        # 遇到其他段落标题则结束
        if echo "$trimmed" | grep -qE '^\['; then
            in_deps=false; continue
        fi
        if $in_deps; then
            [[ -z "$trimmed" ]] && continue
            [[ "$trimmed" == \#* ]] && continue
            # 提取包名（= 号前面）
            local pkg_name
            pkg_name=$(echo "$trimmed" | sed -n 's/^\([a-zA-Z0-9_-]*\)[[:space:]]*=.*/\1/p')
            if [[ -n "$pkg_name" ]]; then
                pkgs="${pkgs}${pkgs:+$'\n'}${pkg_name}"
            fi
        fi
    done < "$file"

    local count=0
    if [[ -n "$pkgs" ]]; then
        count=$(echo "$pkgs" | wc -l | tr -d ' ')
    fi

    echo "${count}|0"
    if [[ -n "$pkgs" ]]; then
        echo "$pkgs"
    fi
}

# ─── 检测可疑后缀变体 ───
# 返回: 匹配的知名包名，或空
check_suffix_variant() {
    local pkg="$1"
    for suffix in $VARIANT_SUFFIXES; do
        if [[ "$pkg" == *"$suffix" ]]; then
            local base="${pkg%"$suffix"}"
            for known in $ALL_KNOWN_PACKAGES; do
                if [[ "$base" == "$known" ]]; then
                    echo "$known"
                    return 0
                fi
            done
        fi
    done
    return 1
}

# ─── 检测可疑关键词 ───
check_suspicious_keywords() {
    local pkg="$1"
    echo "$pkg" | grep -qiE "$SUSPICIOUS_KEYWORDS"
}

# ─── 全局计数 ───
TOTAL_DEPS=0
TOTAL_FINDINGS=0
FINDING_ID=0
JSON_FILES=""
JSON_FINDINGS=""

# ─── 检查单个依赖文件 ───
audit_dep_file() {
    local file="$1"
    local ecosystem="$2"
    local parse_func="$3"

    local rel_file
    rel_file=$(echo "$file" | sed "s|^${TARGET%/}/||")
    local basename_file
    basename_file=$(basename "$file")

    # 解析依赖
    local parse_output
    parse_output=$($parse_func "$file")

    local counts
    counts=$(echo "$parse_output" | head -1)
    local direct_count
    direct_count=$(echo "$counts" | cut -d'|' -f1)
    local dev_count
    dev_count=$(echo "$counts" | cut -d'|' -f2)
    local total_count=$((direct_count + dev_count))
    TOTAL_DEPS=$((TOTAL_DEPS + total_count))

    # 提取包列表（跳过第一行的计数）
    local packages=""
    if [[ $(echo "$parse_output" | wc -l | tr -d ' ') -gt 1 ]]; then
        packages=$(echo "$parse_output" | tail -n +2)
    fi

    # JSON: 记录文件信息
    local packages_json="[]"
    if [[ -n "$packages" ]]; then
        packages_json="["
        local first=true
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            local escaped_pkg
            escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
            if $first; then
                packages_json="${packages_json}\"${escaped_pkg}\""
                first=false
            else
                packages_json="${packages_json},\"${escaped_pkg}\""
            fi
        done <<< "$packages"
        packages_json="${packages_json}]"
    fi

    local file_json
    file_json=$(printf '{"file":"%s","ecosystem":"%s","direct_count":%d,"dev_count":%d,"packages":%s}' \
        "$basename_file" "$ecosystem" "$direct_count" "$dev_count" "$packages_json")

    if [[ -n "$JSON_FILES" ]]; then
        JSON_FILES="${JSON_FILES},${file_json}"
    else
        JSON_FILES="$file_json"
    fi

    # CLI 输出文件头
    if ! $OUTPUT_JSON; then
        echo -e "文件: ${BOLD}${basename_file}${RESET} (${ecosystem})"
        if [[ "$dev_count" -gt 0 ]]; then
            echo -e "  依赖总数: ${CYAN}${total_count}${RESET} (direct: ${direct_count}, dev: ${dev_count})"
        else
            echo -e "  依赖总数: ${CYAN}${total_count}${RESET}"
        fi
        echo ""
    fi

    if [[ -z "$packages" ]]; then
        if ! $OUTPUT_JSON; then
            echo "  (无依赖)"
            echo ""
        fi
        return
    fi

    # 对每个包进行检测
    local file_findings=0
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue

        # 提取最后一个 / 后的部分（用于 go module 路径）
        local short_pkg="$pkg"
        if [[ "$ecosystem" == "go" ]]; then
            short_pkg=$(basename "$pkg")
        fi

        # 转小写用于比较
        local pkg_lower
        pkg_lower=$(echo "$short_pkg" | tr '[:upper:]' '[:lower:]')

        # 如果包名本身就是知名包，跳过 typosquatting 检测
        local is_known=false
        for known in $ALL_KNOWN_PACKAGES; do
            if [[ "$pkg_lower" == "$known" ]]; then
                is_known=true
                break
            fi
        done

        # 1. Typosquatting 检测（Levenshtein 距离）— 仅对非知名包进行
        local found_typo=false
        if ! $is_known; then
        for known in $ALL_KNOWN_PACKAGES; do
            # 跳过完全匹配
            if [[ "$pkg_lower" == "$known" ]]; then
                continue
            fi

            # 快速过滤：长度差超过 2 的直接跳过
            local len_pkg=${#pkg_lower}
            local len_known=${#known}
            local len_diff=$((len_pkg - len_known))
            [[ $len_diff -lt 0 ]] && len_diff=$((-len_diff))
            if [[ $len_diff -gt 2 ]]; then
                continue
            fi

            local dist
            dist=$(levenshtein "$pkg_lower" "$known")

            if [[ "$dist" -le 2 ]]; then
                found_typo=true
                FINDING_ID=$((FINDING_ID + 1))
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                file_findings=$((file_findings + 1))

                local escaped_pkg
                escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
                local finding_json
                finding_json=$(printf '{"id":"DEP-%03d","package":"%s","ecosystem":"%s","file":"%s","severity":"high","category":"typosquatting","similar_to":"%s","distance":%d,"description":"包名与知名包 %s 仅差 %d 个字符，疑似 typosquatting","recommendation":"请确认包名是否拼写正确"}' \
                    "$FINDING_ID" "$escaped_pkg" "$ecosystem" "$basename_file" "$known" "$dist" "$known" "$dist")

                if [[ -n "$JSON_FINDINGS" ]]; then
                    JSON_FINDINGS="${JSON_FINDINGS},${finding_json}"
                else
                    JSON_FINDINGS="$finding_json"
                fi

                if ! $OUTPUT_JSON; then
                    printf "  ${RED}[high]${RESET} ${BOLD}%s${RESET} -> 疑似 ${CYAN}%s${RESET} 的 typosquatting (距离: %d)\n" \
                        "$pkg" "$known" "$dist"
                fi

                break  # 找到最近的匹配即停止
            fi
        done

        # 2. 后缀变体检测（仅在未检测到 typosquatting 时）
        if ! $found_typo; then
            local variant_match=""
            variant_match=$(check_suffix_variant "$pkg_lower" 2>/dev/null || true)
            if [[ -n "$variant_match" ]]; then
                FINDING_ID=$((FINDING_ID + 1))
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                file_findings=$((file_findings + 1))

                local escaped_pkg
                escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
                local finding_json
                finding_json=$(printf '{"id":"DEP-%03d","package":"%s","ecosystem":"%s","file":"%s","severity":"medium","category":"suffix-variant","similar_to":"%s","distance":0,"description":"包名含后缀，去掉后缀后匹配知名包 %s，可能为混淆变体","recommendation":"请确认是否应使用 %s"}' \
                    "$FINDING_ID" "$escaped_pkg" "$ecosystem" "$basename_file" "$variant_match" "$variant_match" "$variant_match")

                if [[ -n "$JSON_FINDINGS" ]]; then
                    JSON_FINDINGS="${JSON_FINDINGS},${finding_json}"
                else
                    JSON_FINDINGS="$finding_json"
                fi

                if ! $OUTPUT_JSON; then
                    printf "  ${YELLOW}[medium]${RESET} ${BOLD}%s${RESET} -> 疑似 ${CYAN}%s${RESET} 的变体 (去后缀匹配)\n" \
                        "$pkg" "$variant_match"
                fi
            fi
        fi
        fi  # end if ! $is_known

        # 3. 可疑关键词检测（对完整包名/路径进行检查，白名单豁免）
        local full_pkg_lower
        full_pkg_lower=$(echo "$pkg" | tr '[:upper:]' '[:lower:]')
        local keyword_whitelisted=false
        for wl in $KEYWORD_WHITELIST; do
            if [[ "$full_pkg_lower" == "$wl" || "$full_pkg_lower" == "$wl/"* || "$full_pkg_lower" == *"/$wl" ]]; then
                keyword_whitelisted=true
                break
            fi
            # 支持 scoped 包前缀匹配: @testing-library/anything
            if [[ "$wl" == @* && "$full_pkg_lower" == "$wl/"* ]]; then
                keyword_whitelisted=true
                break
            fi
        done
        if ! $keyword_whitelisted && check_suspicious_keywords "$full_pkg_lower"; then
            FINDING_ID=$((FINDING_ID + 1))
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
            file_findings=$((file_findings + 1))

            local matched_keyword
            matched_keyword=$(echo "$full_pkg_lower" | grep -oiE "$SUSPICIOUS_KEYWORDS" | head -1)

            local escaped_pkg
            escaped_pkg=$(echo "$pkg" | sed 's/"/\\"/g')
            local finding_json
            finding_json=$(printf '{"id":"DEP-%03d","package":"%s","ecosystem":"%s","file":"%s","severity":"high","category":"suspicious-keyword","similar_to":"","distance":0,"description":"包名含可疑关键词 %s","recommendation":"请确认此依赖的来源和用途"}' \
                "$FINDING_ID" "$escaped_pkg" "$ecosystem" "$basename_file" "$matched_keyword")

            if [[ -n "$JSON_FINDINGS" ]]; then
                JSON_FINDINGS="${JSON_FINDINGS},${finding_json}"
            else
                JSON_FINDINGS="$finding_json"
            fi

            if ! $OUTPUT_JSON; then
                printf "  ${RED}[high]${RESET} ${BOLD}%s${RESET} -> 包名含可疑关键词 \"${YELLOW}%s${RESET}\"\n" \
                    "$pkg" "$matched_keyword"
            fi
        fi

    done <<< "$packages"

    if [[ $file_findings -eq 0 ]] && ! $OUTPUT_JSON; then
        echo "  (无异常)"
    fi

    if ! $OUTPUT_JSON; then
        echo ""
    fi
}

# ─── 主流程 ───
if ! $OUTPUT_JSON; then
    echo ""
    echo -e "${BOLD}CLS-Certify 依赖审计${RESET}"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo "────────────────────────────────────────"
fi

# 扫描依赖文件
FILES_FOUND=0

# package.json
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    FILES_FOUND=$((FILES_FOUND + 1))
    audit_dep_file "$f" "npm" "parse_package_json"
done < <(find "$TARGET" -name "package.json" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)

# requirements.txt
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    FILES_FOUND=$((FILES_FOUND + 1))
    audit_dep_file "$f" "pip" "parse_requirements_txt"
done < <(find "$TARGET" -name "requirements.txt" -not -path "*/.git/*" 2>/dev/null)

# Gemfile
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    FILES_FOUND=$((FILES_FOUND + 1))
    audit_dep_file "$f" "ruby" "parse_gemfile"
done < <(find "$TARGET" -name "Gemfile" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null)

# go.mod
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    FILES_FOUND=$((FILES_FOUND + 1))
    audit_dep_file "$f" "go" "parse_go_mod"
done < <(find "$TARGET" -name "go.mod" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null)

# Cargo.toml
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    FILES_FOUND=$((FILES_FOUND + 1))
    audit_dep_file "$f" "rust" "parse_cargo_toml"
done < <(find "$TARGET" -name "Cargo.toml" -not -path "*/.git/*" -not -path "*/target/*" 2>/dev/null)

# ─── 无依赖文件 ───
if [[ $FILES_FOUND -eq 0 ]]; then
    if $OUTPUT_JSON; then
        printf '{"tool":"cls-dep-audit","target":"%s","total_dependencies":0,"dep_files":[],"total_findings":0,"findings":[]}\n' "$TARGET"
    else
        echo -e "  ${YELLOW}未找到任何依赖文件${RESET}"
        echo "────────────────────────────────────────"
    fi
    exit 0
fi

# ─── 输出结果 ───
if $OUTPUT_JSON; then
    printf '{"tool":"cls-dep-audit","target":"%s","total_dependencies":%d,"dep_files":[%s],"total_findings":%d,"findings":[%s]}\n' \
        "$TARGET" "$TOTAL_DEPS" "$JSON_FILES" "$TOTAL_FINDINGS" "$JSON_FINDINGS"
else
    echo "────────────────────────────────────────"
    if [[ $TOTAL_FINDINGS -eq 0 ]]; then
        echo -e "${GREEN}未发现可疑依赖${RESET}"
    else
        echo -e "${YELLOW}共发现 ${BOLD}${TOTAL_FINDINGS}${RESET}${YELLOW} 个可疑依赖${RESET}"
    fi
    echo ""
fi

exit $( [[ $TOTAL_FINDINGS -eq 0 ]] && echo 0 || echo 1 )
