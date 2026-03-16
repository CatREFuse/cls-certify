#!/usr/bin/env bash
# CLS-Certify 敏感信息扫描工具
# 扫描文件/目录中的硬编码 API Key、密码、私钥、连接串、JWT、PII 等敏感信息
#
# 用法:
#   ./tools/secret-scan.sh <file_or_dir> [--json] [--min-severity critical|high|medium|low] [--context N]
#
# 示例:
#   ./tools/secret-scan.sh ./src/
#   ./tools/secret-scan.sh config.js --min-severity high
#   ./tools/secret-scan.sh ./src/ --json --min-severity critical
#   ./tools/secret-scan.sh ./src/ --context 5

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
MIN_SEVERITY="low"
TARGET=""
CONTEXT_LINES=3

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
    "*.pyc" "*.class" "*.o" "*.so" "*.dylib" "*.exe"
)

# ─── 严重性等级数值（用于比较过滤） ───
severity_to_num() {
    case "$1" in
        critical) echo 4 ;;
        high)     echo 3 ;;
        medium)   echo 2 ;;
        low)      echo 1 ;;
        *)        echo 0 ;;
    esac
}

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 敏感信息扫描工具"
    echo ""
    echo "用法: $0 <file_or_dir> [options]"
    echo ""
    echo "选项:"
    echo "  --json                    输出 JSON 格式"
    echo "  --min-severity <level>    最低严重性 (critical|high|medium|low, 默认: low)"
    echo "  --context <N>             上下文行数 (默认: 3)"
    echo "  -h, --help                显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        --min-severity) MIN_SEVERITY="$2"; shift 2 ;;
        --context) CONTEXT_LINES="$2"; shift 2 ;;
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

MIN_SEVERITY_NUM=$(severity_to_num "$MIN_SEVERITY")

# ─── 敏感信息正则模式定义 ───
# 格式: "severity|pattern_name|description|regex"
PATTERNS=(
    # ── Critical ──
    'critical|openai_api_key|OpenAI API Key|sk-proj-[a-zA-Z0-9]{20,}'
    'critical|openai_api_key|OpenAI API Key|sk-[a-zA-Z0-9]{20,}'
    'critical|github_token|GitHub Personal Access Token|ghp_[a-zA-Z0-9]{36}'
    'critical|github_oauth_token|GitHub OAuth Token|gho_[a-zA-Z0-9]{36}'
    'critical|github_app_token|GitHub App Token|ghs_[a-zA-Z0-9]{36}'
    'critical|github_refresh_token|GitHub Refresh Token|ghr_[a-zA-Z0-9]{36}'
    'critical|aws_access_key|AWS Access Key ID|AKIA[0-9A-Z]{16}'
    'critical|aws_temp_key|AWS Temporary Access Key|ASIA[0-9A-Z]{16}'
    'critical|aliyun_access_key|Alibaba Cloud Access Key|LTAI[a-zA-Z0-9]{16}'
    'critical|tencent_secret_id|Tencent Cloud Secret ID|AKID[a-zA-Z0-9]{32}'
    'critical|google_api_key|Google API Key|AIza[0-9A-Za-z_-]{35}'
    'critical|private_key|Private Key File|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    'critical|db_connection_string|Database Connection String|(mongodb|mysql|postgresql|redis)://[^:]+:[^@]+@'
    'critical|hardcoded_password|Hardcoded Password|(password|passwd|pwd)\s*[=:]\s*['"'"'""][^'"'"'""]{4,}['"'"'""]'

    # ── High ──
    'high|generic_api_key|Generic API Key/Secret/Token|api[_-]?(key|secret|token)\s*[=:]\s*['"'"'""][a-zA-Z0-9_\-]{32,}['"'"'""]'
    'high|bearer_token|Bearer/Token Authentication|(bearer|token)\s+[a-zA-Z0-9_\-.]{40,}'
    'high|jwt_token|JSON Web Token|eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
    'high|env_secret|Environment File Secret|^[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|PASS)=[^\s'"'"'"]{8,}'
    'high|x_api_key_header|X-API-Key Header|x-api-key\s*:\s*[a-zA-Z0-9_\-]{32,}'

    # ── Medium ──
    'medium|email_address|Email Address|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    'medium|ip_address|IP Address|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
)

# ─── 误报关键词（用于行上下文检测） ───
FALSE_POSITIVE_CONTEXT="example|sample|placeholder|your_key_here|your-api-key|TODO|FIXME|lorem|ipsum|fake|mock|dummy|changeme|replace_me|INSERT_HERE"

# ─── 高置信前缀模式（有明确前缀的密钥，不做通用误报过滤） ───
HIGH_CONFIDENCE_PATTERNS="openai_api_key|github_token|github_oauth_token|github_app_token|github_refresh_token|aws_access_key|aws_temp_key|aliyun_access_key|tencent_secret_id|google_api_key|private_key|db_connection_string|jwt_token"

# ─── 判断是否为误报 ───
is_false_positive() {
    local matched="$1"
    local pattern_name="$2"
    local full_line="$3"

    # 高置信前缀模式：只检查行上下文中是否有明确的占位符提示
    if echo "$pattern_name" | grep -qE "$HIGH_CONFIDENCE_PATTERNS"; then
        # 仅当行上下文中有明确占位标记时才判为误报
        echo "$full_line" | grep -qiE "(${FALSE_POSITIVE_CONTEXT})" && return 0
        return 1
    fi

    # 其他模式：对匹配内容本身做误报检测
    echo "$matched" | grep -qiE "$FALSE_POSITIVE_CONTEXT" && return 0
    # 全是重复字符（如 000000, aaaaaa）
    local unique_chars
    unique_chars=$(echo "$matched" | fold -w1 | sort -u | wc -l | tr -d ' ')
    [[ "$unique_chars" -le 3 ]] && return 0

    # 密码模式的额外误报过滤
    if [[ "$pattern_name" == "hardcoded_password" ]]; then
        # 排除 environ / os.getenv / getpass / input / process.env 等动态取值
        echo "$full_line" | grep -qiE '(environ|getenv|getpass|input\(|process\.env|os\.environ|System\.getenv|vault|config\.|Config\.)' && return 0
        # 排除赋值为空字符串
        echo "$matched" | grep -qE "[=:]\s*['\"](\s*)['\"]" && return 0
    fi

    # Email 模式的误报过滤
    if [[ "$pattern_name" == "email_address" ]]; then
        echo "$matched" | grep -qiE '@(example\.com|test\.com|localhost|example\.org|test\.org|foo\.com|bar\.com|domain\.com|email\.com|your-domain\.com)' && return 0
        # 排除常见非真实邮箱模式
        echo "$matched" | grep -qiE '^(user|admin|info|test|hello|no-?reply|webmaster|support)@' && return 0
    fi

    # IP 地址的误报过滤
    if [[ "$pattern_name" == "ip_address" ]]; then
        # 排除回环和广播地址
        echo "$matched" | grep -qE '^(127\.|0\.0\.0\.0|255\.255\.255\.255|localhost)' && return 0
        # 排除内网段
        echo "$matched" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' && return 0
        # 排除版本号模式（如 1.2.3.4 类似的短数字）
        local octets
        octets=$(echo "$matched" | tr '.' '\n')
        local max_octet=0
        while IFS= read -r o; do
            [[ "$o" -gt 255 ]] 2>/dev/null && return 0
        done <<< "$octets"
    fi

    # 通用：检测是否在注释或测试上下文
    echo "$full_line" | grep -qiE '^\s*(#|//|/\*|\*|--)\s*.*(example|test|demo|fake|mock)' && return 0

    return 1
}

# ─── 截断显示 ───
truncate_str() {
    local str="$1"
    local max_len="${2:-60}"
    if [[ ${#str} -gt $max_len ]]; then
        echo "${str:0:40}...${str: -10}"
    else
        echo "$str"
    fi
}

# ─── 转义 JSON 字符串 ───
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

# ─── 扫描单个文件 ───
TOTAL_FINDINGS=0
JSON_ITEMS=""
FINDING_ID=0

scan_file() {
    local file="$1"

    # 检查文件是否为文本文件（跳过二进制）
    if ! file "$file" 2>/dev/null | grep -qiE '(text|json|xml|script|source|ascii|utf)'; then
        return
    fi

    # 将文件读入数组（兼容 macOS bash 3.2）
    local file_lines=()
    local total_lines=0
    while IFS= read -r _line || [[ -n "$_line" ]]; do
        file_lines+=("$_line")
        total_lines=$((total_lines + 1))
    done < "$file"

    local idx=0
    while [[ $idx -lt $total_lines ]]; do
        local line="${file_lines[$idx]}"
        local line_num=$((idx + 1))
        idx=$((idx + 1))

        # 跳过空行
        [[ -z "$line" ]] && continue

        # 遍历所有模式
        for pattern_def in "${PATTERNS[@]}"; do
            local sev pname desc regex
            IFS='|' read -r sev pname desc regex <<< "$pattern_def"

            # 严重性过滤
            local sev_num
            sev_num=$(severity_to_num "$sev")
            [[ "$sev_num" -lt "$MIN_SEVERITY_NUM" ]] && continue

            # 正则匹配
            local matched
            matched=$(echo "$line" | grep -oE "$regex" 2>/dev/null | head -1) || true
            [[ -z "$matched" ]] && continue

            # 误报过滤
            is_false_positive "$matched" "$pname" "$line" && continue

            FINDING_ID=$((FINDING_ID + 1))
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))

            local display_str
            display_str=$(truncate_str "$matched")

            # ─── 提取上下文行 ───
            local ctx_before=()
            local ctx_after=()
            local cb_start=$((idx - 1 - CONTEXT_LINES))
            [[ $cb_start -lt 0 ]] && cb_start=0
            local cb_end=$((idx - 2))  # idx 已经 +1，所以 idx-2 是命中行的前一行
            local ci=$cb_start
            while [[ $ci -le $cb_end && $ci -ge 0 ]]; do
                ctx_before+=("${file_lines[$ci]}")
                ci=$((ci + 1))
            done

            local ca_start=$idx  # idx 已经 +1，当前就是下一行
            local ca_end=$((idx - 1 + CONTEXT_LINES))
            [[ $ca_end -ge $total_lines ]] && ca_end=$((total_lines - 1))
            ci=$ca_start
            while [[ $ci -le $ca_end ]]; do
                ctx_after+=("${file_lines[$ci]}")
                ci=$((ci + 1))
            done

            if $OUTPUT_JSON; then
                local escaped_evidence escaped_file escaped_desc
                escaped_evidence=$(json_escape "$display_str")
                escaped_file=$(json_escape "$file")
                escaped_desc=$(json_escape "$desc")

                # 构建 context_before JSON 数组
                local json_ctx_before="["
                local first=true
                local cb_item
                for cb_item in "${ctx_before[@]+"${ctx_before[@]}"}"; do
                    if $first; then
                        first=false
                    else
                        json_ctx_before="${json_ctx_before},"
                    fi
                    json_ctx_before="${json_ctx_before}\"$(json_escape "$cb_item")\""
                done
                json_ctx_before="${json_ctx_before}]"

                # 构建 context_after JSON 数组
                local json_ctx_after="["
                first=true
                local ca_item
                for ca_item in "${ctx_after[@]+"${ctx_after[@]}"}"; do
                    if $first; then
                        first=false
                    else
                        json_ctx_after="${json_ctx_after},"
                    fi
                    json_ctx_after="${json_ctx_after}\"$(json_escape "$ca_item")\""
                done
                json_ctx_after="${json_ctx_after}]"

                local item
                item=$(printf '{"id":"SECRET-%03d","file":"%s","line":%d,"severity":"%s","pattern_name":"%s","description":"%s","evidence":"%s","context_before":%s,"context_after":%s,"verified":false,"recommendation":"%s"}' \
                    "$FINDING_ID" "$escaped_file" "$line_num" "$sev" "$pname" "$escaped_desc" "$escaped_evidence" "$json_ctx_before" "$json_ctx_after" "使用环境变量存储密钥")
                if [[ -n "$JSON_ITEMS" ]]; then
                    JSON_ITEMS="${JSON_ITEMS},${item}"
                else
                    JSON_ITEMS="$item"
                fi
            else
                local color
                case "$sev" in
                    critical) color="$RED" ;;
                    high)     color="$RED" ;;
                    medium)   color="$YELLOW" ;;
                    *)        color="$GREEN" ;;
                esac
                printf "  ${color}[%s]${RESET} ${BOLD}%s${RESET}:%d  pattern=${CYAN}%s${RESET}\n" \
                    "$sev" "$file" "$line_num" "$pname"

                # 显示上下文：命中行前
                local ctx_line_num
                ctx_line_num=$((line_num - ${#ctx_before[@]}))
                local cb_display
                for cb_display in "${ctx_before[@]+"${ctx_before[@]}"}"; do
                    printf "    ${DIM}%4d │ %s${RESET}\n" "$ctx_line_num" "$cb_display"
                    ctx_line_num=$((ctx_line_num + 1))
                done

                # 显示命中行（红色高亮）
                printf "    ${RED}${BOLD}%4d │ %s${RESET}\n" "$line_num" "$line"

                # 显示上下文：命中行后
                ctx_line_num=$((line_num + 1))
                local ca_display
                for ca_display in "${ctx_after[@]+"${ctx_after[@]}"}"; do
                    printf "    ${DIM}%4d │ %s${RESET}\n" "$ctx_line_num" "$ca_display"
                    ctx_line_num=$((ctx_line_num + 1))
                done

                printf "         evidence: %s\n\n" "$display_str"
            fi

            # 每行每个模式只取第一个匹配，避免重复
            break
        done
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
    echo -e "${BOLD}CLS-Certify 敏感信息扫描${RESET}"
    echo -e "最低严重性: ${CYAN}${MIN_SEVERITY}${RESET}"
    echo -e "上下文行数: ${CYAN}${CONTEXT_LINES}${RESET}"
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
    local_target=$(json_escape "$TARGET")
    printf '{"tool":"cls-secret-scan","target":"%s","min_severity":"%s","context_lines":%d,"total_findings":%d,"findings":[%s]}\n' \
        "$local_target" "$MIN_SEVERITY" "$CONTEXT_LINES" "$TOTAL_FINDINGS" "$JSON_ITEMS"
else
    echo "────────────────────────────────────────"
    if [[ $TOTAL_FINDINGS -eq 0 ]]; then
        echo -e "${GREEN}未发现硬编码敏感信息${RESET}"
    else
        echo -e "${YELLOW}共发现 ${BOLD}${TOTAL_FINDINGS}${RESET}${YELLOW} 个敏感信息${RESET}"
    fi
    echo ""
fi

exit $( [[ $TOTAL_FINDINGS -eq 0 ]] && echo 0 || echo 1 )
