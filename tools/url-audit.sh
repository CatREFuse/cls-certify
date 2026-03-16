#!/usr/bin/env bash
# CLS-Certify URL 审计工具
# 提取代码中的所有 URL/域名，按 14 类 API 分类标准进行自动分类和风险评估
#
# 用法:
#   ./tools/url-audit.sh <file_or_dir> [--json] [--context N] [--show-context]
#
# 示例:
#   ./tools/url-audit.sh ./src/
#   ./tools/url-audit.sh ./src/ --json
#   ./tools/url-audit.sh ./src/ --json --context 5
#   ./tools/url-audit.sh ./src/ --show-context

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
TARGET=""
CONTEXT_LINES=3
SHOW_CONTEXT=false

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

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify URL 审计工具"
    echo ""
    echo "用法: $0 <file_or_dir> [options]"
    echo ""
    echo "选项:"
    echo "  --json                 输出 JSON 格式"
    echo "  --context N            上下文行数 (默认 3)"
    echo "  --show-context         CLI 模式下显示上下文"
    echo "  -h, --help             显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        --context) CONTEXT_LINES="$2"; shift 2 ;;
        --show-context) SHOW_CONTEXT=true; shift ;;
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

# ─── 临时文件 ───
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# 存储: URL\tFILE:LINE
URL_RAW="$TMP_DIR/url_raw.txt"
# 去重后: URL\tLOCATIONS(逗号分隔)\tCOUNT
URL_DEDUP="$TMP_DIR/url_dedup.txt"
# 域名警告
DOMAIN_WARNINGS="$TMP_DIR/domain_warnings.txt"
# 上下文存储: URL\tFILE:LINE\tBEFORE_BASE64\tAFTER_BASE64
URL_CONTEXT="$TMP_DIR/url_context.txt"

touch "$URL_RAW" "$URL_DEDUP" "$DOMAIN_WARNINGS" "$URL_CONTEXT"

# ─── URL 提取正则 ───
URL_REGEX='https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%[-]+'

# ─── 14 类 API 分类函数 ───
# 输入: 域名
# 输出: category\trisk_level
classify_domain() {
    local domain="$1"

    # 2. ai_service (Low) — 必须在 cloud_service 之前检查，因为部分域名也匹配 cloud 通配符
    case "$domain" in
        api.openai.com|api.anthropic.com|generativelanguage.googleapis.com|\
api.deepseek.com|api.mistral.ai|api.cohere.ai|aip.baidubce.com|\
dashscope.aliyuncs.com|api.moonshot.cn)
            echo "ai_service	low"; return ;;
    esac

    # 7. advertising (High) — 在 cloud/social 之前
    case "$domain" in
        googleads.googleapis.com)
            echo "advertising	high"; return ;;
    esac

    # 8. social_media (Medium) — graph.facebook.com 也用于广告
    case "$domain" in
        api.twitter.com|oauth.reddit.com|api.linkedin.com|graph.instagram.com|\
youtube.googleapis.com|edith.xiaohongshu.com|api.weibo.com|graph.facebook.com)
            echo "social_media	medium"; return ;;
    esac

    # 10. search_knowledge (Low)
    case "$domain" in
        customsearch.googleapis.com|api.bing.microsoft.com|api.search.brave.com|\
serpapi.com|api.wolframalpha.com)
            echo "search_knowledge	low"; return ;;
    esac

    # 11. location (Medium)
    case "$domain" in
        maps.googleapis.com|api.mapbox.com|restapi.amap.com|api.map.baidu.com)
            echo "location	medium"; return ;;
    esac

    # 6. analytics (Medium)
    case "$domain" in
        google-analytics.com|*.google-analytics.com|api.mixpanel.com|\
api.amplitude.com|api.segment.io|app.posthog.com|plausible.io)
            echo "analytics	medium"; return ;;
    esac

    # 12. cdn_static (Low)
    case "$domain" in
        api.cloudflare.com|api.fastly.com|data.jsdelivr.com|unpkg.com|cdnjs.cloudflare.com)
            echo "cdn_static	low"; return ;;
    esac

    # 5. communication (Medium)
    case "$domain" in
        api.twilio.com|api.sendgrid.com|api.mailgun.net|api.pusherapp.com|rest.ably.io)
            echo "communication	medium"; return ;;
    esac
    # email.*.amazonaws.com
    if echo "$domain" | grep -qE '^email\..*\.amazonaws\.com$'; then
        echo "communication	medium"; return
    fi

    # 9. payment (Low - PCI required)
    case "$domain" in
        api.stripe.com|api.paypal.com|connect.squareup.com|openapi.alipay.com|\
api.mch.weixin.qq.com)
            echo "payment	low"; return ;;
    esac

    # 3. developer_tools (Low)
    case "$domain" in
        api.github.com|gitlab.com|api.bitbucket.org|hub.docker.com|\
registry.npmjs.org|pypi.org|crates.io)
            echo "developer_tools	low"; return ;;
    esac

    # 4. saas_productivity (Low)
    case "$domain" in
        slack.com|discord.com|api.notion.com|api.linear.app|api.trello.com|\
app.asana.com|api.monday.com)
            echo "saas_productivity	low"; return ;;
    esac

    # 13. blockchain (Medium)
    case "$domain" in
        api.etherscan.io|deep-index.moralis.io)
            echo "blockchain	medium"; return ;;
    esac
    if echo "$domain" | grep -qE '\.(infura|alchemyapi)\.io$'; then
        echo "blockchain	medium"; return
    fi

    # 14. suspicious — 域名含 collector/tracker/telemetry/beacon
    if echo "$domain" | grep -qiE 'collector|tracker|telemetry|beacon'; then
        echo "suspicious	critical"; return
    fi

    # 1. cloud_service (Low) — 通配符匹配放最后
    if echo "$domain" | grep -qE '\.(amazonaws|azure|windows\.net|googleapis|aliyuncs|tencentcloudapi|volces)\.com$' \
       || echo "$domain" | grep -qE '\.windows\.net$'; then
        echo "cloud_service	low"; return
    fi

    echo "unknown	low"
}

# ─── 域名信誉检查 ───
# 输入: URL, 域名
# 输出: 追加到 DOMAIN_WARNINGS 文件
check_reputation() {
    local url="$1"
    local domain="$2"

    # 短链接
    case "$domain" in
        bit.ly|t.co|tinyurl.com|is.gd|buff.ly|ow.ly)
            echo "${domain}	short_link	high	短链接，隐藏真实目标" >> "$DOMAIN_WARNINGS"
            ;;
    esac

    # 纯 IP 地址
    if echo "$domain" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "${domain}	ip_address	high	使用纯 IP 地址，无法验证身份" >> "$DOMAIN_WARNINGS"
    fi

    # 可疑 TLD
    if echo "$domain" | grep -qE '\.(tk|ml|ga|cf|top|xyz|buzz)$'; then
        echo "${domain}	suspicious_tld	medium	使用可疑顶级域名" >> "$DOMAIN_WARNINGS"
    fi

    # 动态 DNS
    if echo "$domain" | grep -qE '\.(ngrok\.io|serveo\.net|localtunnel\.me)$'; then
        echo "${domain}	dynamic_dns	high	动态 DNS 服务，可能为临时隧道" >> "$DOMAIN_WARNINGS"
    fi

    # 非标准端口
    local port
    port=$(echo "$url" | grep -oE ':[0-9]{4,5}(/|$)' | grep -oE '[0-9]+' || true)
    if [[ -n "$port" ]]; then
        case "$port" in
            80|443|8080|8443|3000|5000) ;;
            *) echo "${domain}:${port}	non_standard_port	medium	使用非标准端口 ${port}" >> "$DOMAIN_WARNINGS" ;;
        esac
    fi

    # Base64 编码 URL
    if echo "$url" | grep -q 'aHR0c'; then
        echo "${domain}	base64_url	high	URL 中包含 Base64 编码内容 (aHR0c)" >> "$DOMAIN_WARNINGS"
    fi
}

# ─── 提取域名 ───
extract_domain() {
    local url="$1"
    echo "$url" | sed -E 's|^https?://||' | sed -E 's|[/:?#].*||'
}

# ─── 清理 URL 尾部无效字符 ───
clean_url() {
    local url="$1"
    # 移除尾部的引号、逗号、分号、括号等非 URL 字符
    echo "$url" | sed -E "s/[\"',;\`)>]+$//" | sed -E 's/\)+$//'
}

# ─── 扫描单个文件 ───
scan_file() {
    local file="$1"

    # 先将文件所有行读入数组
    local file_lines_count=0
    while IFS= read -r _fline || [[ -n "$_fline" ]]; do
        file_lines_count=$((file_lines_count + 1))
        eval "FILE_LINE_${file_lines_count}=\$_fline"
    done < "$file"

    local line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))

        # 提取所有 URL
        local urls_in_line
        urls_in_line=$(echo "$line" | grep -oE "$URL_REGEX" 2>/dev/null || true)
        [[ -z "$urls_in_line" ]] && continue

        while IFS= read -r raw_url; do
            local url
            url=$(clean_url "$raw_url")
            [[ -z "$url" ]] && continue

            # 跳过太短的 URL（只有协议+域名不足 10 字符的）
            [[ ${#url} -lt 10 ]] && continue

            printf '%s\t%s:%d\n' "$url" "$file" "$line_num" >> "$URL_RAW"

            # 收集上下文行
            local ctx_before=""
            local ctx_after=""
            local ctx_start=$((line_num - CONTEXT_LINES))
            local ctx_end=$((line_num + CONTEXT_LINES))
            [[ $ctx_start -lt 1 ]] && ctx_start=1
            [[ $ctx_end -gt $file_lines_count ]] && ctx_end=$file_lines_count

            local i=$ctx_start
            while [[ $i -lt $line_num ]]; do
                eval "local _ctx_line=\$FILE_LINE_${i}"
                if [[ -n "$ctx_before" ]]; then
                    ctx_before="${ctx_before}"$'\n'"${_ctx_line}"
                else
                    ctx_before="${_ctx_line}"
                fi
                i=$((i + 1))
            done

            i=$((line_num + 1))
            while [[ $i -le $ctx_end ]]; do
                eval "local _ctx_line=\$FILE_LINE_${i}"
                if [[ -n "$ctx_after" ]]; then
                    ctx_after="${ctx_after}"$'\n'"${_ctx_line}"
                else
                    ctx_after="${_ctx_line}"
                fi
                i=$((i + 1))
            done

            # base64 编码上下文以安全存储（macOS 兼容）
            local b64_before b64_after
            if [[ -n "$ctx_before" ]]; then
                b64_before=$(printf '%s' "$ctx_before" | base64)
            else
                b64_before=""
            fi
            if [[ -n "$ctx_after" ]]; then
                b64_after=$(printf '%s' "$ctx_after" | base64)
            else
                b64_after=""
            fi

            printf '%s\t%s:%d\t%s\t%s\n' "$url" "$file" "$line_num" "$b64_before" "$b64_after" >> "$URL_CONTEXT"
        done <<< "$urls_in_line"
    done < "$file"
}

# ─── 构建 find 排除参数 ───
build_find_excludes() {
    local excludes=""
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        excludes="$excludes -not -path '*/$pattern'"
    done
    echo "$excludes"
}

# ─── 去重合并 ───
dedup_urls() {
    if [[ ! -s "$URL_RAW" ]]; then
        return
    fi

    # 按 URL 分组，合并位置，计算出现次数
    sort "$URL_RAW" | awk -F'\t' '
    {
        url = $1
        loc = $2
        if (url in locations) {
            locations[url] = locations[url] "," loc
            count[url]++
        } else {
            locations[url] = loc
            count[url] = 1
            # 保持顺序
            order[++n] = url
            seen[url] = 1
        }
    }
    END {
        for (i = 1; i <= n; i++) {
            u = order[i]
            printf "%s\t%s\t%d\n", u, locations[u], count[u]
        }
    }' > "$URL_DEDUP"
}

# ─── 获取域名信誉标签 ───
get_reputation() {
    local domain="$1"
    # 检查该域名是否在 DOMAIN_WARNINGS 中（也匹配 domain:port 形式）
    if grep -qE "^${domain}(	|:)" "$DOMAIN_WARNINGS" 2>/dev/null; then
        echo "suspicious"
    else
        echo "trusted"
    fi
}

# ─── 根据域名警告提升风险等级 ───
# severity 等级: low < medium < high < critical
# 输入: 当前 risk_level, 域名
# 输出: 可能被提升后的 risk_level
elevate_risk_level() {
    local current="$1"
    local domain="$2"
    local max_sev="$current"

    if [[ -s "$DOMAIN_WARNINGS" ]]; then
        while IFS=$'\t' read -r w_domain w_flag w_sev w_desc; do
            if [[ "$w_domain" == "$domain" ]] || echo "$w_domain" | grep -q "^${domain}:"; then
                # 比较并取更高的级别
                case "$w_sev" in
                    critical) max_sev="critical" ;;
                    high)
                        [[ "$max_sev" != "critical" ]] && max_sev="high"
                        ;;
                    medium)
                        [[ "$max_sev" == "low" ]] && max_sev="medium"
                        ;;
                esac
            fi
        done < "$DOMAIN_WARNINGS"
    fi

    echo "$max_sev"
}

# ─── 主流程 ───
if ! $OUTPUT_JSON; then
    echo ""
    echo -e "${BOLD}CLS-Certify URL 审计${RESET}"
    echo -e "目标: ${CYAN}${TARGET}${RESET}"
    echo "────────────────────────────────────────"
fi

# 扫描文件
if [[ -f "$TARGET" ]]; then
    scan_file "$TARGET"
elif [[ -d "$TARGET" ]]; then
    excludes=$(build_find_excludes)
    while IFS= read -r file; do
        scan_file "$file"
    done < <(eval "find '$TARGET' -type f -size -1M $excludes" 2>/dev/null)
fi

# 去重
dedup_urls

# 对每个唯一 URL 做域名信誉检查（只检查一次每个唯一域名）
CHECKED_DOMAINS="$TMP_DIR/checked_domains.txt"
touch "$CHECKED_DOMAINS"

while IFS=$'\t' read -r url locations count; do
    domain=$(extract_domain "$url")
    if ! grep -qxF "$domain" "$CHECKED_DOMAINS" 2>/dev/null; then
        check_reputation "$url" "$domain"
        echo "$domain" >> "$CHECKED_DOMAINS"
    fi
done < "$URL_DEDUP"

# 去重域名警告
if [[ -s "$DOMAIN_WARNINGS" ]]; then
    sort -u "$DOMAIN_WARNINGS" > "$TMP_DIR/dw_sorted.txt"
    mv "$TMP_DIR/dw_sorted.txt" "$DOMAIN_WARNINGS"
fi

# ─── 输出结果 ───
TOTAL_APIS=0
API_COUNTER=0

if $OUTPUT_JSON; then
    # JSON 输出
    JSON_APIS=""
    JSON_WARNINGS=""

    while IFS=$'\t' read -r url locations count; do
        API_COUNTER=$((API_COUNTER + 1))
        TOTAL_APIS=$((TOTAL_APIS + 1))

        domain=$(extract_domain "$url")
        classification=$(classify_domain "$domain")
        category=$(echo "$classification" | cut -f1)
        risk_level=$(echo "$classification" | cut -f2)
        reputation=$(get_reputation "$domain")
        risk_level=$(elevate_risk_level "$risk_level" "$domain")

        # 收集该域名的 flags
        flags=""
        if [[ -s "$DOMAIN_WARNINGS" ]]; then
            while IFS=$'\t' read -r w_domain w_flag w_sev w_desc; do
                # 匹配域名（包含端口的情况也要匹配）
                if [[ "$w_domain" == "$domain" ]] || echo "$w_domain" | grep -q "^${domain}:"; then
                    if [[ -n "$flags" ]]; then
                        flags="${flags},\"${w_flag}\""
                    else
                        flags="\"${w_flag}\""
                    fi
                fi
            done < "$DOMAIN_WARNINGS"
        fi

        # 转换 locations 为 JSON 数组
        loc_json=""
        IFS=',' read -ra loc_arr <<< "$locations"
        for loc in "${loc_arr[@]}"; do
            if [[ -n "$loc_json" ]]; then
                loc_json="${loc_json},\"${loc}\""
            else
                loc_json="\"${loc}\""
            fi
        done

        # 收集该 URL 的上下文（取第一次出现的上下文）
        ctx_before_json="[]"
        ctx_after_json="[]"
        if [[ -s "$URL_CONTEXT" ]]; then
            ctx_line_match=$(grep -m1 "^$(echo "$url" | sed 's/[[\.*^$()+?{|]/\\&/g')	" "$URL_CONTEXT" 2>/dev/null || true)
            if [[ -n "$ctx_line_match" ]]; then
                b64_bef=$(echo "$ctx_line_match" | cut -f3)
                b64_aft=$(echo "$ctx_line_match" | cut -f4)

                if [[ -n "$b64_bef" ]]; then
                    decoded_bef=$(echo "$b64_bef" | base64 -d 2>/dev/null || echo "$b64_bef" | base64 -D 2>/dev/null || true)
                    if [[ -n "$decoded_bef" ]]; then
                        ctx_before_json="["
                        first_ctx=true
                        while IFS= read -r ctx_l; do
                            escaped_ctx=$(echo "$ctx_l" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/	/\\t/g')
                            if $first_ctx; then
                                ctx_before_json="${ctx_before_json}\"${escaped_ctx}\""
                                first_ctx=false
                            else
                                ctx_before_json="${ctx_before_json},\"${escaped_ctx}\""
                            fi
                        done <<< "$decoded_bef"
                        ctx_before_json="${ctx_before_json}]"
                    fi
                fi

                if [[ -n "$b64_aft" ]]; then
                    decoded_aft=$(echo "$b64_aft" | base64 -d 2>/dev/null || echo "$b64_aft" | base64 -D 2>/dev/null || true)
                    if [[ -n "$decoded_aft" ]]; then
                        ctx_after_json="["
                        first_ctx=true
                        while IFS= read -r ctx_l; do
                            escaped_ctx=$(echo "$ctx_l" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/	/\\t/g')
                            if $first_ctx; then
                                ctx_after_json="${ctx_after_json}\"${escaped_ctx}\""
                                first_ctx=false
                            else
                                ctx_after_json="${ctx_after_json},\"${escaped_ctx}\""
                            fi
                        done <<< "$decoded_aft"
                        ctx_after_json="${ctx_after_json}]"
                    fi
                fi
            fi
        fi

        # 转义 URL 中的特殊字符
        escaped_url=$(echo "$url" | sed 's/"/\\"/g')

        item=$(printf '{"id":"API-%03d","endpoint":"%s","domain":"%s","method":"unknown","category":"%s","reputation":"%s","risk_level":"%s","calls_count":%d,"locations":[%s],"flags":[%s],"context_before":%s,"context_after":%s,"verified":false}' \
            "$API_COUNTER" "$escaped_url" "$domain" "$category" "$reputation" "$risk_level" "$count" "$loc_json" "$flags" "$ctx_before_json" "$ctx_after_json")

        if [[ -n "$JSON_APIS" ]]; then
            JSON_APIS="${JSON_APIS},${item}"
        else
            JSON_APIS="$item"
        fi
    done < "$URL_DEDUP"

    # 域名警告 JSON
    if [[ -s "$DOMAIN_WARNINGS" ]]; then
        while IFS=$'\t' read -r w_domain w_flag w_sev w_desc; do
            escaped_desc=$(echo "$w_desc" | sed 's/"/\\"/g')
            w_item=$(printf '{"domain":"%s","flag":"%s","severity":"%s","description":"%s","verified":false}' \
                "$w_domain" "$w_flag" "$w_sev" "$escaped_desc")
            if [[ -n "$JSON_WARNINGS" ]]; then
                JSON_WARNINGS="${JSON_WARNINGS},${w_item}"
            else
                JSON_WARNINGS="$w_item"
            fi
        done < "$DOMAIN_WARNINGS"
    fi

    printf '{"tool":"cls-url-audit","target":"%s","total_apis":%d,"apis":[%s],"domain_warnings":[%s]}\n' \
        "$TARGET" "$TOTAL_APIS" "$JSON_APIS" "$JSON_WARNINGS"
else
    # CLI 输出
    while IFS=$'\t' read -r url locations count; do
        TOTAL_APIS=$((TOTAL_APIS + 1))

        domain=$(extract_domain "$url")
        classification=$(classify_domain "$domain")
        category=$(echo "$classification" | cut -f1)
        risk_level=$(echo "$classification" | cut -f2)
        reputation=$(get_reputation "$domain")
        risk_level=$(elevate_risk_level "$risk_level" "$domain")

        # 如果域名有警告且分类是 unknown，将其标记为 suspicious
        if [[ "$reputation" == "suspicious" && "$category" == "unknown" ]]; then
            category="suspicious"
        fi

        # 根据风险等级上色
        color=""
        case "$risk_level" in
            critical) color="$RED" ;;
            high)     color="$RED" ;;
            medium)   color="$YELLOW" ;;
            *)        color="$GREEN" ;;
        esac

        printf "  ${color}[%s]${RESET} ${BOLD}%s${RESET}  category=%s  reputation=%s  calls=%d\n" \
            "$risk_level" "$domain" "$category" "$reputation" "$count"
        printf "        %s\n" "$url"

        # 显示位置
        IFS=',' read -ra loc_arr <<< "$locations"
        loc_display=""
        for loc in "${loc_arr[@]}"; do
            if [[ -n "$loc_display" ]]; then
                loc_display="${loc_display}, ${loc}"
            else
                loc_display="${loc}"
            fi
        done
        printf "        %s\n" "$loc_display"

        # 显示上下文（仅在 --show-context 模式）
        if $SHOW_CONTEXT && [[ -s "$URL_CONTEXT" ]]; then
            ctx_line_match=$(grep -m1 "^$(echo "$url" | sed 's/[[\.*^$()+?{|]/\\&/g')	" "$URL_CONTEXT" 2>/dev/null || true)
            if [[ -n "$ctx_line_match" ]]; then
                b64_bef=$(echo "$ctx_line_match" | cut -f3)
                b64_aft=$(echo "$ctx_line_match" | cut -f4)

                if [[ -n "$b64_bef" ]]; then
                    decoded_bef=$(echo "$b64_bef" | base64 -d 2>/dev/null || echo "$b64_bef" | base64 -D 2>/dev/null || true)
                    if [[ -n "$decoded_bef" ]]; then
                        printf "        ${CYAN}--- 上文 ---${RESET}\n"
                        while IFS= read -r ctx_l; do
                            printf "        ${CYAN}| %s${RESET}\n" "$ctx_l"
                        done <<< "$decoded_bef"
                    fi
                fi

                if [[ -n "$b64_aft" ]]; then
                    decoded_aft=$(echo "$b64_aft" | base64 -d 2>/dev/null || echo "$b64_aft" | base64 -D 2>/dev/null || true)
                    if [[ -n "$decoded_aft" ]]; then
                        printf "        ${CYAN}--- 下文 ---${RESET}\n"
                        while IFS= read -r ctx_l; do
                            printf "        ${CYAN}| %s${RESET}\n" "$ctx_l"
                        done <<< "$decoded_aft"
                    fi
                fi
            fi
        fi

        # 显示域名警告
        if [[ -s "$DOMAIN_WARNINGS" ]]; then
            while IFS=$'\t' read -r w_domain w_flag w_sev w_desc; do
                if [[ "$w_domain" == "$domain" ]] || echo "$w_domain" | grep -q "^${domain}:"; then
                    printf "        ${YELLOW}⚠ %s${RESET}\n" "$w_desc"
                fi
            done < "$DOMAIN_WARNINGS"
        fi

        echo ""
    done < "$URL_DEDUP"

    echo "────────────────────────────────────────"
    if [[ $TOTAL_APIS -eq 0 ]]; then
        echo -e "${GREEN}未发现 URL/API 调用${RESET}"
    else
        echo -e "${CYAN}共发现 ${BOLD}${TOTAL_APIS}${RESET}${CYAN} 个唯一 API 端点${RESET}"

        # 统计域名警告数
        if [[ -s "$DOMAIN_WARNINGS" ]]; then
            warning_count=$(wc -l < "$DOMAIN_WARNINGS" | tr -d ' ')
            echo -e "${YELLOW}域名信誉警告: ${BOLD}${warning_count}${RESET}${YELLOW} 条${RESET}"
        fi
    fi
    echo ""
fi

exit $( [[ $TOTAL_APIS -eq 0 ]] && echo 0 || echo 1 )
