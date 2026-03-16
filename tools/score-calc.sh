#!/usr/bin/env bash
# CLS-Certify 综合评分工具
# 汇总所有检测工具的 JSON 输出，计算综合评分并生成最终等级
#
# 用法:
#   ./tools/score-calc.sh --input-dir /path/to/json-results/ [--json]
#   ./tools/score-calc.sh -f secret.json -f threat.json -f entropy.json [--json]
#   cat results/*.json | ./tools/score-calc.sh --stdin [--json]
#
# 示例:
#   ./tools/score-calc.sh --input-dir ./results/
#   ./tools/score-calc.sh -f secret.json -f threat.json --json
#   cat results/*.json | ./tools/score-calc.sh --stdin --json

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
USE_STDIN=false
INPUT_DIR=""
declare -a INPUT_FILES=()
INPUT_FILES_COUNT=0

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── 评分状态 ───
BASE_SCORE=100
TOTAL_DEDUCTION=0
FORCE_D=false
CAP_C=false
TRUST_LEVEL=""

# ─── 扣分/降级记录 ───
DEDUCTION_COUNT=0
FORCED_DOWNGRADE_COUNT=0
GRADE_CAP_COUNT=0
PROCESSED_FILES=""

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 综合评分工具"
    echo ""
    echo "用法: $0 [options]"
    echo ""
    echo "输入方式:"
    echo "  --input-dir <dir>      指定 JSON 结果目录"
    echo "  -f <file>              指定 JSON 文件（可多次使用）"
    echo "  --stdin                从 stdin 读取 JSON（多个 JSON 用换行分隔）"
    echo ""
    echo "选项:"
    echo "  --json                 输出 JSON 格式"
    echo "  -h, --help             显示帮助"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-dir) INPUT_DIR="$2"; shift 2 ;;
        -f) INPUT_FILES+=("$2"); INPUT_FILES_COUNT=$((INPUT_FILES_COUNT + 1)); shift 2 ;;
        --stdin) USE_STDIN=true; shift ;;
        --json) OUTPUT_JSON=true; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) echo "未知参数: $1"; usage ;;
    esac
done

# ─── 检测 jq 是否可用 ───
HAS_JQ=false
if command -v jq &>/dev/null; then
    HAS_JQ=true
fi

# ─── JSON 字段提取辅助函数 ───
# 当没有 jq 时使用 grep/sed 做基本解析
json_get_string() {
    local json="$1"
    local key="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$key // empty" 2>/dev/null
    else
        echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed "s/\"$key\"[[:space:]]*:[[:space:]]*\"//;s/\"$//"
    fi
}

json_get_number() {
    local json="$1"
    local key="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$key // 0" 2>/dev/null
    else
        echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*[0-9.-]*" | head -1 | sed "s/\"$key\"[[:space:]]*:[[:space:]]*//"
    fi
}

json_get_array() {
    local json="$1"
    local key="$2"
    if $HAS_JQ; then
        echo "$json" | jq -c ".$key // []" 2>/dev/null
    else
        # 简易提取：获取数组内容
        echo "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\[\(.*\)\].*/[\1]/p" | head -1
    fi
}

json_array_iterate() {
    local arr="$1"
    if $HAS_JQ; then
        echo "$arr" | jq -c '.[]' 2>/dev/null
    else
        # 简易分割：按大括号深度分割数组元素
        echo "$arr" | sed 's/^\[//;s/\]$//' | awk '{
            depth=0; buf=""; n=split($0,chars,"");
            for(i=1;i<=n;i++){
                c=chars[i];
                if(c=="{") depth++;
                if(c=="}" && depth>0) depth--;
                if(c=="," && depth==0){
                    print buf; buf="";
                } else {
                    buf=buf c;
                }
            }
            if(buf!="") print buf;
        }'
    fi
}

# ─── 扣分记录函数 ───
declare -a DEDUCTIONS_SOURCE=()
declare -a DEDUCTIONS_POINTS=()
declare -a DEDUCTIONS_REASON=()
declare -a DEDUCTIONS_DETAILS=()

add_deduction() {
    local source="$1"
    local points="$2"
    local reason="$3"
    local details="${4:-}"
    DEDUCTIONS_SOURCE+=("$source")
    DEDUCTIONS_POINTS+=("$points")
    DEDUCTIONS_REASON+=("$reason")
    DEDUCTIONS_DETAILS+=("$details")
    DEDUCTION_COUNT=$((DEDUCTION_COUNT + 1))
}

declare -a FORCED_DOWNGRADES=()
add_forced_downgrade() {
    FORCED_DOWNGRADES+=("$1")
    FORCED_DOWNGRADE_COUNT=$((FORCED_DOWNGRADE_COUNT + 1))
}

declare -a GRADE_CAPS=()
add_grade_cap() {
    GRADE_CAPS+=("$1")
    GRADE_CAP_COUNT=$((GRADE_CAP_COUNT + 1))
}

# ─── 处理 secret-scan JSON ───
process_secret_scan() {
    local json="$1"
    local findings
    findings=$(json_get_array "$json" "findings")
    local total_deduct=0
    local detail_items=""

    # 跟踪已扣分的 pattern_name（同类型最多扣一次）
    local seen_patterns=""
    local critical_count=0
    local high_count=0
    local medium_count=0
    local has_private_key=false

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local severity pattern_name
        severity=$(json_get_string "$item" "severity")
        pattern_name=$(json_get_string "$item" "pattern_name")

        # 检查是否已见过同类型
        if echo "$seen_patterns" | grep -qF "|${pattern_name}|"; then
            continue
        fi
        seen_patterns="${seen_patterns}|${pattern_name}|"

        local item_id
        item_id=$(json_get_string "$item" "id")
        local detail_entry="${item_id}: ${pattern_name}"
        if [[ -n "$detail_items" ]]; then
            detail_items="${detail_items};;${detail_entry}"
        else
            detail_items="${detail_entry}"
        fi

        case "$severity" in
            critical)
                total_deduct=$((total_deduct + 40))
                critical_count=$((critical_count + 1))
                # 检查是否为私钥泄露 → 强制 D 级
                if [[ "$pattern_name" == "private_key" ]]; then
                    has_private_key=true
                fi
                ;;
            high)
                total_deduct=$((total_deduct + 25))
                high_count=$((high_count + 1))
                ;;
            medium)
                total_deduct=$((total_deduct + 5))
                medium_count=$((medium_count + 1))
                ;;
        esac
    done < <(json_array_iterate "$findings")

    if [[ $total_deduct -gt 0 ]]; then
        local reason_parts=""
        [[ $critical_count -gt 0 ]] && reason_parts="发现 ${critical_count} 个 critical 级别密钥泄露"
        [[ $high_count -gt 0 ]] && {
            [[ -n "$reason_parts" ]] && reason_parts="${reason_parts}，"
            reason_parts="${reason_parts}发现 ${high_count} 个 high 级别密钥泄露"
        }
        [[ $medium_count -gt 0 ]] && {
            [[ -n "$reason_parts" ]] && reason_parts="${reason_parts}，"
            reason_parts="${reason_parts}发现 ${medium_count} 个 medium 级别敏感信息"
        }
        add_deduction "secret-scan" "-${total_deduct}" "$reason_parts" "$detail_items"
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + total_deduct))
    else
        add_deduction "secret-scan" "0" "未发现敏感信息" ""
    fi

    # 强制 D 级：critical 级别的私钥泄露
    if $has_private_key; then
        FORCE_D=true
        add_forced_downgrade "secret-scan: 发现 critical 级别的私钥泄露"
    fi
}

# ─── 处理 threat-scan JSON ───
process_threat_scan() {
    local json="$1"
    local findings
    findings=$(json_get_array "$json" "findings")
    local total_deduct=0
    local detail_items=""
    local finding_count=0

    # 跟踪各类别
    local exfiltration_count=0

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local severity category pattern_id item_id
        severity=$(json_get_string "$item" "severity")
        category=$(json_get_string "$item" "category")
        pattern_id=$(json_get_string "$item" "pattern_id")
        item_id=$(json_get_string "$item" "id")

        local detail_entry="${item_id}: ${category}(${severity})"
        if [[ -n "$detail_items" ]]; then
            detail_items="${detail_items};;${detail_entry}"
        else
            detail_items="${detail_entry}"
        fi

        finding_count=$((finding_count + 1))

        case "$category" in
            code_execution)
                if [[ "$severity" == "critical" ]]; then
                    total_deduct=$((total_deduct + 40))
                    FORCE_D=true
                    add_forced_downgrade "threat-scan: code_execution(critical)"
                fi
                ;;
            injection)
                if [[ "$severity" == "critical" ]]; then
                    total_deduct=$((total_deduct + 40))
                    FORCE_D=true
                    add_forced_downgrade "threat-scan: injection(critical)"
                fi
                ;;
            prompt_poison)
                if [[ "$severity" == "critical" ]]; then
                    total_deduct=$((total_deduct + 40))
                    FORCE_D=true
                    add_forced_downgrade "threat-scan: prompt_poison(critical)"
                fi
                ;;
            privilege_escalation)
                if [[ "$severity" == "critical" ]]; then
                    total_deduct=$((total_deduct + 40))
                    FORCE_D=true
                    add_forced_downgrade "threat-scan: privilege_escalation(critical)"
                fi
                ;;
            ai_safety)
                total_deduct=$((total_deduct + 20))
                ;;
            exfiltration)
                total_deduct=$((total_deduct + 35))
                exfiltration_count=$((exfiltration_count + 1))
                ;;
            dynamic_download)
                # 检查 pattern_id 中是否包含 L2/L3 或 L1
                if echo "$pattern_id" | grep -qE "L[23]"; then
                    total_deduct=$((total_deduct + 40))
                    FORCE_D=true
                    add_forced_downgrade "threat-scan: dynamic_download(L2+)"
                elif echo "$pattern_id" | grep -qE "L1"; then
                    total_deduct=$((total_deduct + 20))
                fi
                ;;
            conditional_trigger)
                total_deduct=$((total_deduct + 30))
                CAP_C=true
                add_grade_cap "threat-scan: conditional_trigger 触发最高 C 级"
                ;;
        esac
    done < <(json_array_iterate "$findings")

    # exfiltration 批量触发 C 级上限
    if [[ $exfiltration_count -ge 2 ]]; then
        CAP_C=true
        add_grade_cap "threat-scan: exfiltration 批量发现（${exfiltration_count} 个），最高 C 级"
    fi

    if [[ $total_deduct -gt 0 ]]; then
        add_deduction "threat-scan" "-${total_deduct}" "发现 ${finding_count} 个安全威胁" "$detail_items"
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + total_deduct))
    else
        add_deduction "threat-scan" "0" "未发现安全威胁" ""
    fi
}

# ─── 处理 entropy-detect JSON ───
process_entropy_detect() {
    local json="$1"
    local findings
    findings=$(json_get_array "$json" "findings")
    local total_deduct=0
    local cap=30
    local detail_items=""
    local finding_count=0

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local severity item_id
        severity=$(json_get_string "$item" "severity")
        item_id=$(json_get_string "$item" "id")

        local detail_entry="${item_id}: ${severity}"
        if [[ -n "$detail_items" ]]; then
            detail_items="${detail_items};;${detail_entry}"
        else
            detail_items="${detail_entry}"
        fi

        finding_count=$((finding_count + 1))

        case "$severity" in
            critical) total_deduct=$((total_deduct + 20)) ;;
            high)     total_deduct=$((total_deduct + 15)) ;;
            medium)   total_deduct=$((total_deduct + 10)) ;;
        esac
    done < <(json_array_iterate "$findings")

    # 最多累计扣 30
    if [[ $total_deduct -gt $cap ]]; then
        total_deduct=$cap
    fi

    if [[ $total_deduct -gt 0 ]]; then
        add_deduction "entropy-detect" "-${total_deduct}" "发现 ${finding_count} 个高熵字符串（代码混淆嫌疑）" "$detail_items"
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + total_deduct))
    else
        add_deduction "entropy-detect" "0" "未发现异常" ""
    fi
}

# ─── 处理 url-audit JSON ───
process_url_audit() {
    local json="$1"
    local total_deduct=0
    local cap=30
    local detail_items=""
    local has_critical_domain=false

    # 处理 domain_warnings
    local domain_warnings
    domain_warnings=$(json_get_array "$json" "domain_warnings")

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local flag domain severity
        flag=$(json_get_string "$item" "flag")
        domain=$(json_get_string "$item" "domain")
        severity=$(json_get_string "$item" "severity")

        local detail_entry="域名 ${domain}: ${flag}"
        if [[ -n "$detail_items" ]]; then
            detail_items="${detail_items};;${detail_entry}"
        else
            detail_items="${detail_entry}"
        fi

        case "$flag" in
            short_link)     total_deduct=$((total_deduct + 15)) ;;
            ip_address)     total_deduct=$((total_deduct + 15)) ;;
            suspicious_tld) total_deduct=$((total_deduct + 10)) ;;
            dynamic_dns)    total_deduct=$((total_deduct + 15)) ;;
        esac

        if [[ "$severity" == "critical" ]]; then
            has_critical_domain=true
        fi
    done < <(json_array_iterate "$domain_warnings")

    # 处理 apis
    local apis
    apis=$(json_get_array "$json" "apis")

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local api_category endpoint
        api_category=$(json_get_string "$item" "category")
        endpoint=$(json_get_string "$item" "endpoint")

        case "$api_category" in
            suspicious)
                total_deduct=$((total_deduct + 20))
                local detail_entry="可疑 API: ${endpoint}"
                if [[ -n "$detail_items" ]]; then
                    detail_items="${detail_items};;${detail_entry}"
                else
                    detail_items="${detail_entry}"
                fi
                ;;
            advertising)
                total_deduct=$((total_deduct + 10))
                local detail_entry="广告 API: ${endpoint}"
                if [[ -n "$detail_items" ]]; then
                    detail_items="${detail_items};;${detail_entry}"
                else
                    detail_items="${detail_entry}"
                fi
                ;;
        esac
    done < <(json_array_iterate "$apis")

    # 最多累计扣 30
    if [[ $total_deduct -gt $cap ]]; then
        total_deduct=$cap
    fi

    # critical 级别可疑域名 → 最高 C 级
    if $has_critical_domain; then
        CAP_C=true
        add_grade_cap "url-audit: 存在 critical 级别的可疑域名"
    fi

    if [[ $total_deduct -gt 0 ]]; then
        add_deduction "url-audit" "-${total_deduct}" "发现可疑域名/API" "$detail_items"
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + total_deduct))
    else
        add_deduction "url-audit" "0" "未发现可疑域名或 API" ""
    fi
}

# ─── 处理 dep-audit JSON ───
process_dep_audit() {
    local json="$1"
    local findings
    findings=$(json_get_array "$json" "findings")
    local total_deduct=0
    local detail_items=""
    local has_typosquat_d1=false

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local category distance item_id pkg
        category=$(json_get_string "$item" "category")
        distance=$(json_get_number "$item" "distance")
        item_id=$(json_get_string "$item" "id")
        pkg=$(json_get_string "$item" "package")

        local detail_entry="${item_id}: ${pkg}(${category})"
        if [[ -n "$detail_items" ]]; then
            detail_items="${detail_items};;${detail_entry}"
        else
            detail_items="${detail_entry}"
        fi

        case "$category" in
            typosquatting)
                if [[ "$distance" == "1" ]]; then
                    total_deduct=$((total_deduct + 30))
                    has_typosquat_d1=true
                elif [[ "$distance" == "2" ]]; then
                    total_deduct=$((total_deduct + 15))
                fi
                ;;
            suspicious-keyword|suspicious_name)
                total_deduct=$((total_deduct + 10))
                ;;
        esac
    done < <(json_array_iterate "$findings")

    # typosquatting distance=1 → 最高 C 级
    if $has_typosquat_d1; then
        CAP_C=true
        add_grade_cap "dep-audit: typosquatting distance=1，恶意包嫌疑"
    fi

    if [[ $total_deduct -gt 0 ]]; then
        add_deduction "dep-audit" "-${total_deduct}" "发现可疑依赖" "$detail_items"
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + total_deduct))
    else
        add_deduction "dep-audit" "0" "依赖正常" ""
    fi
}

# ─── 处理 github-repo-check JSON ───
process_github_repo_check() {
    local json="$1"
    local trust
    trust=$(json_get_string "$json" "trust_level")
    local score
    score=$(json_get_number "$json" "score")
    local deduct=0
    local bonus=0
    local reason=""

    TRUST_LEVEL="$trust"

    case "$trust" in
        T1)
            bonus=5
            reason="来源 T1，加 5 分"
            ;;
        T2)
            bonus=0
            reason="来源 T2"
            ;;
        T3)
            # score<40 → -15
            local is_low
            is_low=$(awk -v s="$score" 'BEGIN { print (s < 40) ? 1 : 0 }')
            if [[ "$is_low" -eq 1 ]]; then
                deduct=15
                reason="来源 T3，仓库评分 ${score} < 40，扣 15 分"
            else
                reason="来源 T3，仓库评分 ${score}"
            fi
            ;;
        *)
            reason="来源未知"
            ;;
    esac

    if [[ $bonus -gt 0 ]]; then
        add_deduction "github-check" "+${bonus}" "$reason" ""
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION - bonus))
    elif [[ $deduct -gt 0 ]]; then
        add_deduction "github-check" "-${deduct}" "$reason" ""
        TOTAL_DEDUCTION=$((TOTAL_DEDUCTION + deduct))
    else
        add_deduction "github-check" "0" "$reason" ""
    fi
}

# ─── 路由到对应处理器 ───
process_json() {
    local json="$1"
    local tool
    tool=$(json_get_string "$json" "tool")

    case "$tool" in
        cls-secret-scan)        process_secret_scan "$json" ;;
        cls-threat-scan)        process_threat_scan "$json" ;;
        cls-entropy-detect)     process_entropy_detect "$json" ;;
        cls-url-audit)          process_url_audit "$json" ;;
        cls-dep-audit)          process_dep_audit "$json" ;;
        cls-github-repo-check)  process_github_repo_check "$json" ;;
        *)
            # 未知工具，跳过
            return 0
            ;;
    esac
}

# ─── 收集输入文件 ───
collect_input_files() {
    local result=""

    if [[ -n "$INPUT_DIR" ]]; then
        if [[ ! -d "$INPUT_DIR" ]]; then
            echo "错误: 目录 $INPUT_DIR 不存在" >&2
            exit 1
        fi
        while IFS= read -r f; do
            [[ -z "$f" ]] && continue
            if [[ -n "$result" ]]; then
                result="${result}"$'\n'"${f}"
            else
                result="${f}"
            fi
        done < <(find "$INPUT_DIR" -maxdepth 1 -name "*.json" -type f 2>/dev/null | sort)
    fi

    if [[ $INPUT_FILES_COUNT -gt 0 ]]; then
        for f in "${INPUT_FILES[@]}"; do
            if [[ ! -f "$f" ]]; then
                echo "错误: 文件 $f 不存在" >&2
                exit 1
            fi
            if [[ -n "$result" ]]; then
                result="${result}"$'\n'"${f}"
            else
                result="${f}"
            fi
        done
    fi

    echo "$result"
}

# ─── 主流程 ───

# 验证至少有一种输入方式
if [[ -z "$INPUT_DIR" && $INPUT_FILES_COUNT -eq 0 && "$USE_STDIN" != "true" ]]; then
    echo "错误: 请指定输入方式（--input-dir / -f / --stdin）"
    usage
fi

# 从文件读取或从 stdin 读取
if $USE_STDIN; then
    # 从 stdin 读取，每行一个 JSON
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # 跳过非 JSON 行
        [[ "$line" != "{"* ]] && continue
        process_json "$line"
        if [[ -n "$PROCESSED_FILES" ]]; then
            PROCESSED_FILES="${PROCESSED_FILES},(stdin)"
        else
            PROCESSED_FILES="(stdin)"
        fi
    done
else
    # 收集文件列表
    file_list=$(collect_input_files)
    if [[ -z "$file_list" ]]; then
        echo "错误: 未找到任何 JSON 文件"
        exit 1
    fi

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        json_content=$(cat "$file")
        [[ -z "$json_content" ]] && continue
        process_json "$json_content"
        local_basename=$(basename "$file")
        if [[ -n "$PROCESSED_FILES" ]]; then
            PROCESSED_FILES="${PROCESSED_FILES},${local_basename}"
        else
            PROCESSED_FILES="${local_basename}"
        fi
    done <<< "$file_list"
fi

# ─── 计算最终分数 ───
FINAL_SCORE=$((BASE_SCORE - TOTAL_DEDUCTION))

# 分数下限为 0，上限为 100
if [[ $FINAL_SCORE -lt 0 ]]; then
    FINAL_SCORE=0
fi
if [[ $FINAL_SCORE -gt 100 ]]; then
    FINAL_SCORE=100
fi

# ─── 判定等级 ───
determine_grade() {
    local score=$1

    # 强制 D 级
    if $FORCE_D; then
        echo "D"
        return
    fi

    # 最高 C 级触发 且 总分 > 49
    if $CAP_C && [[ $score -gt 49 ]]; then
        echo "C"
        return
    fi

    if [[ $score -ge 90 ]]; then
        echo "S"
    elif [[ $score -ge 80 ]]; then
        # S 级需 T1/T2 来源，否则降为 A
        if [[ "$TRUST_LEVEL" == "T1" || "$TRUST_LEVEL" == "T2" ]]; then
            echo "S"
        else
            echo "A"
        fi
    elif [[ $score -ge 65 ]]; then
        echo "A"
    elif [[ $score -ge 50 ]]; then
        echo "B"
    elif [[ $score -ge 30 ]]; then
        echo "C"
    else
        echo "D"
    fi
}

GRADE=$(determine_grade $FINAL_SCORE)

# ─── 评价文案 ───
get_evaluation() {
    case "$1" in
        S) echo "优秀安全级别，满足所有安全要求" ;;
        A) echo "标准安全级别，可放心使用" ;;
        B) echo "基础安全级别，存在改进空间" ;;
        C) echo "警示级别，存在安全风险，请谨慎使用" ;;
        D) echo "危险级别，不建议使用" ;;
        *) echo "未知" ;;
    esac
}

EVALUATION=$(get_evaluation "$GRADE")

# stamp_color
get_stamp_color() {
    case "$1" in
        S|A|B) echo "green" ;;
        C|D)   echo "red" ;;
        *)     echo "green" ;;
    esac
}

STAMP_COLOR=$(get_stamp_color "$GRADE")

# S+ 标记（总分 >= 90 且无降级，脚本标记为 S）
GRADE_DISPLAY="$GRADE"
if [[ "$GRADE" == "S" && $FINAL_SCORE -ge 90 ]]; then
    EVALUATION="顶级安全，已通过人工验证"
    GRADE_DISPLAY="S（满足 S+ 条件，需人工验证）"
fi

# ─── 输出 ───
if $OUTPUT_JSON; then
    # 构建 deductions JSON 数组
    DEDUCTIONS_JSON=""
    for ((i = 0; i < DEDUCTION_COUNT; i++)); do
        d_source="${DEDUCTIONS_SOURCE[$i]}"
        d_points="${DEDUCTIONS_POINTS[$i]}"
        d_reason="${DEDUCTIONS_REASON[$i]}"
        d_details="${DEDUCTIONS_DETAILS[$i]}"

        # 转义 JSON 特殊字符
        d_reason=$(echo "$d_reason" | sed 's/"/\\"/g')

        # 构建 details 数组
        details_json="[]"
        if [[ -n "$d_details" ]]; then
            details_json="["
            first=true
            # 用 ;; 作为分隔符
            old_ifs="$IFS"
            IFS=$'\n'
            for d in $(echo "$d_details" | sed 's/;;/\n/g'); do
                [[ -z "$d" ]] && continue
                d=$(echo "$d" | sed 's/"/\\"/g')
                if $first; then
                    details_json="${details_json}\"${d}\""
                    first=false
                else
                    details_json="${details_json},\"${d}\""
                fi
            done
            IFS="$old_ifs"
            details_json="${details_json}]"
        fi

        # 解析 points 为数字
        d_points_num="$d_points"
        if [[ "$d_points" == "+"* ]]; then
            d_points_num="${d_points#+}"
        fi

        entry=$(printf '{"source":"%s","points":%s,"reason":"%s","details":%s}' \
            "$d_source" "$d_points_num" "$d_reason" "$details_json")

        if [[ -n "$DEDUCTIONS_JSON" ]]; then
            DEDUCTIONS_JSON="${DEDUCTIONS_JSON},${entry}"
        else
            DEDUCTIONS_JSON="${entry}"
        fi
    done

    # 构建 forced_downgrades JSON 数组
    DOWNGRADES_JSON=""
    for ((i = 0; i < FORCED_DOWNGRADE_COUNT; i++)); do
        dg_item="${FORCED_DOWNGRADES[$i]}"
        dg_item=$(echo "$dg_item" | sed 's/"/\\"/g')
        if [[ -n "$DOWNGRADES_JSON" ]]; then
            DOWNGRADES_JSON="${DOWNGRADES_JSON},\"${dg_item}\""
        else
            DOWNGRADES_JSON="\"${dg_item}\""
        fi
    done

    # 构建 grade_caps JSON 数组
    CAPS_JSON=""
    for ((i = 0; i < GRADE_CAP_COUNT; i++)); do
        gc_item="${GRADE_CAPS[$i]}"
        gc_item=$(echo "$gc_item" | sed 's/"/\\"/g')
        if [[ -n "$CAPS_JSON" ]]; then
            CAPS_JSON="${CAPS_JSON},\"${gc_item}\""
        else
            CAPS_JSON="\"${gc_item}\""
        fi
    done

    # 构建 input_files JSON 数组
    FILES_JSON=""
    old_ifs="$IFS"
    IFS=','
    for f in $PROCESSED_FILES; do
        [[ -z "$f" ]] && continue
        if [[ -n "$FILES_JSON" ]]; then
            FILES_JSON="${FILES_JSON},\"${f}\""
        else
            FILES_JSON="\"${f}\""
        fi
    done
    IFS="$old_ifs"

    # trust_level 可能为空
    trust_out="${TRUST_LEVEL:-unknown}"
    output_eval=$(echo "$EVALUATION" | sed 's/"/\\"/g')

    printf '{"tool":"cls-score-calc","grade":"%s","score":%d,"max_score":100,"evaluation":"%s","stamp_color":"%s","trust_level":"%s","deductions":[%s],"forced_downgrades":[%s],"grade_caps":[%s],"input_files":[%s]}\n' \
        "$GRADE" "$FINAL_SCORE" "$output_eval" "$STAMP_COLOR" "$trust_out" \
        "$DEDUCTIONS_JSON" "$DOWNGRADES_JSON" "$CAPS_JSON" "$FILES_JSON"
else
    # CLI 输出
    echo ""
    echo -e "${BOLD}CLS-Certify 综合评分${RESET}"
    echo "════════════════════════════════════════"
    echo ""

    # 根据等级选择颜色
    GRADE_COLOR="$GREEN"
    case "$GRADE" in
        C) GRADE_COLOR="$YELLOW" ;;
        D) GRADE_COLOR="$RED" ;;
    esac

    echo -e "  评级: ${GRADE_COLOR}${BOLD}${GRADE_DISPLAY}${RESET}"
    echo -e "  评分: ${BOLD}${FINAL_SCORE}${RESET} / 100"
    echo -e "  评价: ${EVALUATION}"
    echo ""
    echo "════════════════════════════════════════"
    echo "扣分明细:"

    for ((i = 0; i < DEDUCTION_COUNT; i++)); do
        d_source="${DEDUCTIONS_SOURCE[$i]}"
        d_points="${DEDUCTIONS_POINTS[$i]}"
        d_reason="${DEDUCTIONS_REASON[$i]}"

        # 格式化对齐
        printf "  ${CYAN}[%-15s]${RESET} %+4s  %s\n" "$d_source" "$d_points" "$d_reason"
    done

    echo ""
    echo "降级检查:"

    if $FORCE_D; then
        for ((i = 0; i < FORCED_DOWNGRADE_COUNT; i++)); do
            echo -e "  ${RED}✗ D 级强制触发: ${FORCED_DOWNGRADES[$i]}${RESET}"
        done
    else
        echo -e "  ${GREEN}✓ 无 D 级强制触发${RESET}"
    fi

    if $CAP_C; then
        for ((i = 0; i < GRADE_CAP_COUNT; i++)); do
            echo -e "  ${YELLOW}✗ C 级上限触发: ${GRADE_CAPS[$i]}${RESET}"
        done
    else
        echo -e "  ${GREEN}✓ 无 C 级上限触发${RESET}"
    fi

    echo "────────────────────────────────────────"
    echo ""
fi

exit 0
