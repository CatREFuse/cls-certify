#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# CLS-Certify Report Renderer
# 将符合 report-data-protocol.md 协议的 Markdown 报告渲染为 HTML/PDF
#
# 用法: bash render.sh <report.md> [output.html] [--pdf]
#   report.md   - 符合数据协议的 Markdown 报告文件
#   output.html - 输出路径（默认: 同目录同名 .html）
#   --pdf       - 同时生成 PDF 版本（需要 Google Chrome）
# ─────────────────────────────────────────────────────────────
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$SCRIPT_DIR/templates/report-template.html"
GENERATE_PDF=0

# 解析参数
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --pdf) GENERATE_PDF=1 ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
  echo "用法: bash render.sh <report.md> [output.html] [--pdf]"
  exit 1
fi

INPUT="${POSITIONAL[0]}"
OUTPUT="${POSITIONAL[1]:-${INPUT%.md}.html}"

if [[ ! -f "$INPUT" ]]; then
  echo "错误: 找不到报告文件 $INPUT" >&2; exit 1
fi
if [[ ! -f "$TEMPLATE" ]]; then
  echo "错误: 找不到模板文件 $TEMPLATE" >&2; exit 1
fi

# ─── 提取 frontmatter 和 body ───
FRONTMATTER=$(awk '/^---$/{n++; next} n==1{print}' "$INPUT")
BODY=$(awk '/^---$/{n++; next} n>=2{print}' "$INPUT")

# ─── 从 frontmatter 提取标量字段 ───
get_field() {
  echo "$FRONTMATTER" | grep -E "^${1}:" | head -1 | sed -E "s/^${1}:[[:space:]]*//" | sed 's/^"//;s/"$//'
}

REPORT_ID=$(get_field "report_id")
REPORT_DATE=$(get_field "report_date")
SCANNER_VERSION=$(get_field "scanner_version")
SCAN_MODE=$(get_field "scan_mode")
SKILL_NAME=$(get_field "skill_name")
SKILL_VERSION=$(get_field "skill_version")
SKILL_PATH=$(get_field "skill_path")
MAINTAINER=$(get_field "maintainer")
LICENSE=$(get_field "license")
TRUST_LEVEL=$(get_field "trust_level")
TRUST_LEVEL_TEXT=$(get_field "trust_level_text")
SCAN_DURATION=$(get_field "scan_duration")
CODE_STATS=$(get_field "code_stats")
GRADE=$(get_field "grade")
SCORE=$(get_field "score")
EVALUATION=$(get_field "evaluation")
STAMP_COLOR=$(get_field "stamp_color")
TOTAL_FINDINGS=$(get_field "total_findings")
SAMPLE_HASH=$(get_field "sample_hash")
DISCLAIMER=$(get_field "disclaimer")

# ─── 派生值 ───
if [[ "$STAMP_COLOR" == "red" ]]; then
  STAMP_SVG_COLOR="#B22222"
  RADAR_FILL="rgba(192,57,43,0.12)"
  RADAR_STROKE="var(--red)"
else
  STAMP_SVG_COLOR="#1B7A3D"
  RADAR_FILL="rgba(45,95,138,0.12)"
  RADAR_STROKE="var(--accent)"
fi

# trust_level tag
if [[ "$TRUST_LEVEL" == "T3" ]]; then
  TRUST_TAG="<span class=\"tag\" style=\"background:var(--red-bg);color:var(--red);border:1px solid rgba(192,57,43,0.2);\">${TRUST_LEVEL} · ${TRUST_LEVEL_TEXT}</span>"
else
  TRUST_TAG="<span class=\"tag tag-t2\">${TRUST_LEVEL} · ${TRUST_LEVEL_TEXT}</span>"
fi

# license tag
if [[ -z "$LICENSE" || "$LICENSE" == "无许可证" || "$LICENSE" == "none" ]]; then
  LICENSE_TAG="<span class=\"tag\" style=\"background:var(--red-bg);color:var(--red);border:1px solid rgba(192,57,43,0.2);\">无许可证</span>"
else
  LICENSE_TAG="<span class=\"tag tag-mit\">${LICENSE}</span>"
fi

# recommendations title
case "$GRADE" in
  C|D) REC_TITLE="紧急处置建议" ;;
  *)   REC_TITLE="提升建议" ;;
esac

# ─── 解析 radar（6 维度） ───
RADAR_NAMES=()
RADAR_SHORTS=()
RADAR_SCORES=()
RADAR_STATUSES=()
RADAR_DETAILS=()

current_idx=-1
while IFS= read -r line; do
  if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*name: ]]; then
    current_idx=$((current_idx + 1))
    RADAR_NAMES+=("$(echo "$line" | sed -E 's/.*name:[[:space:]]*//' | sed 's/^"//;s/"$//')")
  elif [[ "$line" =~ ^[[:space:]]*short: ]]; then
    RADAR_SHORTS+=("$(echo "$line" | sed -E 's/.*short:[[:space:]]*//' | sed 's/^"//;s/"$//')")
  elif [[ "$line" =~ ^[[:space:]]*score: ]]; then
    RADAR_SCORES+=("$(echo "$line" | sed -E 's/.*score:[[:space:]]*//')")
  elif [[ "$line" =~ ^[[:space:]]*status: ]]; then
    RADAR_STATUSES+=("$(echo "$line" | sed -E 's/.*status:[[:space:]]*//' | sed 's/^"//;s/"$//')")
  elif [[ "$line" =~ ^[[:space:]]*detail: ]]; then
    RADAR_DETAILS+=("$(echo "$line" | sed -E 's/.*detail:[[:space:]]*//' | sed 's/^"//;s/"$//')")
  fi
done <<< "$(echo "$FRONTMATTER" | awk '/^radar:/{found=1; next} found && /^[a-zA-Z]/{exit} found{print}')"

# ─── 计算雷达图 SVG 坐标 ───
# 中心 (150,150)，最大半径 110
# 6 轴角度: -90°, -30°, 30°, 90°, 150°, 210°
COS_VALS=(0 0.866 0.866 0 -0.866 -0.866)
SIN_VALS=(-1 -0.5 0.5 1 0.5 -0.5)

POLYGON_POINTS=""
DOTS_HTML=""

for i in 0 1 2 3 4 5; do
  s=${RADAR_SCORES[$i]}
  r=$(echo "$s * 1.1" | bc)
  x=$(printf "%.1f" "$(echo "150 + $r * ${COS_VALS[$i]}" | bc)")
  y=$(printf "%.1f" "$(echo "150 + $r * ${SIN_VALS[$i]}" | bc)")
  if [[ $i -gt 0 ]]; then POLYGON_POINTS+=" "; fi
  POLYGON_POINTS+="${x},${y}"
  DOTS_HTML+="<circle cx=\"${x}\" cy=\"${y}\" r=\"3.5\" fill=\"${RADAR_STROKE}\"/>"
done

# ─── 生成 radar legend HTML ───
LEGEND_HTML=""
for i in 0 1 2 3 4 5; do
  name="${RADAR_NAMES[$i]}"
  score="${RADAR_SCORES[$i]}"
  status="${RADAR_STATUSES[$i]}"
  case "$status" in
    pass) dot_color="var(--green)"; score_color="var(--green)"; badge_class="pass"; badge_text="✓ 通过" ;;
    warn) dot_color="var(--yellow)"; score_color="var(--yellow)"; badge_class="warn"; badge_text="⚠ 警告" ;;
    fail) dot_color="var(--red)"; score_color="var(--red)"; badge_class="fail"; badge_text="❌ 危险" ;;
  esac
  LEGEND_HTML+="<div class=\"legend-item\">"
  LEGEND_HTML+="<span class=\"legend-dot\" style=\"background:${dot_color};\"></span>"
  LEGEND_HTML+="<span class=\"legend-name\">${name}</span>"
  LEGEND_HTML+="<span class=\"legend-score\" style=\"color:${score_color};\">${score}</span>"
  LEGEND_HTML+="<span class=\"legend-status ${badge_class}\">${badge_text}</span>"
  LEGEND_HTML+="</div>"
done
# legend-keys 已在模板中硬编码，此处不重复生成

# ─── 解析 compliance ───
COMPLIANCE_HTML=""
while IFS= read -r line; do
  if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*text: ]]; then
    c_text=$(echo "$line" | sed -E 's/.*text:[[:space:]]*//' | sed 's/^"//;s/"$//')
  elif [[ "$line" =~ ^[[:space:]]*status: ]]; then
    c_status=$(echo "$line" | sed -E 's/.*status:[[:space:]]*//' | sed 's/^"//;s/"$//')
    case "$c_status" in
      pass) c_icon="✓" ;;
      warn) c_icon="!" ;;
      fail) c_icon="✗" ;;
    esac
    COMPLIANCE_HTML+="<div class=\"compliance-item\"><span class=\"compliance-icon ${c_status}\">${c_icon}</span><span class=\"compliance-text\">${c_text}</span></div>"
  fi
done <<< "$(echo "$FRONTMATTER" | awk '/^compliance:/{found=1; next} found && /^[a-zA-Z]/{exit} found{print}')"

# ─── 解析 body: pattern_tags ───
TAGS_SECTION=$(echo "$BODY" | awk '/^## pattern_tags/{f=1; next} /^## [a-z]/{if(f) exit} f{print}' | grep -E '^- ' || true)
TAGS_HTML=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  severity=$(echo "$line" | sed -E 's/^- ([a-z]+):.*/\1/')
  text=$(echo "$line" | sed -E 's/^- [a-z]+:[[:space:]]*//')
  TAGS_HTML+="<span class=\"pattern-tag ${severity}\">${text}</span>"
done <<< "$TAGS_SECTION"

# ─── 解析 body: summary ───
SUMMARY_SECTION=$(echo "$BODY" | awk '/^## summary/{f=1; next} /^## [a-z]/{if(f) exit} f{print}' | grep -E '^[0-9]+\.' || true)
SUMMARY_HTML=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  text=$(echo "$line" | sed -E 's/^[0-9]+\.[[:space:]]*//')
  SUMMARY_HTML+="<li>${text}</li>"
done <<< "$SUMMARY_SECTION"

# ─── 解析 body: external_apis ───
API_SECTION=$(echo "$BODY" | awk '/^## external_apis/{f=1; next} /^## [a-z]/{if(f) exit} f{print}' | grep -E '^\|[^-]' | tail -n +2 || true)
APIS_HTML=""
API_COUNT=0
while IFS='|' read -r _ endpoint method reputation encryption data_types provider _; do
  [[ -z "$endpoint" ]] && continue
  endpoint=$(echo "$endpoint" | xargs)
  method=$(echo "$method" | xargs)
  reputation=$(echo "$reputation" | xargs)
  encryption=$(echo "$encryption" | xargs)
  data_types=$(echo "$data_types" | xargs)
  provider=$(echo "$provider" | xargs)

  # 行样式
  row_style=""
  [[ "$reputation" == "unknown" || "$reputation" == "suspicious" || "$reputation" == "malicious" ]] && row_style=" style=\"background:rgba(192,57,43,0.03);\""

  # endpoint 样式
  ep_style=""
  [[ "$reputation" == "suspicious" || "$reputation" == "malicious" ]] && ep_style=" style=\"color:var(--red);\""

  # method badge
  method_lower=$(echo "$method" | tr '[:upper:]' '[:lower:]')
  method_class="post"
  [[ "$method_lower" == "get" ]] && method_class="get"

  # reputation dot
  rep_class="trusted"
  rep_text="可信"
  case "$reputation" in
    unknown) rep_class="unknown"; rep_text="未知" ;;
    suspicious) rep_class="suspicious"; rep_text="可疑" ;;
    malicious) rep_class="suspicious"; rep_text="恶意" ;;
  esac

  # encryption badge
  enc_class="https"
  [[ "$encryption" == "HTTP" || "$encryption" == "无加密" ]] && enc_class="http"

  # data_types 样式
  dt_style=""
  [[ "$reputation" == "suspicious" || "$reputation" == "malicious" ]] && dt_style=" style=\"font-size:11px;color:var(--red);\""
  [[ -z "$dt_style" ]] && dt_style=" style=\"font-size:11px;\""

  APIS_HTML+="<tr${row_style}>"
  APIS_HTML+="<td class=\"endpoint\"${ep_style}>${endpoint}</td>"
  APIS_HTML+="<td><span class=\"method-badge ${method_class}\">${method}</span></td>"
  APIS_HTML+="<td><span class=\"reputation-dot ${rep_class}\">${rep_text}</span></td>"
  APIS_HTML+="<td><span class=\"encryption-badge ${enc_class}\">${encryption}</span></td>"
  APIS_HTML+="<td${dt_style}>${data_types}</td>"
  APIS_HTML+="<td style=\"font-size:12px;\">${provider}</td>"
  APIS_HTML+="</tr>"
  API_COUNT=$((API_COUNT + 1))
done <<< "$API_SECTION"

# ─── 解析 body: findings ───
FINDINGS_HTML=""
FINDINGS_COUNT=0

# 逐块解析 ### RISK-xxx
current_risk=""
f_severity="" f_category="" f_title="" f_location="" f_function="" f_description="" f_evidence="" f_recommendation=""
in_evidence=0

flush_finding() {
  [[ -z "$f_title" ]] && return
  FINDINGS_COUNT=$((FINDINGS_COUNT + 1))

  # severity 样式映射
  case "$f_severity" in
    critical) sev_upper="Critical" ;;
    high) sev_upper="High" ;;
    medium) sev_upper="Medium" ;;
    low) sev_upper="Low" ;;
    *) sev_upper="Info" ;;
  esac

  FINDINGS_HTML+="<div class=\"finding\">"
  FINDINGS_HTML+="<div class=\"finding-header\">"
  FINDINGS_HTML+="<span class=\"severity-dot ${f_severity}\"></span>"
  FINDINGS_HTML+="<span class=\"finding-id\">${current_risk}</span>"
  FINDINGS_HTML+="<span class=\"finding-title\">${f_title}</span>"
  FINDINGS_HTML+="<span class=\"severity-badge ${f_severity}\">${sev_upper}</span>"
  FINDINGS_HTML+="</div>"
  FINDINGS_HTML+="<div class=\"finding-body\">"

  # meta
  FINDINGS_HTML+="<div class=\"finding-meta\">"
  [[ -n "$f_category" ]] && FINDINGS_HTML+="<span class=\"finding-meta-item\"><strong>类别</strong> ${f_category}</span>"
  [[ -n "$f_location" ]] && FINDINGS_HTML+="<span class=\"finding-meta-item\"><strong>位置</strong> ${f_location}</span>"
  [[ -n "$f_function" ]] && FINDINGS_HTML+="<span class=\"finding-meta-item\"><strong>函数</strong> ${f_function}</span>"
  FINDINGS_HTML+="</div>"

  # description
  [[ -n "$f_description" ]] && FINDINGS_HTML+="<p class=\"finding-desc\">${f_description}</p>"

  # evidence (code block)
  if [[ -n "$f_evidence" ]]; then
    FINDINGS_HTML+="<div class=\"code-evidence\">"
    while IFS= read -r eline; do
      [[ "$eline" =~ ^\`\`\` ]] && continue
      [[ -z "$eline" ]] && continue
      # 检测高亮行
      if [[ "$eline" =~ "← 高亮行" || "$eline" =~ "←" ]]; then
        linenum=$(echo "$eline" | grep -oE '^[[:space:]]*[0-9]+' | xargs || true)
        code=$(echo "$eline" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]*//')
        FINDINGS_HTML+="<span class=\"highlight-line\"><span class=\"line-num\">${linenum}</span>${code}</span>"
      else
        linenum=$(echo "$eline" | grep -oE '^[[:space:]]*[0-9]+' | xargs || true)
        code=$(echo "$eline" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]*//')
        FINDINGS_HTML+="<span class=\"line-num\">${linenum}</span>${code}<br>"
      fi
    done <<< "$f_evidence"
    FINDINGS_HTML+="</div>"
  fi

  # recommendation
  [[ -n "$f_recommendation" ]] && FINDINGS_HTML+="<div class=\"finding-recommendation\">${f_recommendation}</div>"

  FINDINGS_HTML+="</div></div>"
}

FINDINGS_SECTION=$(echo "$BODY" | awk '/^## findings/{f=1; next} /^## [a-z]/{if(f) exit} f{print}')
if [[ -n "$FINDINGS_SECTION" ]]; then
while IFS= read -r line; do
  if [[ "$line" =~ ^###[[:space:]]+(RISK-[0-9]+) ]]; then
    flush_finding
    current_risk="${BASH_REMATCH[1]}"
    f_severity="" f_category="" f_title="" f_location="" f_function="" f_description="" f_evidence="" f_recommendation=""
    in_evidence=0
  elif [[ $in_evidence -eq 1 ]]; then
    if [[ "$line" == "- recommendation:"* ]]; then
      in_evidence=0
      f_recommendation=$(echo "$line" | sed -E 's/^- recommendation:[[:space:]]*//')
    else
      f_evidence+="${line}"$'\n'
    fi
  elif [[ "$line" == "- severity:"* ]]; then
    f_severity=$(echo "$line" | sed -E 's/^- severity:[[:space:]]*//')
  elif [[ "$line" == "- category:"* ]]; then
    f_category=$(echo "$line" | sed -E 's/^- category:[[:space:]]*//')
  elif [[ "$line" == "- title:"* ]]; then
    f_title=$(echo "$line" | sed -E 's/^- title:[[:space:]]*//')
  elif [[ "$line" == "- location:"* ]]; then
    f_location=$(echo "$line" | sed -E 's/^- location:[[:space:]]*//')
  elif [[ "$line" == "- function:"* ]]; then
    f_function=$(echo "$line" | sed -E 's/^- function:[[:space:]]*//')
  elif [[ "$line" == "- description:"* ]]; then
    f_description=$(echo "$line" | sed -E 's/^- description:[[:space:]]*//')
  elif [[ "$line" == "- evidence:"* ]]; then
    in_evidence=1
    f_evidence=""
  elif [[ "$line" == "- recommendation:"* ]]; then
    f_recommendation=$(echo "$line" | sed -E 's/^- recommendation:[[:space:]]*//')
  fi
done <<< "$FINDINGS_SECTION"
flush_finding
fi

# ─── 解析 body: recommendations ───
REC_SECTION=$(echo "$BODY" | awk '/^## recommendations/{f=1; next} f{print}')
RECOMMENDATIONS_HTML=""
rec_num=0
rec_title=""
rec_desc=""

flush_rec() {
  [[ -z "$rec_title" ]] && return
  RECOMMENDATIONS_HTML+="<li class=\"rec-item\">"
  RECOMMENDATIONS_HTML+="<span class=\"rec-num\">${rec_num}</span>"
  RECOMMENDATIONS_HTML+="<div class=\"rec-content\">"
  RECOMMENDATIONS_HTML+="<div class=\"rec-title\">${rec_title}</div>"
  RECOMMENDATIONS_HTML+="<div class=\"rec-desc\">${rec_desc}</div>"
  RECOMMENDATIONS_HTML+="</div></li>"
}

if [[ -n "$REC_SECTION" ]]; then
while IFS= read -r line; do
  if [[ "$line" =~ ^###[[:space:]]+([0-9]+)\.[[:space:]]+(.*) ]]; then
    flush_rec
    rec_num="${BASH_REMATCH[1]}"
    rec_title="${BASH_REMATCH[2]}"
    rec_desc=""
  elif [[ -n "$line" && ! "$line" =~ ^## ]]; then
    rec_desc+="${line} "
  fi
done <<< "$REC_SECTION"
flush_rec
fi

# ─── 注入模板 ───
# 使用 perl 做替换（避免 sed 的转义问题）
cp "$TEMPLATE" "$OUTPUT"

replace_placeholder() {
  local key="$1"
  local value="$2"
  CLS_REPLACE_VALUE="$value" perl -pi -e 's/\Q{{'"$key"'}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
}

replace_placeholder "report_id" "$REPORT_ID"
replace_placeholder "report_date" "$REPORT_DATE"
replace_placeholder "scanner_version" "$SCANNER_VERSION"
replace_placeholder "scan_mode" "$SCAN_MODE"
replace_placeholder "skill_name" "$SKILL_NAME"
replace_placeholder "skill_version" "$SKILL_VERSION"
replace_placeholder "skill_path" "$SKILL_PATH"
replace_placeholder "maintainer" "$MAINTAINER"
replace_placeholder "scan_duration" "$SCAN_DURATION"
replace_placeholder "code_stats" "$CODE_STATS"
replace_placeholder "grade" "$GRADE"
replace_placeholder "score" "$SCORE"
replace_placeholder "stamp_color" "$STAMP_COLOR"
replace_placeholder "stamp_svg_color" "$STAMP_SVG_COLOR"
replace_placeholder "total_findings" "$TOTAL_FINDINGS"
replace_placeholder "sample_hash" "$SAMPLE_HASH"
replace_placeholder "disclaimer" "$DISCLAIMER"
replace_placeholder "recommendations_title" "$REC_TITLE"
replace_placeholder "radar_fill_color" "$RADAR_FILL"
replace_placeholder "radar_stroke_color" "$RADAR_STROKE"
replace_placeholder "api_count" "$API_COUNT"
replace_placeholder "findings_count" "$FINDINGS_COUNT"

# 复合 HTML 片段同样用环境变量传值（避免 shell/perl 双层解释）
CLS_REPLACE_VALUE="$TRUST_TAG" perl -pi -e 's/\Q{{trust_level_tag}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$LICENSE_TAG" perl -pi -e 's/\Q{{license_tag}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$EVALUATION" perl -pi -e 's/\Q{{evaluation}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$TAGS_HTML" perl -pi -e 's/\Q{{PATTERN_TAGS_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$SUMMARY_HTML" perl -pi -e 's/\Q{{SUMMARY_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$POLYGON_POINTS" perl -pi -e 's/\Q{{RADAR_POLYGON_POINTS}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$DOTS_HTML" perl -pi -e 's/\Q{{RADAR_DOTS_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$LEGEND_HTML" perl -pi -e 's/\Q{{RADAR_LEGEND_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$APIS_HTML" perl -pi -e 's/\Q{{APIS_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$FINDINGS_HTML" perl -pi -e 's/\Q{{FINDINGS_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$COMPLIANCE_HTML" perl -pi -e 's/\Q{{COMPLIANCE_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"
CLS_REPLACE_VALUE="$RECOMMENDATIONS_HTML" perl -pi -e 's/\Q{{RECOMMENDATIONS_HTML}}\E/$ENV{CLS_REPLACE_VALUE}/g' "$OUTPUT"

# ─── 验证 ───
REMAINING=$(grep -c '{{' "$OUTPUT" || true)
if [[ "$REMAINING" -gt 0 ]]; then
  echo "⚠ 警告: HTML 中仍有 ${REMAINING} 个未替换的占位符:" >&2
  grep -oE '\{\{[a-zA-Z0-9_]+\}\}' "$OUTPUT" | sort -u >&2
fi

echo "✓ HTML 报告已生成: $OUTPUT"
echo "  等级: ${GRADE} | 评分: ${SCORE}/100 | 发现: ${TOTAL_FINDINGS} 项"

# ─── PDF 生成 ───
if [[ "$GENERATE_PDF" -eq 1 ]]; then
  PDF_OUTPUT="${OUTPUT%.html}.pdf"

  # 查找 Chrome
  CHROME=""
  for candidate in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do
    if [[ -f "$candidate" ]]; then
      CHROME="$candidate"
      break
    fi
  done

  if [[ -z "$CHROME" ]]; then
    echo "⚠ 跳过 PDF: 未找到 Chrome/Edge/Chromium，请安装后重试" >&2
  else
    # 将 HTML 路径转为 file:// URL
    ABS_OUTPUT="$(cd "$(dirname "$OUTPUT")" && pwd)/$(basename "$OUTPUT")"
    FILE_URL="file://${ABS_OUTPUT}"

    "$CHROME" \
      --headless \
      --disable-gpu \
      --no-sandbox \
      --print-to-pdf="$PDF_OUTPUT" \
      --no-pdf-header-footer \
      --run-all-compositor-stages-before-draw \
      --virtual-time-budget=15000 \
      "$FILE_URL" \
      2>/dev/null

    if [[ -f "$PDF_OUTPUT" ]]; then
      echo "✓ PDF 报告已生成: $PDF_OUTPUT"
    else
      echo "⚠ PDF 生成失败" >&2
    fi
  fi
fi
