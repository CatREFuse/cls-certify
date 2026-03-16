#!/usr/bin/env bash
# CLS-Certify 安全威胁模式扫描工具
# 基于正则模式扫描代码中的安全威胁，支持多类别检测
#
# 用法:
#   ./tools/threat-scan.sh <file_or_dir> [--json] [--category <category>]
#
# 示例:
#   ./tools/threat-scan.sh ./src/
#   ./tools/threat-scan.sh ./src/ --category code_execution
#   ./tools/threat-scan.sh ./src/ --json
#   ./tools/threat-scan.sh ./src/ --json --category injection

set -euo pipefail

# ─── 默认参数 ───
OUTPUT_JSON=false
TARGET=""
FILTER_CATEGORY=""

# ─── 颜色 ───
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── 排除的文件模式 ───
EXCLUDE_PATTERNS=(
    "*.test.js" "*.spec.js" "*.test.ts" "*.spec.ts"
    "*test*.py" "__tests__/*" "__pycache__/*"
    "node_modules/*" ".git/*" "vendor/*" "dist/*" "build/*"
    "*.min.js" "*.min.css" "*.map"
    "*.png" "*.jpg" "*.jpeg" "*.gif" "*.svg" "*.ico"
    "*.woff" "*.woff2" "*.ttf" "*.eot"
    "*.zip" "*.tar" "*.gz" "*.pdf"
    "*.pyc" "*.o" "*.so" "*.dylib" "*.exe" "*.dll"
)

# ─── 使用说明 ───
usage() {
    echo "CLS-Certify 安全威胁模式扫描工具"
    echo ""
    echo "用法: $0 <file_or_dir> [options]"
    echo ""
    echo "选项:"
    echo "  --json                 输出 JSON 格式"
    echo "  --category <category>  过滤检测类别"
    echo "  -h, --help             显示帮助"
    echo ""
    echo "支持的类别:"
    echo "  code_execution     代码执行"
    echo "  injection          注入攻击"
    echo "  ai_safety          AI 安全"
    echo "  exfiltration       隐蔽外传"
    echo "  prompt_poison      提示词投毒"
    echo "  privilege_escalation 权限升级"
    echo "  conditional_trigger  条件触发"
    echo "  dynamic_download   动态下载"
    exit 0
}

# ─── 参数解析 ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        --category) FILTER_CATEGORY="$2"; shift 2 ;;
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

# 验证类别参数
VALID_CATEGORIES="code_execution|injection|ai_safety|exfiltration|prompt_poison|privilege_escalation|conditional_trigger|dynamic_download"
if [[ -n "$FILTER_CATEGORY" ]]; then
    if ! echo "$FILTER_CATEGORY" | grep -qE "^($VALID_CATEGORIES)$"; then
        echo "错误: 无效的类别 '$FILTER_CATEGORY'"
        echo "有效类别: $VALID_CATEGORIES"
        exit 1
    fi
fi

# ─── 零宽字符正则（需要嵌入实际 UTF-8 字节） ───
ZERO_WIDTH_REGEX=$'[\xe2\x80\x8b\xe2\x80\x8c\xe2\x80\x8d\xe2\x81\xa0\xef\xbb\xbf]'

# ─── 威胁模式定义 ───
# 格式: "类别;;严重性;;模式ID;;模式名称;;正则;;描述;;影响;;建议"
# 使用 ;; 作为分隔符，避免与正则中的 | 冲突

THREAT_PATTERNS=(
    # ── code_execution（代码执行）── critical ──
    'code_execution;;critical;;TH-CE-001;;dangerous_eval_js;;eval\s*\(;;JS eval() 执行动态代码;;攻击者可能通过注入恶意代码实现 RCE;;使用 JSON.parse 或安全的解析替代 eval'
    'code_execution;;critical;;TH-CE-002;;function_constructor;;Function\s*\(;;使用 Function 构造器创建动态函数;;可被利用执行任意代码;;避免动态构造函数，使用静态定义'
    'code_execution;;critical;;TH-CE-003;;settimeout_string;;setTimeout\s*\(\s*['"'"'"'"'"'"`];;setTimeout 传入字符串参数;;等效于 eval，可执行注入代码;;传入函数引用而非字符串'
    'code_execution;;critical;;TH-CE-004;;setinterval_string;;setInterval\s*\(\s*['"'"'"'"'"'"`];;setInterval 传入字符串参数;;等效于 eval，可执行注入代码;;传入函数引用而非字符串'
    'code_execution;;critical;;TH-CE-005;;python_eval;;eval\s*\(;;Python eval() 执行动态表达式;;攻击者可注入恶意表达式;;使用 ast.literal_eval 或白名单校验'
    'code_execution;;critical;;TH-CE-006;;python_exec;;exec\s*\(;;Python exec() 执行动态代码;;可执行任意 Python 代码;;避免 exec，使用安全的替代方案'
    'code_execution;;critical;;TH-CE-007;;python_compile;;compile\s*\(;;Python compile() 编译动态代码;;可被利用编译恶意代码;;避免动态编译用户输入'
    'code_execution;;critical;;TH-CE-008;;python_import;;__import__\s*\(;;Python 动态导入模块;;可导入危险模块;;使用显式 import 语句'
    'code_execution;;critical;;TH-CE-009;;shell_eval;;eval\s+;;Shell eval 执行动态命令;;可执行注入的 Shell 命令;;避免 eval，使用参数数组'
    'code_execution;;critical;;TH-CE-010;;child_process;;child_process;;Node.js child_process 模块;;可执行系统命令;;验证并过滤所有传入参数'
    'code_execution;;critical;;TH-CE-011;;exec_sync;;execSync\s*\(;;Node.js 同步执行系统命令;;可执行注入的系统命令;;使用 execFile 并验证参数'
    'code_execution;;critical;;TH-CE-012;;spawn_call;;spawn\s*\(;;创建子进程;;可执行系统命令;;验证并过滤传入参数'
    'code_execution;;critical;;TH-CE-013;;os_system;;os\.system\s*\(;;Python os.system() 执行系统命令;;可执行任意系统命令;;使用 subprocess 并传入参数列表'
    'code_execution;;critical;;TH-CE-014;;os_popen;;os\.popen\s*\(;;Python os.popen() 执行命令;;可执行任意系统命令;;使用 subprocess.run 替代'
    'code_execution;;critical;;TH-CE-015;;subprocess_call;;subprocess\.(call|run|Popen)\s*\(;;Python subprocess 执行命令;;可执行系统命令;;避免 shell=True，使用参数列表'
    'code_execution;;critical;;TH-CE-016;;php_system;;system\s*\(;;PHP system() 执行系统命令;;可执行任意系统命令;;使用 escapeshellarg 过滤参数'
    'code_execution;;critical;;TH-CE-017;;php_passthru;;passthru\s*\(;;PHP passthru() 执行命令;;可执行任意系统命令;;避免直接执行用户输入'
    'code_execution;;critical;;TH-CE-018;;php_shell_exec;;shell_exec\s*\(;;PHP shell_exec() 执行命令;;可执行任意系统命令;;使用 escapeshellarg 过滤'
    'code_execution;;critical;;TH-CE-019;;php_proc_open;;proc_open\s*\(;;PHP proc_open() 创建进程;;可执行系统命令;;严格验证所有输入参数'
    'code_execution;;critical;;TH-CE-020;;ruby_system;;system\s*\(;;Ruby system() 执行系统命令;;可执行任意系统命令;;使用参数数组形式调用'
    'code_execution;;critical;;TH-CE-021;;ruby_io_popen;;IO\.popen;;Ruby IO.popen 执行命令;;可执行系统命令;;验证并过滤所有参数'
    'code_execution;;critical;;TH-CE-022;;destructive_rm;;rm\s+-rf\s+/;;递归删除根目录;;可造成系统级破坏;;使用安全路径限制，避免 -rf /'
    'code_execution;;critical;;TH-CE-023;;chmod_777;;chmod\s+777;;设置完全开放权限;;文件可被任意用户读写执行;;使用最小权限原则'
    'code_execution;;critical;;TH-CE-024;;mkfs_format;;mkfs\.;;格式化磁盘;;可造成数据完全丢失;;确认操作目标并添加保护'
    'code_execution;;critical;;TH-CE-025;;format_drive;;format\s+[A-Z]:;;格式化磁盘驱动器;;可造成数据完全丢失;;确认操作目标并添加保护'

    # ── injection（注入攻击）── critical ──
    'injection;;critical;;TH-INJ-001;;sql_concat_var;;SELECT.*\+.*\$;;SQL 查询中拼接变量;;可能存在 SQL 注入;;使用参数化查询'
    'injection;;critical;;TH-INJ-002;;sql_format_string;;SELECT.*%s;;SQL 查询使用格式化字符串;;可能存在 SQL 注入;;使用参数化查询'
    'injection;;critical;;TH-INJ-003;;sql_cursor_format;;cursor\.execute.*%;;cursor.execute 使用字符串格式化;;可能存在 SQL 注入;;使用参数化占位符'
    'injection;;critical;;TH-INJ-004;;sql_query_concat;;db\.query.*\+;;数据库查询拼接字符串;;可能存在 SQL 注入;;使用参数化查询'
    'injection;;critical;;TH-INJ-005;;sql_union_select;;UNION\s+SELECT;;UNION SELECT 语句;;可能被利用进行 SQL 注入;;使用参数化查询，验证输入'
    'injection;;critical;;TH-INJ-006;;sql_or_tautology;;OR\s+1=1;;SQL 恒真条件;;典型 SQL 注入 payload;;使用参数化查询'
    'injection;;critical;;TH-INJ-007;;cmd_exec_concat;;exec\s*\(.*\+;;命令执行中拼接字符串;;可能存在命令注入;;使用参数数组，避免拼接'
    'injection;;critical;;TH-INJ-008;;cmd_system_var;;system\s*\(.*\$;;system() 中使用变量;;可能存在命令注入;;过滤并验证所有外部输入'
    'injection;;critical;;TH-INJ-009;;cmd_popen_concat;;popen\s*\(.*\+;;popen() 中拼接字符串;;可能存在命令注入;;使用安全的命令构建方式'
    'injection;;critical;;TH-INJ-010;;runtime_exec;;Runtime\.getRuntime\(\)\.exec;;Java Runtime.exec 执行命令;;可能存在命令注入;;使用 ProcessBuilder 并验证参数'
    'injection;;critical;;TH-INJ-011;;path_traversal_unix;;\.\.\//;;Unix 路径遍历;;可访问任意文件;;规范化路径并检查边界'
    'injection;;critical;;TH-INJ-012;;path_traversal_win;;\.\.\\\\;;Windows 路径遍历;;可访问任意文件;;规范化路径并检查边界'
    'injection;;critical;;TH-INJ-013;;path_traversal_encoded;;%2e%2e%2f;;编码路径遍历;;可绕过路径过滤访问任意文件;;解码后检查路径遍历'
    'injection;;critical;;TH-INJ-014;;path_traversal_mixed;;%2e%2e/;;混合编码路径遍历;;可绕过路径过滤;;解码后检查路径遍历'
    'injection;;critical;;TH-INJ-015;;xss_document_write;;document\.write\s*\(;;document.write 输出内容;;可能存在 XSS 漏洞;;使用 textContent 或安全的 DOM 操作'
    'injection;;critical;;TH-INJ-016;;xss_innerhtml;;innerHTML\s*=;;直接设置 innerHTML;;可能存在 XSS 漏洞;;使用 textContent 或 DOMPurify 过滤'
    'injection;;critical;;TH-INJ-017;;xss_jquery_html;;\.html\s*\(.*\+;;jQuery .html() 拼接内容;;可能存在 XSS 漏洞;;使用 .text() 或过滤 HTML'

    # ── ai_safety（AI 安全）── high ──
    'ai_safety;;high;;TH-AI-001;;ignore_previous;;ignore previous.*instruction;;忽略先前指令的提示注入;;可绕过 AI 安全限制;;实施输入过滤和提示词防护'
    'ai_safety;;high;;TH-AI-002;;ignore_above;;ignore.*above.*instruction;;忽略上方指令的提示注入;;可绕过 AI 安全限制;;实施输入过滤和提示词防护'
    'ai_safety;;high;;TH-AI-003;;disregard_previous;;disregard.*previous;;无视先前内容的提示注入;;可绕过 AI 安全限制;;实施输入过滤和提示词防护'
    'ai_safety;;high;;TH-AI-004;;dan_mode;;DAN.*mode;;DAN 模式越狱尝试;;可绕过 AI 安全限制;;检测并阻断 DAN 模式请求'
    'ai_safety;;high;;TH-AI-005;;jailbreak_keyword;;jailbreak;;越狱关键词;;可能尝试绕过 AI 限制;;监控并过滤越狱尝试'
    'ai_safety;;high;;TH-AI-006;;do_anything_now;;do anything now;;"做任何事" 越狱尝试;;可绕过 AI 安全限制;;检测并阻断此类请求'
    'ai_safety;;high;;TH-AI-007;;system_prompt_leak;;system prompt;;尝试获取系统提示词;;可泄露系统配置;;保护系统提示词不被提取'
    'ai_safety;;high;;TH-AI-008;;developer_mode;;developer mode;;开发者模式越狱;;可绕过 AI 安全限制;;检测并阻断开发者模式请求'
    'ai_safety;;high;;TH-AI-009;;new_context;;new context:;;新上下文注入;;可重置 AI 行为约束;;验证上下文来源'
    'ai_safety;;high;;TH-AI-010;;role_override;;system:\s*you are now;;角色覆盖注入;;可改变 AI 行为;;验证角色指令来源'
    'ai_safety;;high;;TH-AI-011;;unrestricted_ai;;as an AI without restrictions;;无限制 AI 请求;;可绕过安全限制;;检测并阻断此类请求'
    'ai_safety;;high;;TH-AI-012;;hypothetical;;hypothetically speaking;;假设场景绕过;;可通过假设绕过限制;;识别假设场景中的恶意意图'
    'ai_safety;;high;;TH-AI-013;;educational_bypass;;for educational purposes;;教育目的绕过;;可借教育名义获取危险信息;;评估请求的真实意图'
    'ai_safety;;high;;TH-AI-014;;fictional_bypass;;in a fictional scenario;;虚构场景绕过;;可通过虚构场景绕过限制;;识别虚构场景中的恶意意图'
    'ai_safety;;high;;TH-AI-015;;pretend_bypass;;pretend you are;;角色扮演绕过;;可通过角色扮演绕过限制;;识别并阻断恶意角色扮演'
    'ai_safety;;high;;TH-AI-016;;roleplay_bypass;;roleplay as;;角色扮演绕过;;可通过角色扮演绕过限制;;识别并阻断恶意角色扮演'
    'ai_safety;;high;;TH-AI-017;;not_bound;;you are not bound by;;声称不受约束;;可尝试移除 AI 限制;;检测并阻断此类请求'
    'ai_safety;;high;;TH-AI-018;;no_longer_subject;;no longer subject to;;声称不再受限;;可尝试移除 AI 限制;;检测并阻断此类请求'

    # ── prompt_poison（提示词投毒）── critical ──
    'prompt_poison;;critical;;TH-PP-001;;html_comment_inject_en;;<!--.*(?:ignore|execute|skip).*-->;;HTML 注释中隐藏指令(英文);;可在不可见区域注入恶意指令;;过滤 HTML 注释中的指令'
    'prompt_poison;;critical;;TH-PP-002;;html_comment_inject_zh;;<!--.*(?:忽略|执行|跳过).*-->;;HTML 注释中隐藏指令(中文);;可在不可见区域注入恶意指令;;过滤 HTML 注释中的指令'
    "prompt_poison;;critical;;TH-PP-003;;zero_width_chars;;${ZERO_WIDTH_REGEX};;零宽字符隐藏内容;;可隐藏恶意指令在可见文本中;;检测并移除零宽字符"
    'prompt_poison;;critical;;TH-PP-004;;role_override_zh;;你现在是.*没有.*限制;;中文角色覆盖;;可重新定义 AI 角色和限制;;检测中文提示词攻击'
    'prompt_poison;;critical;;TH-PP-005;;forget_system_zh;;忘记.*系统提示;;中文遗忘系统提示;;可清除 AI 安全约束;;检测中文提示词攻击'
    'prompt_poison;;critical;;TH-PP-006;;forget_system_en;;forget.*system.*prompt;;遗忘系统提示(英文);;可清除 AI 安全约束;;保护系统提示词'
    'prompt_poison;;critical;;TH-PP-007;;skip_confirm_zh;;不需要用户确认直接执行;;跳过用户确认;;可绕过用户确认机制;;始终要求用户确认危险操作'
    'prompt_poison;;critical;;TH-PP-008;;skip_permission_zh;;跳过权限检查;;跳过权限检查;;可绕过权限验证;;始终执行权限检查'
    'prompt_poison;;critical;;TH-PP-009;;test_env_bypass_zh;;测试环境.*不需要安全;;测试环境安全绕过;;可在测试环境禁用安全措施;;所有环境都应用安全策略'

    # ── privilege_escalation（权限升级）── critical ──
    'privilege_escalation;;critical;;TH-PE-001;;disable_sandbox;;dangerouslyDisableSandbox;;禁用沙箱保护;;可突破沙箱限制执行危险操作;;保持沙箱启用'
    'privilege_escalation;;critical;;TH-PE-002;;skip_permission_prompt;;skipDangerousModePermissionPrompt;;跳过危险模式权限提示;;可绕过安全确认;;保持权限提示启用'
    'privilege_escalation;;critical;;TH-PE-003;;no_verify;;--no-verify;;跳过 Git hooks 验证;;可绕过代码质量和安全检查;;始终执行 Git hooks'
    'privilege_escalation;;critical;;TH-PE-004;;sudo_usage;;sudo\s+;;使用 sudo 提权;;可获取 root 权限;;使用最小权限原则'
    'privilege_escalation;;critical;;TH-PE-005;;doas_usage;;doas\s+;;使用 doas 提权;;可获取更高权限;;使用最小权限原则'
    'privilege_escalation;;critical;;TH-PE-006;;permissions_allow_bash;;permissions.*allow.*Bash;;配置允许 Bash 执行;;可执行任意系统命令;;限制允许的命令范围'
    'privilege_escalation;;critical;;TH-PE-007;;settings_json;;settings\.json;;修改设置文件;;可篡改工具配置;;保护配置文件完整性'
    'privilege_escalation;;critical;;TH-PE-008;;claude_settings;;\.claude/settings;;修改 Claude 设置;;可篡改 AI 工具安全配置;;保护 Claude 配置文件'
    'privilege_escalation;;critical;;TH-PE-009;;bashrc_modify;;\.bashrc;;修改 Bash 配置文件;;可注入持久化恶意命令;;监控 Shell 配置文件变更'
    'privilege_escalation;;critical;;TH-PE-010;;zshrc_modify;;\.zshrc;;修改 Zsh 配置文件;;可注入持久化恶意命令;;监控 Shell 配置文件变更'
    'privilege_escalation;;critical;;TH-PE-011;;profile_modify;;\.profile;;修改 Shell Profile;;可注入持久化恶意命令;;监控 Shell 配置文件变更'
    'privilege_escalation;;critical;;TH-PE-012;;hooks_tamper;;hooks.*PostToolUse;;篡改工具 Hook;;可在工具执行后运行恶意代码;;保护 Hook 配置'

    # ── exfiltration（隐蔽外传）── high ──
    'exfiltration;;high;;TH-EX-001;;dns_exfil_subshell;;\$\(.*\)\..*\.(com|net|org|io);;DNS 子域名数据外传;;可通过 DNS 查询泄露数据;;监控异常 DNS 请求'
    'exfiltration;;high;;TH-EX-002;;dns_dig_exfil;;dig\s+.*\$;;dig 命令中使用变量;;可通过 DNS 查询泄露数据;;过滤 DNS 查询中的敏感数据'
    'exfiltration;;high;;TH-EX-003;;dns_nslookup_exfil;;nslookup\s+.*\$;;nslookup 中使用变量;;可通过 DNS 查询泄露数据;;过滤 DNS 查询中的敏感数据'
    'exfiltration;;high;;TH-EX-004;;git_push_non_origin;;git\s+push.*(?!origin);;Git push 到非 origin 远程;;可将代码推送到恶意仓库;;限制 Git 远程仓库白名单'
    'exfiltration;;high;;TH-EX-005;;git_remote_add;;git\s+remote\s+add;;添加 Git 远程仓库;;可添加恶意仓库地址;;监控 Git 远程仓库变更'
    'exfiltration;;high;;TH-EX-006;;clipboard_pbcopy;;pbcopy;;使用 pbcopy 复制到剪贴板;;可将敏感数据复制到剪贴板;;监控剪贴板操作'
    'exfiltration;;high;;TH-EX-007;;clipboard_xclip;;xclip;;使用 xclip 操作剪贴板;;可将敏感数据复制到剪贴板;;监控剪贴板操作'
    'exfiltration;;high;;TH-EX-008;;clipboard_xsel;;xsel;;使用 xsel 操作剪贴板;;可将敏感数据复制到剪贴板;;监控剪贴板操作'
    'exfiltration;;high;;TH-EX-009;;clipboard_generic;;clipboard;;剪贴板操作;;可将敏感数据复制到剪贴板;;监控剪贴板操作'
    'exfiltration;;high;;TH-EX-010;;env_inject_bashrc;;>>\s*~/?\.(bashrc|zshrc|profile);;向 Shell 配置文件追加内容;;可注入持久化环境变量或命令;;监控 Shell 配置文件写入'

    # ── dynamic_download（动态下载）── high/critical ──
    'dynamic_download;;critical;;TH-DD-001;;curl_pipe_exec;;curl.*\|\s*(bash|sh|zsh|python|node);;curl 管道执行;;远程代码直接执行，无审计;;先下载后审查再执行'
    'dynamic_download;;critical;;TH-DD-002;;wget_exec;;wget.*&&.*(bash|sh|source|\./);; wget 下载后执行;;远程代码直接执行;;先下载后审查再执行'
    'dynamic_download;;critical;;TH-DD-003;;fetch_eval;;fetch\(.*\)\.then.*eval;;fetch 后 eval 执行;;远程代码直接执行;;验证来源并避免 eval'
    'dynamic_download;;critical;;TH-DD-004;;requests_exec;;requests\.get\(.*\).*exec\(;;requests.get 后 exec 执行;;远程代码直接执行;;验证来源并避免 exec'
    'dynamic_download;;high;;TH-DD-005;;anti_forensics_rm;;&&\s*rm\s+;;执行后删除痕迹;;可清除攻击证据;;保留操作日志和文件'
    'dynamic_download;;high;;TH-DD-006;;anti_forensics_shred;;&&\s*shred\s+;;执行后安全擦除;;可彻底清除攻击证据;;保留操作日志和文件'
    'dynamic_download;;high;;TH-DD-007;;tmp_exec_rm;;/tmp/.*&&.*rm;;临时文件执行后删除;;可执行后消除痕迹;;监控临时目录执行行为'

    # ── conditional_trigger（条件触发）── high ──
    'conditional_trigger;;high;;TH-CT-001;;time_js;;Date\(\).*get(Month|Date|FullYear);;JavaScript 时间条件检查;;可设置定时触发恶意逻辑;;审查时间相关条件逻辑'
    'conditional_trigger;;high;;TH-CT-002;;time_python;;datetime\.now\(\).*if;;Python 时间条件检查;;可设置定时触发恶意逻辑;;审查时间相关条件逻辑'
    'conditional_trigger;;high;;TH-CT-003;;time_shell;;date\s+.*-d;;Shell 日期条件;;可设置定时触发恶意逻辑;;审查时间相关条件逻辑'
    'conditional_trigger;;high;;TH-CT-004;;env_ci_check;;if.*(CI|GITHUB_ACTIONS|JENKINS);;CI 环境检测;;可在特定 CI 环境触发恶意行为;;审查 CI 环境条件逻辑'
    'conditional_trigger;;high;;TH-CT-005;;env_var_python;;if.*(os\.environ\[|process\.env\.);;环境变量条件检查;;可根据环境变量触发恶意行为;;审查环境变量条件逻辑'
    'conditional_trigger;;high;;TH-CT-006;;platform_check;;if.*(platform|os\.name|sys\.platform);;平台检测条件;;可针对特定平台触发恶意行为;;审查平台检测逻辑'
)

# ─── 解析模式定义（使用 ;; 分隔符） ───
parse_pattern() {
    local pattern_def="$1"
    # 将 ;; 替换为一个不太常见的单字符分隔符 (ASCII 单元分隔符 \x1F)
    local sep=$'\x1f'
    local converted="${pattern_def//;;/$sep}"
    IFS="$sep" read -r P_CATEGORY P_SEVERITY P_PATTERN_ID P_PATTERN_NAME P_REGEX P_DESCRIPTION P_IMPACT P_RECOMMENDATION <<< "$converted"
}

# ─── 判断是否在注释中 ───
is_comment_line() {
    local trimmed="$1"
    # 去除前导空白
    trimmed=$(echo "$trimmed" | sed 's/^[[:space:]]*//')
    case "$trimmed" in
        '#'*|'//'*|'/*'*|'*'*|'--'*|'"""'*|"'''"*) return 0 ;;
    esac
    return 1
}

# ─── 降低严重性（注释中的匹配降一级） ───
downgrade_severity() {
    local severity="$1"
    case "$severity" in
        critical) echo "high" ;;
        high)     echo "medium" ;;
        medium)   echo "low" ;;
        low)      echo "info" ;;
        *)        echo "$severity" ;;
    esac
}

# ─── 截断证据字符串 ───
truncate_evidence() {
    local str="$1"
    local max_len=60
    if [[ ${#str} -gt $max_len ]]; then
        echo "${str:0:50}..."
    else
        echo "$str"
    fi
}

# ─── 转义 JSON 字符串 ───
escape_json() {
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

scan_file() {
    local file="$1"
    local line_num=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))

        for pattern_def in "${THREAT_PATTERNS[@]}"; do
            parse_pattern "$pattern_def"

            # 过滤类别
            if [[ -n "$FILTER_CATEGORY" && "$P_CATEGORY" != "$FILTER_CATEGORY" ]]; then
                continue
            fi

            # 正则匹配
            if echo "$line" | grep -qEi "$P_REGEX" 2>/dev/null; then
                local current_severity="$P_SEVERITY"

                # 上下文感知：注释中降低严重性
                if is_comment_line "$line"; then
                    current_severity=$(downgrade_severity "$P_SEVERITY")
                fi

                TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))

                # 截断证据
                local trimmed_line
                trimmed_line=$(echo "$line" | sed 's/^[[:space:]]*//')
                local evidence
                evidence=$(truncate_evidence "$trimmed_line")

                if $OUTPUT_JSON; then
                    local escaped_evidence
                    escaped_evidence=$(escape_json "$evidence")
                    local escaped_file
                    escaped_file=$(escape_json "$file")
                    local escaped_desc
                    escaped_desc=$(escape_json "$P_DESCRIPTION")
                    local escaped_impact
                    escaped_impact=$(escape_json "$P_IMPACT")
                    local escaped_rec
                    escaped_rec=$(escape_json "$P_RECOMMENDATION")

                    local item
                    item=$(printf '{"id":"THREAT-%03d","file":"%s","line":%d,"severity":"%s","category":"%s","pattern_id":"%s","pattern_name":"%s","description":"%s","evidence":"%s","impact":"%s","recommendation":"%s"}' \
                        "$TOTAL_FINDINGS" "$escaped_file" "$line_num" "$current_severity" "$P_CATEGORY" "$P_PATTERN_ID" "$P_PATTERN_NAME" "$escaped_desc" "$escaped_evidence" "$escaped_impact" "$escaped_rec")

                    if [[ -n "$JSON_ITEMS" ]]; then
                        JSON_ITEMS="${JSON_ITEMS},${item}"
                    else
                        JSON_ITEMS="$item"
                    fi
                else
                    local color
                    case "$current_severity" in
                        critical) color="$RED" ;;
                        high)     color="$YELLOW" ;;
                        medium)   color="$MAGENTA" ;;
                        *)        color="$GREEN" ;;
                    esac
                    printf "  ${color}[%s]${RESET} ${BOLD}%s${RESET}:%d  category=${CYAN}%s${RESET}  pattern=${DIM}%s${RESET}\n" \
                        "$current_severity" "$file" "$line_num" "$P_CATEGORY" "$P_PATTERN_NAME"
                    printf "         %s\n\n" "$evidence"
                fi

                # 一行只匹配一个模式后跳出（避免重复报告同一行）
                break
            fi
        done
    done < "$file"
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
    echo -e "${BOLD}CLS-Certify 安全威胁模式扫描${RESET}"
    if [[ -n "$FILTER_CATEGORY" ]]; then
        echo -e "类别过滤: ${CYAN}${FILTER_CATEGORY}${RESET}"
    fi
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
    local_target=$(escape_json "$TARGET")
    printf '{"tool":"cls-threat-scan","target":"%s","total_findings":%d,"findings":[%s]}\n' \
        "$local_target" "$TOTAL_FINDINGS" "$JSON_ITEMS"
else
    echo "────────────────────────────────────────"
    if [[ $TOTAL_FINDINGS -eq 0 ]]; then
        echo -e "${GREEN}未发现安全威胁模式${RESET}"
    else
        echo -e "${YELLOW}共发现 ${BOLD}${TOTAL_FINDINGS}${RESET}${YELLOW} 个安全威胁模式${RESET}"
    fi
    echo ""
fi

exit $( [[ $TOTAL_FINDINGS -eq 0 ]] && echo 0 || echo 1 )
