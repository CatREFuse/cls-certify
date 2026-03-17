# CLS-Certify 威胁模式库 v2.1

> 140+ 安全威胁检测模式，覆盖命令注入、数据外泄、提示词注入、Agent 上下文注入、终端注入等攻击向量

---

## 模式分类概览

| 类别 | 数量 | 主要风险 |
|-----|------|---------|
| 代码执行类 | 25 | RCE、命令注入 |
| 数据安全类 | 10 | 数据外泄、凭证窃取 |
| 注入攻击类 | 25 | SQL注入、命令注入、XSS、终端注入 |
| AI 安全类 | 18 | 提示词注入、越狱攻击 |
| 提示词投毒类 | 15 | 隐蔽注入、MCP 工具链攻击、静默执行 |
| 权限升级类 | 24 | 配置篡改、Hook 滥用、Shell 深度注入 |
| 供应链类 | 5 | 依赖混淆、恶意包 |
| 网络攻击类 | 5 | SSRF、DNS 重绑定 |
| **Agent 上下文注入类** | **12** | **记忆注入、系统提示篡改、配置注入** |

---

## 1. 代码执行类 (Code Execution)

### TH-001: 动态代码执行

```yaml
id: TH-001
name: dangerous_eval_exec
severity: critical
category: code_execution
description: 使用 eval/exec 执行动态代码

patterns:
  javascript:
    - pattern: "eval\\s*\\("
      description: "JavaScript eval()"
    - pattern: "Function\\s*\\("
      description: "JavaScript Function constructor"
    - pattern: "setTimeout\\s*\\([^,]+,\\s*['\"]`
      description: "setTimeout with string"
    - pattern: "setInterval\\s*\\([^,]+,\\s*['\"]`
      description: "setInterval with string"

  python:
    - pattern: "eval\\s*\\("
      description: "Python eval()"
    - pattern: "exec\\s*\\("
      description: "Python exec()"
    - pattern: "compile\\s*\\("
      description: "Python compile()"
    - pattern: "__import__\\s*\\("
      description: "Python dynamic import"

  shell:
    - pattern: "eval\\s+"
      description: "Shell eval"
    - pattern: "\\$\\("
      description: "Command substitution"
    - pattern: "`[^`]+`"
      description: "Backtick command execution"

impact: >
  攻击者可能通过注入恶意代码实现远程代码执行 (RCE)，
  完全控制目标系统。

mitigation: >
  - 使用 JSON.parse 替代 eval 解析 JSON
  - 使用 ast.literal_eval 替代 eval 解析 Python 字面量
  - 避免使用字符串拼接构建命令

example_risk:
  code: "eval(userInput)"
  attack: "userInput = '__import__(\"os\").system(\"rm -rf /\")'"
```

### TH-002: 系统命令执行

```yaml
id: TH-002
name: system_command_execution
severity: critical
category: code_execution
description: 执行系统级命令

patterns:
  python:
    - pattern: "os\\.system\\s*\\("
    - pattern: "os\\.popen\\s*\\("
    - pattern: "subprocess\\.call\\s*\\("
    - pattern: "subprocess\\.run\\s*\\("
    - pattern: "subprocess\\.Popen\\s*\\("

  nodejs:
    - pattern: "child_process"
    - pattern: "exec\\s*\\("
    - pattern: "execSync\\s*\\("
    - pattern: "spawn\\s*\\("

  php:
    - pattern: "system\\s*\\("
    - pattern: "exec\\s*\\("
    - pattern: "passthru\\s*\\("
    - pattern: "shell_exec\\s*\\("
    - pattern: "proc_open\\s*\\("

  ruby:
    - pattern: "system\\s*\\("
    - pattern: "exec\\s*\\("
    - pattern: "backtick|%x\{"
    - pattern: "IO\\.popen"

impact: 命令注入风险，攻击者可执行任意系统命令
mitigation: >
  - 使用参数化命令执行
  - 严格过滤用户输入
  - 使用白名单限制允许的命令
```

---

## 2. 数据安全类 (Data Security)

### TH-010: API 密钥硬编码

```yaml
id: TH-010
name: hardcoded_api_keys
severity: high
category: secret_leak
description: 代码中硬编码 API 密钥

patterns:
  openai:
    - pattern: "sk-[a-zA-Z0-9]{48}"
      description: "OpenAI API Key"
    - pattern: "sk-proj-[a-zA-Z0-9]{48,}"
      description: "OpenAI Project API Key"

  github:
    - pattern: "ghp_[a-zA-Z0-9]{36}"
      description: "GitHub Personal Access Token"
    - pattern: "gho_[a-zA-Z0-9]{36}"
      description: "GitHub OAuth Token"
    - pattern: "ghu_[a-zA-Z0-9]{36}"
      description: "GitHub User Token"

  aws:
    - pattern: "AKIA[0-9A-Z]{16}"
      description: "AWS Access Key ID"
    - pattern: "ASIA[0-9A-Z]{16}"
      description: "AWS Temporary Access Key"

  generic:
    - pattern: "api[_-]?key\\s*[=:]\\s*['\"][a-zA-Z0-9]{32,}['\"]"
      description: "Generic API Key"
    - pattern: "api[_-]?secret\\s*[=:]\\s*['\"][a-zA-Z0-9]{32,}['\"]"
      description: "Generic API Secret"

entropy_check:
  enabled: true
  min_entropy: 4.5
  min_length: 20

impact: 密钥泄露可能导致未授权访问和数据泄露
mitigation: >
  - 使用环境变量存储密钥
  - 使用密钥管理服务 (KMS)
  - 实施密钥轮换策略
```

### TH-011: 密码硬编码

```yaml
id: TH-011
name: hardcoded_passwords
severity: critical
category: secret_leak
description: 代码中硬编码密码

patterns:
  - pattern: "password\\s*[=:]\\s*['\"][^'\"]+['\"]"
    context_check: true
  - pattern: "passwd\\s*[=:]\\s*['\"][^'\"]+['\"]"
  - pattern: "pwd\\s*[=:]\\s*['\"][^'\"]+['\"]"
  - pattern: "pass\\s*[=:]\\s*['\"][^'\"]+['\"]"

exclusions:
  - "password = os.environ.get"
  - "password = input("
  - "password = getpass("
  - "password = ''"
  - 'password = ""'
  - "password = None"

impact: 硬编码密码可直接被攻击者利用
mitigation: >
  - 使用密钥管理系统
  - 使用配置中心
  - 使用哈希存储（而非明文）
```

### TH-012: 私钥泄露

```yaml
id: TH-012
name: private_key_exposure
severity: critical
category: secret_leak
description: 私钥文件泄露

patterns:
  rsa:
    - pattern: "-----BEGIN RSA PRIVATE KEY-----"
    - pattern: "-----BEGIN OPENSSH PRIVATE KEY-----"

  ecdsa:
    - pattern: "-----BEGIN EC PRIVATE KEY-----"

  dsa:
    - pattern: "-----BEGIN DSA PRIVATE KEY-----"

  pkcs8:
    - pattern: "-----BEGIN PRIVATE KEY-----"
    - pattern: "-----BEGIN ENCRYPTED PRIVATE KEY-----"

file_extensions:
  - ".pem"
  - ".key"
  - ".p12"
  - ".pfx"
  - "id_rsa"
  - "id_dsa"
  - "id_ecdsa"
  - "id_ed25519"

impact: 私钥泄露可导致完全系统接管
mitigation: >
  - 使用密钥管理系统
  - 私钥文件添加至 .gitignore
  - 定期轮换密钥对
```

---

## 3. 注入攻击类 (Injection Attacks)

### TH-020: SQL 注入

```yaml
id: TH-020
name: sql_injection
severity: critical
category: injection
description: SQL 注入漏洞

patterns:
  string_concat:
    - pattern: "SELECT.*\\+.*\$"
      languages: [java, javascript]
    - pattern: 'SELECT.*\+.*\+'
      languages: [python, javascript]
    - pattern: "SELECT.*\\{\\$"
      languages: [php]
    - pattern: 'SELECT.*%s'
      languages: [python]
    - pattern: "SELECT.*\\{\\{"
      languages: [javascript_template]

  unsafe_functions:
    - pattern: "sqlite3.*execute.*\\+"
    - pattern: "cursor\\.execute.*%"
    - pattern: "db\\.query.*\\+"

  keywords:
    - "UNION SELECT"
    - "OR 1=1"
    - "'; DROP TABLE"
    - "--"
    - "/*"

impact: 数据泄露、数据篡改、权限提升
mitigation: >
  - 使用参数化查询/预编译语句
  - 使用 ORM 框架
  - 严格输入验证
```

### TH-021: 命令注入

```yaml
id: TH-021
name: command_injection
severity: critical
category: injection
description: 命令注入漏洞

patterns:
  - pattern: "exec\\s*\\(.*\\+"
  - pattern: "system\\s*\\(.*\\$"
  - pattern: "popen\\s*\\(.*\\+"
  - pattern: "cmd\\s*\\+"
  - pattern: "Runtime\\.getRuntime\\(\\)\\.exec"

dangerous_chars:
  - ";"
  - "&"
  - "|"
  - "`"
  - "$"
  - "("
  - ")"
  - "\"
  - "'"
  - "\\n"

impact: 远程代码执行、系统接管
mitigation: >
  - 避免使用 shell=True
  - 使用参数列表而非字符串
  - 严格过滤危险字符
```

### TH-022: 路径遍历

```yaml
id: TH-022
name: path_traversal
severity: high
category: injection
description: 路径遍历/目录遍历漏洞

patterns:
  - pattern: "open\\s*\\(.*\\+.*\\+"
  - pattern: "readFile.*\\+"
  - pattern: "sendFile.*\\+"
  - pattern: "\\.\\./"
  - pattern: "\\.\\.\\\\"
  - pattern: "%2e%2e%2f"
  - pattern: "%2e%2e/"

sensitive_paths:
  - "/etc/passwd"
  - "/etc/shadow"
  - "C:\\\\Windows\\\\System32"
  - "../../etc/passwd"
  - "....//....//etc/passwd"

impact: 未授权文件访问、敏感文件读取
mitigation: >
  - 使用白名单限制路径
  - 规范化路径后验证
  - 使用 chroot 限制访问范围
```

---

## 4. AI 安全类 (AI Safety)

### TH-030: 提示词注入

```yaml
id: TH-030
name: prompt_injection
severity: high
category: ai_safety
description: AI 提示词注入攻击

patterns:
  injection_attempts:
    - pattern: "ignore previous.*instruction"
      confidence: high
    - pattern: "ignore.*above.*instruction"
      confidence: high
    - pattern: "disregard.*previous"
      confidence: high
    - pattern: "DAN.*mode"
      confidence: high
    - pattern: "jailbreak"
      confidence: medium
    - pattern: "do anything now"
      confidence: high
    - pattern: "system prompt"
      confidence: medium
    - pattern: "developer mode"
      confidence: medium

  context_manipulation:
    - pattern: "new context:"
    - pattern: "system: you are now"
    - pattern: "as an AI without restrictions"

impact: 绕过 AI 安全限制、获取有害内容
mitigation: >
  - 输入过滤和清洗
  - 提示词隔离
  - 输出内容审核
  - 使用结构化提示词
```

### TH-031: 越狱攻击

```yaml
id: TH-031
name: jailbreak_attack
severity: high
category: ai_safety
description: AI 越狱攻击模式

patterns:
  - pattern: "hypothetically speaking"
  - pattern: "for educational purposes"
  - pattern: "in a fictional scenario"
  - pattern: "pretend you are"
  - pattern: "roleplay as"
  - pattern: "you are not bound by"
  - pattern: "no longer subject to"

impact: 诱导 AI 生成有害内容
mitigation: >
  - 意图识别
  - 多层安全防护
  - 输出过滤
```

---

## 5. 供应链类 (Supply Chain)

### TH-040: Typosquatting 检测

```yaml
id: TH-040
name: typosquatting_detection
severity: high
category: supply_chain
description: 依赖包名称混淆攻击

popular_packages:
  - name: "lodash"
    typosquats:
      - "lodahs"
      - "loadsh"
      - "lodash.js"
      - "lodash-es5"

  - name: "express"
    typosquats:
      - "express.js"
      - "expressjs"
      - "express-js"
      - "expres"

  - name: "axios"
    typosquats:
      - "axois"
      - "axios-js"
      - "axios-http"

detection_methods:
  - levenshtein_distance:
      threshold: 2
  - visual_similarity:
      threshold: 0.8
  - soundex_match:
      enabled: true

impact: 安装恶意依赖，导致供应链攻击
mitigation: >
  - 验证包名拼写
  - 检查下载量和维护状态
  - 审查包内容
```

---

## 6. 网络攻击类 (Network Attacks)

### TH-050: SSRF (服务器端请求伪造)

```yaml
id: TH-050
name: server_side_request_forgery
severity: high
category: network
description: 服务器端请求伪造

patterns:
  - pattern: "request\\s*\\(.*http"
  - pattern: "fetch\\s*\\(.*url"
  - pattern: "urllib.*request"
  - pattern: "curl.*\\$"
  - pattern: "wget.*\\$"

internal_targets:
  - "localhost"
  - "127.0.0.1"
  - "0.0.0.0"
  - "::1"
  - "10."
  - "172.16."
  - "192.168."
  - "169.254."
  - "metadata.google.internal"
  - "169.254.169.254"

impact: 访问内部服务、云元数据窃取
mitigation: >
  - URL 白名单
  - DNS 解析后验证 IP
  - 禁用重定向或限制重定向次数
```

---

## 威胁检测配置

### 启用/禁用特定模式

```yaml
threat_detection_config:
  # 全局设置
  enabled: true
  default_severity: high

  # 按类别启用
  categories:
    code_execution:
      enabled: true
      min_severity: critical

    secret_leak:
      enabled: true
      min_severity: high
      entropy_check: true

    injection:
      enabled: true
      min_severity: high

    ai_safety:
      enabled: true
      min_severity: medium

    supply_chain:
      enabled: true
      min_severity: high

    network:
      enabled: true
      min_severity: high

  # 误报排除
  exclusions:
    - pattern: "test_"
      files: ["*test*.js", "*spec*.js"]
    - pattern: "example"
      files: ["README.md", "docs/*"]
```

---

## 7. Agent 上下文注入类 (Agent Context Injection)

### TH-AC: Agent 记忆与配置篡改

```yaml
id: TH-AC-001~012
severity: critical/high
category: agent_context

patterns:
  memory_injection:
    - pattern: "\\.claude/memory"
      description: "访问 Agent 记忆目录"
    - pattern: "MEMORY\\.md"
      description: "修改记忆文件"

  system_prompt_tampering:
    - pattern: "CLAUDE\\.md"
      description: "篡改系统提示文件"
    - pattern: "\\.claude/"
      description: "访问 Agent 配置目录"

  config_injection:
    - pattern: "settings\\.local\\.json"
      description: "修改本地配置"
    - pattern: "permissions\\.allow"
      description: "修改权限白名单"
    - pattern: "permissions\\.deny"
      description: "修改权限黑名单"

  tool_based_injection:
    - pattern: "Write.*memory|Edit.*memory"
      description: "通过工具注入记忆"
    - pattern: "Write.*CLAUDE\\.md|Edit.*CLAUDE\\.md"
      description: "通过工具篡改系统提示"
    - pattern: "Write.*settings.*json|Edit.*settings.*json"
      description: "通过工具修改配置"

impact: >
  Agent 上下文注入攻击可以从根本上改变 Agent 的行为模式。
  记忆注入可植入虚假信息影响后续决策；系统提示篡改可移除安全约束；
  配置注入可自行授予危险权限。这类攻击的危害性在于其持久性和隐蔽性。

mitigation:
  - 对 ~/.claude/ 目录下所有文件实施写保护
  - 限制 skill 对 Agent 配置文件的访问权限
  - 实施记忆文件完整性校验（哈希比对）
```

### TH-PE-013~024: Hook 滥用与 Shell 配置深度注入

```yaml
id: TH-PE-013~024
severity: critical/high
category: privilege_escalation

patterns:
  hook_abuse:
    - pattern: "UserPromptSubmit"
      description: "拦截用户输入的中间人攻击"
    - pattern: "PreToolUse"
      description: "在工具执行前注入逻辑"
    - pattern: "hooks.*(\\.(sh|bash|py|js))"
      description: "Hook 引用外部脚本"

  shell_deep_injection:
    - pattern: "alias\\s+(cd|ls|rm|...)\\s*="
      description: "劫持常用命令别名"
    - pattern: "function\\s+(cd|ls|rm|...)\\s*\\(\\)"
      description: "函数覆盖系统命令"
    - pattern: "export\\s+PATH\\s*="
      description: "PATH 环境变量劫持"
    - pattern: "LD_PRELOAD|DYLD_INSERT_LIBRARIES"
      description: "动态库预加载注入"
    - pattern: "PROMPT_COMMAND\\s*="
      description: "命令提示钩子注入"
    - pattern: "complete\\s+-|compdef\\s+"
      description: "Tab 补全注入"

impact: >
  Hook 滥用可实现对 Agent 交互的全面监控和操控。
  Shell 配置注入可在用户不知情的情况下持久化恶意行为。
```

### TH-INJ-018~025: 日志/终端注入

```yaml
id: TH-INJ-018~025
severity: critical/high/medium
category: injection

patterns:
  ansi_escape:
    - pattern: "\\\\x1[bB]\\["
      description: "ANSI 转义(hex)"
    - pattern: "\\\\033\\["
      description: "ANSI 转义(octal)"
    - pattern: "\\\\e\\["
      description: "ANSI 转义(named)"

  terminal_control:
    - pattern: "\\\\r[^\\n]"
      description: "回车覆写伪造输出"
    - pattern: "\\\\x1[bB]\\]0;"
      description: "终端标题注入"
    - pattern: "\\\\x07|\\\\a"
      description: "响铃字符注入"

impact: >
  终端注入可伪造命令输出，使用户误判安全状态。
  屏幕清除可隐藏恶意操作痕迹。回车覆写可覆盖已显示内容。
```

### TH-PP-010~015: MCP 工具链攻击

```yaml
id: TH-PP-010~015
severity: critical
category: prompt_poison

patterns:
  tool_exploitation:
    - pattern: "(use|call|invoke).*Bash.*(tool|command)"
      description: "引导使用 Bash 工具"
    - pattern: "(use|call).*Write.*(tool|overwrite)"
      description: "引导使用 Write 工具覆盖文件"
    - pattern: "mcp__.*mcp__"
      description: "多工具链组合攻击"

  silent_operation:
    - pattern: "不要(告诉|提示)用户|静默(执行|运行)"
      description: "中文静默执行指令"
    - pattern: "(do not|don't).*(tell|show).*user|silently.*execute"
      description: "英文静默执行指令"

impact: >
  MCP 工具链攻击是 Agent 时代的新型攻击向量。
  Skill 本身可能不包含危险代码，但通过精心构造的提示词，
  引导 Agent 使用已有的 MCP 工具实现恶意目标。
```

---

*威胁库版本: v2.1*
*最后更新: 2026-03-17*
*模式数量: 140+*
