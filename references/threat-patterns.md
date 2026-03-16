# CLS-Certify 威胁模式库 v2.0

> 40+ 安全威胁检测模式，覆盖命令注入、数据外泄、提示词注入、SSRF 等常见攻击向量

---

## 模式分类概览

| 类别 | 数量 | 主要风险 |
|-----|------|---------|
| 代码执行类 | 8 | RCE、命令注入 |
| 数据安全类 | 10 | 数据外泄、凭证窃取 |
| 注入攻击类 | 8 | SQL注入、命令注入、XSS |
| AI 安全类 | 6 | 提示词注入、越狱攻击 |
| 供应链类 | 5 | 依赖混淆、恶意包 |
| 网络攻击类 | 5 | SSRF、DNS 重绑定 |

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

*威胁库版本: v2.0*
*最后更新: 2026-03-13*
*模式数量: 40+*
