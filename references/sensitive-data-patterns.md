# CLS-Certify 敏感数据检测模式库

> 用于识别代码和配置中的敏感信息泄露的检测模式

---

## 1. API 密钥和令牌

### 1.1 OpenAI

```yaml
pattern_name: openai_api_key
severity: critical
confidence: high

patterns:
  - regex: "sk-[a-zA-Z0-9]{48}"
    description: "OpenAI Standard API Key"
    example: "sk-abc123..."

  - regex: "sk-proj-[a-zA-Z0-9]{48,}"
    description: "OpenAI Project API Key"
    example: "sk-proj-abc123..."

  - regex: "sk-test-[a-zA-Z0-9]{48}"
    description: "OpenAI Test API Key"

entropy_check:
  enabled: true
  min_entropy: 4.5
```

### 1.2 GitHub

```yaml
pattern_name: github_tokens
severity: critical
confidence: high

patterns:
  - regex: "ghp_[a-zA-Z0-9]{36}"
    description: "GitHub Personal Access Token"

  - regex: "gho_[a-zA-Z0-9]{36}"
    description: "GitHub OAuth Access Token"

  - regex: "ghu_[a-zA-Z0-9]{36}"
    description: "GitHub User-to-Server Token"

  - regex: "ghs_[a-zA-Z0-9]{36}"
    description: "GitHub Server-to-Server Token"

  - regex: "ghr_[a-zA-Z0-9]{36}"
    description: "GitHub Refresh Token"
```

### 1.3 AWS

```yaml
pattern_name: aws_credentials
severity: critical
confidence: high

patterns:
  - regex: "AKIA[0-9A-Z]{16}"
    description: "AWS Access Key ID"

  - regex: "ASIA[0-9A-Z]{16}"
    description: "AWS Temporary Access Key"

  - regex: "[0-9a-zA-Z/+]{40}"
    context_required: true
    context: "aws_secret|secret.*key|SecretAccessKey"
    description: "AWS Secret Access Key"
```

### 1.4 通用 API 密钥

```yaml
pattern_name: generic_api_keys
severity: high
confidence: medium

patterns:
  - regex: "api[_-]?key\\s*[=:]\\s*['\"][a-zA-Z0-9_\\-]{32,}['\"]"
    description: "Generic API Key"

  - regex: "api[_-]?secret\\s*[=:]\\s*['\"][a-zA-Z0-9_\\-]{32,}['\"]"
    description: "Generic API Secret"

  - regex: "api[_-]?token\\s*[=:]\\s*['\"][a-zA-Z0-9_\\-]{32,}['\"]"
    description: "Generic API Token"

  - regex: "(bearer|token)\\s+[a-zA-Z0-9_\\-\\.]{40,}"
    description: "Bearer Token"

  - regex: "x-api-key\\s*:\\s*[a-zA-Z0-9_\\-]{32,}"
    description: "API Key in Header"
```

---

## 2. 密码和凭证

### 2.1 硬编码密码

```yaml
pattern_name: hardcoded_passwords
severity: critical
confidence: medium

patterns:
  - regex: "password\\s*[=:]\\s*['\"][^'\"]{4,}['\"]"
    description: "Password assignment"
    exclusions:
      - "password = ''"
      - 'password = ""'
      - "password = None"
      - "password = os.environ"
      - "password = getenv"
      - "password = input("
      - "password = getpass("

  - regex: "passwd\\s*[=:]\\s*['\"][^'\"]{4,}['\"]"
    description: "Passwd assignment"

  - regex: "pwd\\s*[=:]\\s*['\"][^'\"]{4,}['\"]"
    description: "Pwd assignment"

  - regex: "pass\\s*[=:]\\s*['\"][^'\"]{4,}['\"]"
    description: "Pass assignment"

  - regex: "secret\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"
    description: "Secret assignment"
    exclusions:
      - "secret_key"
      - "secret_token"
```

### 2.2 数据库连接字符串

```yaml
pattern_name: database_connection_strings
severity: critical
confidence: high

patterns:
  - regex: "mongodb://[^:]+:[^@]+@"
    description: "MongoDB connection with password"

  - regex: "mysql://[^:]+:[^@]+@"
    description: "MySQL connection with password"

  - regex: "postgresql://[^:]+:[^@]+@"
    description: "PostgreSQL connection with password"

  - regex: "redis://:[^@]+@"
    description: "Redis connection with password"

  - regex: "jdbc:[^:]+://[^:]+:[^@]+@"
    description: "JDBC connection with password"
```

---

## 3. 加密密钥

### 3.1 私钥文件

```yaml
pattern_name: private_keys
severity: critical
confidence: high

patterns:
  - regex: "-----BEGIN RSA PRIVATE KEY-----"
    description: "RSA Private Key"

  - regex: "-----BEGIN OPENSSH PRIVATE KEY-----"
    description: "OpenSSH Private Key"

  - regex: "-----BEGIN EC PRIVATE KEY-----"
    description: "ECDSA Private Key"

  - regex: "-----BEGIN DSA PRIVATE KEY-----"
    description: "DSA Private Key"

  - regex: "-----BEGIN PRIVATE KEY-----"
    description: "PKCS#8 Private Key"

  - regex: "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    description: "Encrypted Private Key"

file_extensions:
  - ".pem"
  - ".key"
  - ".p12"
  - ".pfx"
  - ".pkcs12"
  - "id_rsa"
  - "id_dsa"
  - "id_ecdsa"
  - "id_ed25519"
```

### 3.2 API 密钥和密钥

```yaml
pattern_name: cryptographic_keys
severity: critical
confidence: high

patterns:
  - regex: "[a-f0-9]{64}"
    context_required: true
    context: "key|secret|private|aes|hmac"
    description: "Possible 256-bit key"

  - regex: "[a-f0-9]{128}"
    context_required: true
    context: "key|secret|private|aes"
    description: "Possible 512-bit key"
```

---

## 4. 云服务商凭证

### 4.1 阿里云

```yaml
pattern_name: alicloud_credentials
severity: critical
confidence: high

patterns:
  - regex: "LTAI[a-zA-Z0-9]{16}"
    description: "Alibaba Cloud Access Key ID"

  - regex: "[a-zA-Z0-9]{30}"
    context_required: true
    context: "aliyun|alicloud|access.*secret"
    description: "Alibaba Cloud Access Key Secret"
```

### 4.2 腾讯云

```yaml
pattern_name: tencent_cloud_credentials
severity: critical
confidence: high

patterns:
  - regex: "AKID[a-zA-Z0-9]{32}"
    description: "Tencent Cloud Secret ID"

  - regex: "[a-zA-Z0-9]{32}"
    context_required: true
    context: "tencent.*secret|qcloud.*secret"
    description: "Tencent Cloud Secret Key"
```

### 4.3 Google Cloud

```yaml
pattern_name: gcp_credentials
severity: critical
confidence: high

patterns:
  - regex: "[a-z0-9_-]{25,}\\.apps\\.googleusercontent\\.com"
    description: "Google OAuth Client ID"

  - regex: "AIza[0-9A-Za-z_-]{35}"
    description: "Google API Key"
```

### 4.4 Azure

```yaml
pattern_name: azure_credentials
severity: critical
confidence: high

patterns:
  - regex: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    context_required: true
    context: "azure|tenant.*id|client.*id"
    description: "Azure Tenant/Client ID"
```

---

## 5. 认证令牌

### 5.1 JWT

```yaml
pattern_name: jwt_tokens
severity: high
confidence: medium

patterns:
  - regex: "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
    description: "JSON Web Token"

validation:
  - check_structure: true
  - decode_payload: true
  - check_expiration: true
```

### 5.2 会话令牌

```yaml
pattern_name: session_tokens
severity: high
confidence: medium

patterns:
  - regex: "session[_-]?id\\s*[=:]\\s*['\"][a-zA-Z0-9]{16,}['\"]"
    description: "Session ID"

  - regex: "auth[_-]?token\\s*[=:]\\s*['\"][a-zA-Z0-9]{16,}['\"]"
    description: "Auth Token"

  - regex: "csrf[_-]?token\\s*[=:]\\s*['\"][a-zA-Z0-9]{16,}['\"]"
    description: "CSRF Token"
```

---

## 6. 个人信息 (PII)

### 6.1 邮箱地址

```yaml
pattern_name: email_addresses
severity: medium
confidence: high

patterns:
  - regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    description: "Email address"
    exclusions:
      - "example.com"
      - "test.com"
      - "localhost"
```

### 6.2 电话号码

```yaml
pattern_name: phone_numbers
severity: medium
confidence: medium

patterns:
  - regex: "\\+?[1-9]\\d{1,14}"
    description: "E.164 phone number"

  - regex: "\\(\\d{3}\\)\\s*\\d{3}[-\\s]?\\d{4}"
    description: "US phone number"
```

### 6.3 IP 地址

```yaml
pattern_name: ip_addresses
severity: low
confidence: high

patterns:
  - regex: "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
    description: "IPv4 address"
    exclusions:
      - "127.0.0.1"
      - "0.0.0.0"
      - "255.255.255.255"
      - "192.168.x.x"
      - "10.x.x.x"

  - regex: "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    description: "IPv6 address"
```

---

## 7. 配置文件敏感信息

### 7.1 环境变量文件

```yaml
pattern_name: env_file_secrets
severity: high
confidence: high

file_patterns:
  - ".env"
  - ".env.local"
  - ".env.production"
  - ".env.development"

patterns:
  - regex: "^[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS)=[^'\"]*$"
    description: "Potential secret in env file"
```

### 7.2 YAML/JSON 配置

```yaml
pattern_name: config_file_secrets
severity: high
confidence: medium

file_patterns:
  - "*.yaml"
  - "*.yml"
  - "*.json"

patterns:
  - regex: "(password|secret|key|token):\\s*[^'\"\\s{\\[]+[\\s\\n]"
    description: "Unquoted secret in config"
    exclusions:
      - "null"
      - "~"
      - ""
```

---

## 8. 检测配置

### 全局配置

```yaml
detection_config:
  # 熵值检测（识别随机字符串）
  entropy_detection:
    enabled: true
    min_entropy: 4.5
    min_length: 20

  # 上下文检查
  context_analysis:
    enabled: true
    window_size: 50  # 字符

  # 误报过滤
  false_positive_filter:
    enabled: true
    excluded_patterns:
      - "example"
      - "sample"
      - "test"
      - "dummy"
      - "placeholder"
      - "your_key_here"

  # 文件排除
  excluded_files:
    - "*.test.js"
    - "*.spec.js"
    - "*test*.py"
    - "__tests__/*"
    - "*.md"
    - "CHANGELOG*"
    - "LICENSE*"

  # 最大检测结果
  max_findings_per_type: 10
```

### 严重性映射

| 类型 | 默认严重性 |
|-----|----------|
| API Key | Critical |
| Password | Critical |
| Private Key | Critical |
| Database Connection String | Critical |
| OAuth Token | High |
| Session Token | High |
| JWT | High |
| Email | Medium |
| IP Address | Low |

---

*模式库版本: v2.0*
*最后更新: 2026-03-13*
*检测模式数: 50+*
