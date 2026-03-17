# CLS-Certify HTML 报告数据协议 v1.0

> 定义扫描结果（Markdown）与 HTML 模板渲染之间的结构化数据格式

---

## 概述

本协议使用 **YAML frontmatter + Markdown body** 作为中间数据层：
- Frontmatter：标量值和固定结构（元数据、评级、雷达、合规）
- Body：变长列表数据（标签、摘要、API、发现、建议）

阶段 4 输出此格式 → 阶段 5 解析并注入 HTML 模板。

---

## 完整数据格式

```markdown
---
# ═══ 报告元数据 ═══
report_id: "CLS-2026-0314-A7F3"
report_date: "2026 年 3 月 14 日 10:32:18 CST"
scanner_version: "CLS-Certify v2.0"
scan_mode: "Full Scan"

# ═══ 技能信息 ═══
skill_name: "pdf-processor"
skill_version: "v1.2.0"
skill_path: "~/.claude/skills/pdf-processor"
maintainer: "pdf-tools-org"
license: "MIT"
trust_level: "T2"
trust_level_text: "社区来源"
scan_duration: "32.4s"
code_stats: "1,247 lines · 8 files"

# ═══ 评级 ═══
grade: "A"
score: 78
evaluation: "标准安全级别。代码结构规范，无高危后门或数据外泄行为。"
stamp_color: "green"
total_findings: 11

# ═══ Skill 分类 ═══
skill_tier: "T-LITE"
skill_tier_name: "轻量代码 Skill"
scan_strategy: "auto"
skipped_dimensions: []

# ═══ 六维雷达 ═══
radar:
  - name: "静态代码分析"
    short: "静态分析"
    score: 72
    status: "warn"
    detail: "发现 4 项"
  - name: "动态行为分析"
    short: "动态分析"
    score: 90
    status: "pass"
    detail: "行为正常"
  - name: "依赖审计"
    short: "依赖审计"
    score: 85
    status: "pass"
    detail: "12 依赖"
  - name: "网络流量分析"
    short: "网络分析"
    score: 65
    status: "warn"
    detail: "HTTP 明文"
  - name: "隐私合规"
    short: "隐私合规"
    score: 82
    status: "pass"
    detail: "GDPR 基本合规"
  - name: "威胁情报"
    short: "威胁情报"
    score: 95
    status: "pass"
    detail: "无已知威胁"

# ═══ 合规检查 ═══
compliance:
  - text: "数据使用目的明确声明"
    status: "pass"
  - text: "无隐蔽数据收集行为"
    status: "pass"
  - text: "缺少用户数据删除接口"
    status: "warn"
  - text: "无跨 Skill 数据共享"
    status: "pass"
  - text: "无 Agent 配置注入行为"
    status: "pass"
  - text: "无持久化或提权操作"
    status: "pass"

# ═══ 页脚 ═══
sample_hash: "sha256:a7f3c9...e2d1"
disclaimer: "认证结果不代表运行时绝对安全，请配合 CocoLoop Safe 客户端使用。"
---

## pattern_tags

- safe: 无后门程序
- safe: 无数据外泄
- safe: 无 Agent 注入
- safe: 依赖安全
- warning: HTTP 明文传输
- warning: 路径遍历风险
- warning: 硬编码密钥
- info: 缺少 CSP 头

## summary

1. 未检测到后门、数据外泄或 Agent 配置注入等严重威胁，核心安全项全部通过
2. 存在 1 处 HTTP 明文传输（高危），PDF 内容在传输中可能被截获，建议升级为 HTTPS
3. 发现 1 处硬编码 API Key、1 处路径遍历风险和 1 处缺失 CSP 响应头（中危），需修复
4. 依赖包安全，12 个依赖均无已知 CVE 漏洞，威胁情报未匹配恶意模式
5. 整体符合生产环境使用标准，修复上述中高危问题后可提升至 S 级

## external_apis

| endpoint | method | reputation | encryption | data_types | provider |
|----------|--------|------------|------------|------------|----------|
| api.openai.com/v1/chat/completions | POST | trusted | TLS 1.3 | user_input | OpenAI |
| api.logrocket.com/v1/events | POST | trusted | TLS 1.2 | analytics_data | LogRocket |
| api.example.com/upload | POST | unknown | HTTP | file_content | Unknown |

## findings

### RISK-001
- severity: high
- category: insecure_api
- title: 使用 HTTP 明文传输 PDF 内容
- location: src/uploader.js:45:12
- function: uploadPdf()
- description: 检测到向第三方服务发送 PDF 文件内容时使用 HTTP 而非 HTTPS，传输数据未加密。PDF 可能包含用户敏感信息，在传输过程中存在被中间人攻击截获的风险。
- evidence: |
    ```javascript
    43  async function uploadPdf(content, metadata) {
    44    const endpoint = config.uploadUrl;
    45    const res = await fetch('http://api.example.com/upload', {  // ← 高亮行
    46      method: 'POST',
    47      body: pdfContent, // ← 明文传输文件内容
    48    });
    ```
- recommendation: 将 API 端点从 http:// 改为 https://，并验证服务端 TLS 证书有效性。建议启用证书钉扎 (Certificate Pinning)。

### RISK-002
- severity: medium
- category: command_injection
- title: 用户输入未经过滤直接拼入文件路径
- location: src/parser.js:112:8
- function: parsePdf()
- description: 用户提供的文件名未经清洗即拼入文件路径，可能存在路径遍历 (Path Traversal) 风险。
- evidence: |
    ```javascript
    112  const filePath = `./uploads/${userFilename}`;  // ← 高亮行
    113  const data = fs.readFileSync(filePath);
    ```
- recommendation: 使用 path.resolve() 规范化路径后，校验是否仍在预期目录内（白名单校验）。

## recommendations

### 1. 修复 HTTP 明文传输
将 api.example.com 端点切换为 HTTPS，预计提升评分 +8 分

### 2. 移除硬编码 API Key
迁移至环境变量或密钥管理服务，预计提升评分 +5 分

### 3. 增加路径遍历防护
对用户输入的文件名进行白名单校验和路径规范化，预计提升评分 +4 分

### 4. 补充数据删除 API
实现 GDPR 数据主体删除权接口，预计提升评分 +3 分
```

---

## 字段说明

### Frontmatter 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `report_id` | string | ✓ | 报告唯一编号，格式 `CLS-{日期}-{哈希}` |
| `report_date` | string | ✓ | 扫描完成时间 |
| `scanner_version` | string | ✓ | 扫描器版本 |
| `scan_mode` | string | ✓ | Full Scan / Quick Scan / Static Only |
| `skill_name` | string | ✓ | 被检技能名称 |
| `skill_version` | string | ✓ | 被检技能版本 |
| `skill_path` | string | ✓ | 技能文件路径 |
| `maintainer` | string | ✓ | 维护者 |
| `license` | string | ✓ | 许可证 |
| `trust_level` | string | ✓ | T1/T2/T3 |
| `trust_level_text` | string | ✓ | 可信来源/社区来源/未知来源 |
| `scan_duration` | string | ✓ | 扫描耗时 |
| `code_stats` | string | ✓ | 代码行数和文件数 |
| `grade` | string | ✓ | S+/S/A/B/C/D |
| `score` | number | ✓ | 0-100 |
| `evaluation` | string | ✓ | 评估总结文本，可包含 HTML strong 标签 |
| `stamp_color` | string | ✓ | green（S+/S/A/B）或 red（C/D） |
| `total_findings` | number | ✓ | 发现总数 |
| `skill_tier` | string | ✓ | T-MD/T-LITE/T-REF/T-HEAVY/T-FULL/T-QUICK |
| `skill_tier_name` | string | ✓ | 分类名称（纯 Markdown/轻量代码/引用代码/大型代码） |
| `scan_strategy` | string | ✓ | auto/full/quick |
| `skipped_dimensions` | list | ✓ | 被跳过的维度列表（空列表表示全部执行） |
| `radar` | list | ✓ | 6 个维度，每个含 name/short/score/status/detail。被跳过维度 score 为 -1，status 为 "na" |
| `compliance` | list | ✓ | 6 项合规检查，每项含 text/status |
| `sample_hash` | string | ✓ | 被检样本的 SHA256 哈希 |
| `disclaimer` | string | ✓ | 风险免责声明 |

### Body 区块

| 区块 | 格式 | 说明 |
|------|------|------|
| `## pattern_tags` | `- {severity}: {text}` 列表 | severity: safe/warning/danger/info |
| `## summary` | 有序列表 `1. ...` | 3-5 条安全总结 |
| `## external_apis` | Markdown 表格 | 6 列：endpoint/method/reputation/encryption/data_types/provider |
| `## findings` | `### RISK-xxx` 子节 | 每项含 severity/category/title/location/function/description/evidence/recommendation |
| `## recommendations` | `### N. 标题` + 描述 | 改进建议 |

### 状态映射

| status 值 | 图标 | CSS 类 | 颜色 |
|-----------|------|--------|------|
| `pass` | ✓ | `.pass` | green |
| `warn` | ! | `.warn` | yellow |
| `fail` | ✗ | `.fail` | red |
| `na` | — | `.na` | gray |

### 印章颜色映射

| stamp_color | SVG 颜色 | 适用等级 |
|-------------|---------|---------|
| `green` | `#1B7A3D` | S+, S, A, B |
| `red` | `#B22222` | C, D |

---

*协议版本: v1.0*
*最后更新: 2026-03-14*
