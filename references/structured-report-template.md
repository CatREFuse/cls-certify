# CLS-Certify v2.0 结构化报告模板

> 标准化的安全认证报告输出格式，支持 Markdown 人类阅读和 JSON 机器解析

---

## 报告概览

每份报告包含三个核心部分：
1. **评级内容** - 综合安全评级和评分
2. **敏感风险点列举** - 按严重程度排序的详细风险清单
3. **外部 API 列举** - 所有外部 API 调用及风险评估

---

## JSON Schema

### 完整报告结构

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CLS Security Report",
  "type": "object",
  "required": ["report_metadata", "rating", "risk_summary", "sensitive_risks", "external_apis"],
  "properties": {
    "report_metadata": {
      "type": "object",
      "properties": {
        "skill_name": { "type": "string" },
        "skill_version": { "type": "string" },
        "skill_path": { "type": "string" },
        "scan_timestamp": { "type": "string", "format": "date-time" },
        "scanner_version": { "type": "string" },
        "scan_duration_seconds": { "type": "number" },
        "scan_type": { "enum": ["full", "quick", "static-only"] }
      }
    },
    "rating": {
      "type": "object",
      "properties": {
        "level": { "enum": ["S+", "S", "A", "B", "C", "D"] },
        "score": { "type": "number", "minimum": 0, "maximum": 100 },
        "evaluation": { "type": "string" },
        "source_credibility": { "enum": ["T1", "T2", "T3"] },
        "source_details": {
          "type": "object",
          "properties": {
            "github_stars": { "type": "number" },
            "last_updated": { "type": "string", "format": "date" },
            "maintainer": { "type": "string" },
            "license": { "type": "string" }
          }
        }
      }
    },
    "risk_summary": {
      "type": "object",
      "properties": {
        "critical": { "type": "number" },
        "high": { "type": "number" },
        "medium": { "type": "number" },
        "low": { "type": "number" },
        "info": { "type": "number" },
        "total_findings": { "type": "number" }
      }
    },
    "sensitive_risks": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/risk_finding"
      }
    },
    "external_apis": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/api_endpoint"
      }
    },
    "detailed_results": {
      "type": "object",
      "properties": {
        "static_analysis": { "$ref": "#/definitions/static_analysis_result" },
        "dynamic_analysis": { "$ref": "#/definitions/dynamic_analysis_result" },
        "dependency_audit": { "$ref": "#/definitions/dependency_audit_result" },
        "network_analysis": { "$ref": "#/definitions/network_analysis_result" },
        "privacy_compliance": { "$ref": "#/definitions/privacy_compliance_result" }
      }
    }
  },
  "definitions": {
    "risk_finding": {
      "type": "object",
      "required": ["id", "severity", "category", "title"],
      "properties": {
        "id": { "type": "string" },
        "severity": { "enum": ["critical", "high", "medium", "low", "info"] },
        "category": {
          "enum": [
            "dangerous_function",
            "secret_leak",
            "command_injection",
            "data_exfiltration",
            "vulnerable_dependency",
            "malicious_package",
            "insecure_api",
            "privacy_violation",
            "permission_abuse",
            "code_obfuscation"
          ]
        },
        "title": { "type": "string" },
        "description": { "type": "string" },
        "location": {
          "type": "object",
          "properties": {
            "file": { "type": "string" },
            "line": { "type": "number" },
            "column": { "type": "number" },
            "function": { "type": "string" }
          }
        },
        "evidence": { "type": "string" },
        "impact": { "type": "string" },
        "recommendation": { "type": "string" },
        "references": {
          "type": "array",
          "items": { "type": "string" }
        },
        "false_positive_likely": { "type": "boolean" }
      }
    },
    "api_endpoint": {
      "type": "object",
      "required": ["id", "endpoint", "method", "category"],
      "properties": {
        "id": { "type": "string" },
        "endpoint": { "type": "string" },
        "method": { "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] },
        "category": {
          "enum": [
            "cloud_service",
            "saas_api",
            "analytics",
            "advertising",
            "cdn",
            "unknown",
            "suspicious"
          ]
        },
        "reputation": { "enum": ["trusted", "unknown", "suspicious", "malicious"] },
        "risk_level": { "enum": ["low", "medium", "high", "critical"] },
        "domain": { "type": "string" },
        "ip_address": { "type": "string" },
        "data_types": {
          "type": "array",
          "items": {
            "enum": [
              "user_input",
              "system_info",
              "file_content",
              "credentials",
              "analytics_data",
              "usage_stats"
            ]
          }
        },
        "encryption": {
          "type": "object",
          "properties": {
            "protocol": { "enum": ["https", "http"] },
            "tls_version": { "type": "string" },
            "certificate_valid": { "type": "boolean" }
          }
        },
        "authentication": {
          "type": "object",
          "properties": {
            "required": { "type": "boolean" },
            "type": { "enum": ["api_key", "oauth", "bearer", "none", "unknown"] }
          }
        },
        "calls_count": { "type": "number" },
        "description": { "type": "string" },
        "provider": { "type": "string" }
      }
    }
  }
}
```

---

## Markdown 报告模板

```markdown
# CLS 安全认证报告 v2.0

## 📊 执行摘要

| 项目 | 内容 |
|-----|------|
| **Skill 名称** | {skill_name} |
| **版本** | {version} |
| **来源** | {source_path} |
| **扫描时间** | {timestamp} |
| **扫描耗时** | {duration}s |

---

## 🛡️ 评级内容

### 综合评级

**评级: {S+|S|A|B|C|D}** {rating_icon}

**安全评分: {score}/100**

**评价**: {evaluation_summary}

### 来源可信度

- **来源等级**: {T1/T2/T3} - {source_description}
- **GitHub Stars**: {stars} ⭐
- **最后更新**: {last_updated}
- **维护者**: {maintainer}
- **许可证**: {license}

### 风险统计

| 严重程度 | 数量 | 图标 |
|---------|------|------|
| 🔴 Critical | {count} | {progress_bar} |
| 🟠 High | {count} | {progress_bar} |
| 🟡 Medium | {count} | {progress_bar} |
| 🟢 Low | {count} | {progress_bar} |
| 🔵 Info | {count} | {progress_bar} |
| **总计** | **{total}** | |

---

## ⚠️ 敏感风险点列举

### 🔴 Critical 风险 ({count})

| ID | 风险类型 | 位置 | 描述 | 建议 |
|---|---------|------|------|------|
| {id} | {category} | {file}:{line} | {brief} | {fix_hint} |

**详细说明:**

#### {finding_id}: {finding_title}

- **严重程度**: 🔴 Critical
- **风险类别**: {category}
- **发现位置**: `{file}:{line}:{column}`
- **相关函数**: `{function_name}`

**风险描述:**
{detailed_description}

**证据代码:**
```{language}
{evidence_code}
```

**潜在影响:**
{impact_analysis}

**修复建议:**
{recommendation}

**参考链接:**
- {reference_link_1}
- {reference_link_2}

---

### 🟠 High 风险 ({count})

[同上格式...]

---

### 🟡 Medium 风险 ({count})

[同上格式...]

---

## 🌐 外部 API 列举

### API 调用统计

| 类别 | 数量 | 风险分布 |
|-----|------|---------|
| 云服务 API | {count} | 🟢 {low} 🟡 {medium} 🔴 {high} |
| SaaS API | {count} | 🟢 {low} 🟡 {medium} 🔴 {high} |
| 分析监控 | {count} | 🟢 {low} 🟡 {medium} 🔴 {high} |
| 广告追踪 | {count} | 🟢 {low} 🟡 {medium} 🔴 {high} |
| 未分类 | {count} | 🟢 {low} 🟡 {medium} 🔴 {high} |

### 详细 API 清单

#### 可信 API ({count})

| 端点 | 方法 | 类别 | 提供商 | 数据传输 | 加密 |
|-----|------|------|--------|---------|------|
| `{endpoint}` | {method} | {category} | {provider} | {data_types} | {encryption} |

#### 需要关注 API ({count})

| 端点 | 方法 | 风险等级 | 原因 | 建议 |
|-----|------|---------|------|------|
| `{endpoint}` | {method} | {risk} | {reason} | {recommendation} |

#### 可疑 API ({count})

| 端点 | 方法 | 风险等级 | 发现的问题 |
|-----|------|---------|-----------|
| `{endpoint}` | {method} | 🔴 Critical | {issues} |

---

## 🔍 详细检测结果

### 1. 静态代码分析

**状态**: {✅ 通过 / ⚠️ 警告 / ❌ 危险}

- 扫描文件数: {count}
- 代码行数: {lines}
- 发现漏洞: {vulnerabilities}

**发现详情:**
[静态分析结果...]

### 2. 动态行为分析

**状态**: {✅ 通过 / ⚠️ 警告 / ❌ 危险}

**文件系统访问:**
| 操作 | 路径 | 风险 |
|-----|------|------|
| {operation} | `{path}` | {risk} |

**网络请求:**
| 目标 | 方法 | 数据类型 | 风险 |
|-----|------|---------|------|
| {target} | {method} | {data} | {risk} |

### 3. 依赖审计

**依赖统计:**
- 直接依赖: {count}
- 传递依赖: {count}
- 总依赖数: {count}

**漏洞依赖:**
| 包名 | 版本 | CVE | 严重程度 | 修复版本 |
|-----|------|-----|---------|---------|
| {package} | {version} | {cve} | {severity} | {fixed} |

### 4. 隐私合规

**GDPR 合规**: {✅ / ⚠️ / ❌}

| 检查项 | 状态 | 说明 |
|--------|------|------|
| 数据使用目的明确 | {status} | {note} |
| 用户同意机制 | {status} | {note} |
| 数据删除权利 | {status} | {note} |

---

## 💡 使用建议

### 推荐使用场景

- ✅ {scenario_1}
- ✅ {scenario_2}

### 安全使用指南

1. **{建议标题}**:
   {建议内容}

2. **{建议标题}**:
   {建议内容}

### 不适用场景

- ❌ {不适用场景}

---

## 📝 改进建议

若要提升到 {target_rating} 级，建议:

1. {improvement_1}
2. {improvement_2}
3. {improvement_3}

---

*报告生成时间: {timestamp}*
*CLS-Certify 版本: v2.0*
*扫描模式: {scan_mode}*
```

---

## 示例报告

### 示例 1: A 级 Skill

```json
{
  "report_metadata": {
    "skill_name": "pdf-processor",
    "skill_version": "1.2.0",
    "skill_path": "~/.claude/skills/pdf-processor",
    "scan_timestamp": "2026-03-13T10:30:00Z",
    "scanner_version": "2.0.0",
    "scan_duration_seconds": 32
  },
  "rating": {
    "level": "A",
    "score": 78,
    "evaluation": "标准安全级别，代码规范，依赖可靠，可放心使用",
    "source_credibility": "T2",
    "source_details": {
      "github_stars": 450,
      "last_updated": "2026-02-15",
      "maintainer": "pdf-tools-org",
      "license": "MIT"
    }
  },
  "risk_summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 5,
    "info": 2,
    "total_findings": 11
  },
  "sensitive_risks": [
    {
      "id": "RISK-001",
      "severity": "high",
      "category": "insecure_api",
      "title": "使用 HTTP 传输 PDF 内容",
      "description": "检测到向第三方服务发送 PDF 内容时未使用 HTTPS 加密",
      "location": {
        "file": "src/uploader.js",
        "line": 45,
        "column": 12
      },
      "evidence": "fetch('http://api.example.com/upload', {body: pdfContent})",
      "impact": "PDF 内容可能在传输过程中被截获",
      "recommendation": "将 API 端点改为 HTTPS",
      "false_positive_likely": false
    }
  ],
  "external_apis": [
    {
      "id": "API-001",
      "endpoint": "https://api.openai.com/v1/chat/completions",
      "method": "POST",
      "category": "cloud_service",
      "reputation": "trusted",
      "risk_level": "low",
      "domain": "api.openai.com",
      "data_types": ["user_input"],
      "encryption": {
        "protocol": "https",
        "tls_version": "1.3",
        "certificate_valid": true
      },
      "authentication": {
        "required": true,
        "type": "bearer"
      },
      "calls_count": 5,
      "description": "OpenAI API for text extraction",
      "provider": "OpenAI"
    },
    {
      "id": "API-002",
      "endpoint": "http://api.example.com/upload",
      "method": "POST",
      "category": "unknown",
      "reputation": "unknown",
      "risk_level": "high",
      "domain": "api.example.com",
      "data_types": ["file_content"],
      "encryption": {
        "protocol": "http",
        "tls_version": null,
        "certificate_valid": false
      },
      "authentication": {
        "required": false,
        "type": "none"
      },
      "calls_count": 1,
      "description": "PDF upload endpoint (unencrypted)",
      "provider": "Unknown"
    }
  ]
}
```

---

## 报告输出配置

### 输出格式选项

```yaml
output_formats:
  - format: markdown
    extension: .md
    description: 人类可读格式

  - format: json
    extension: .json
    description: 机器解析格式

  - format: sarif
    extension: .sarif
    description: SARIF 标准格式（兼容 GitHub/CodeQL）

  - format: html
    extension: .html
    description: 网页可视化格式
```

### 输出控制

```yaml
report_configuration:
  # 风险级别过滤
  min_severity: medium  # 只报告 medium 及以上

  # 详细信息级别
  detail_level: full    # full | summary | minimal

  # 包含的章节
  sections:
    - metadata
    - rating
    - risk_summary
    - sensitive_risks
    - external_apis
    - detailed_results
    - recommendations

  # 代码片段显示
  show_evidence: true
  max_evidence_lines: 10

  # API 详细程度
  api_detail_level: full  # full | basic
```

---

*模板版本: v2.0*
*最后更新: 2026-03-13*
