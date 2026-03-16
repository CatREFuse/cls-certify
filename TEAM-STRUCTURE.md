# CLS-Certify v2.0 团队分工文档

> 基于 skill-creator 的能力，将安全检查拆分为 6 个专业维度，每个维度由专门的子团队负责

---

## 团队架构

```
                    ┌─────────────────────────────────────┐
                    │         CLS-Certify Core Team        │
                    │    (核心协调、报告生成、评级判定)      │
                    └──────────────┬──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│  静态分析团队  │        │  动态分析团队  │        │  依赖审计团队  │
│  Static Team  │        │ Dynamic Team  │        │Dependency Team│
└───────┬───────┘        └───────┬───────┘        └───────┬───────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│  网络分析团队  │        │  隐私合规团队  │        │  威胁情报团队  │
│  Network Team │        │  Privacy Team │        │  Threat Team  │
└───────────────┘        └───────────────┘        └───────────────┘
```

---

## 各团队职责与交付物

### 🏛️ 1. Core Team（核心团队）

**负责人**: 项目主架构师
**核心职责**:
- 协调各子团队的检测结果
- 综合评级判定（S+/S/A/B/C/D）
- 生成最终结构化报告
- 版本管理与发布

**交付物**:
- `SKILL.md` - 主技能文档
- `core/orchestrator.js` - 检测流程编排器
- `core/report-generator.js` - 报告生成器
- `core/rating-engine.js` - 评级引擎

**输入接口**:
```javascript
{
  "staticResults": {...},      // 来自静态分析团队
  "dynamicResults": {...},     // 来自动态分析团队
  "dependencyResults": {...},  // 来自依赖审计团队
  "networkResults": {...},     // 来自网络分析团队
  "privacyResults": {...},     // 来自隐私合规团队
  "threatResults": {...}       // 来自威胁情报团队
}
```

**输出接口**:
```javascript
{
  "rating": "S+|S|A|B|C|D",
  "score": 85,
  "structuredReport": {...}  // 结构化报告
}
```

---

### 🔍 2. Static Analysis Team（静态分析团队）

**负责人**: 代码安全专家
**核心职责**:
- AST 语义分析
- 敏感信息泄露检测
- 危险函数/命令识别
- 威胁模式匹配（40+ 模式）

**检测维度**:

| 检查项 | 检测模式 | 风险等级 | 负责人 |
|-------|---------|:-------:|--------|
| 2.1 危险函数调用 | `eval()`, `exec()`, `Function()` | 🔴 高 | 代码分析师 A |
| 2.2 敏感信息泄露 | API Key、Token、密码硬编码 | 🔴 高 | 代码分析师 B |
| 2.3 危险命令检测 | `rm -rf`, `chmod 777`, `mkfs` | 🔴 高 | 代码分析师 C |
| 2.4 威胁模式匹配 | 提示注入、命令注入、SSRF | 🟠 中高 | 威胁建模师 |
| 2.5 代码混淆检测 | 高熵字符串、Unicode 转义 | 🟠 中高 | 逆向工程师 |

**交付物**:
- `analyzers/ast-parser.js` - AST 解析器
- `analyzers/secret-detector.js` - 敏感信息检测器
- `analyzers/command-scanner.js` - 危险命令扫描器
- `patterns/threat-patterns.json` - 40+ 威胁模式库
- `patterns/dangerous-commands.json` - 危险命令清单

**输出格式**:
```json
{
  "staticAnalysis": {
    "status": "passed|warning|danger",
    "findings": [
      {
        "id": "SEC-001",
        "severity": "critical|high|medium|low",
        "category": "dangerous_function|secret_leak|command_injection",
        "file": "index.js",
        "line": 42,
        "code": "eval(userInput)",
        "description": "使用 eval 执行用户输入",
        "recommendation": "使用 JSON.parse 替代 eval"
      }
    ],
    "statistics": {
      "totalFiles": 15,
      "totalLines": 1200,
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 3
    }
  }
}
```

---

### 🔄 3. Dynamic Analysis Team（动态分析团队）

**负责人**: 运行时安全专家
**核心职责**:
- 沙箱环境执行监控
- 运行时行为分析
- 输入验证测试
- 异常行为检测

**检测维度**:

| 检查项 | 监控目标 | 风险等级 | 负责人 |
|-------|---------|:-------:|--------|
| 3.1 文件系统访问 | 敏感目录读写 | 🔴 高 | 系统安全工程师 |
| 3.2 网络请求监控 | 外发 HTTP/HTTPS | 🟠 中高 | 网络安全工程师 |
| 3.3 子进程创建 | 系统命令执行 | 🔴 高 | 系统安全工程师 |
| 3.4 输入验证测试 | 提示注入、越权访问 | 🔴 高 | 渗透测试工程师 |
| 3.5 资源使用监控 | CPU/内存/磁盘占用 | 🟢 低 | 性能工程师 |

**交付物**:
- `sandbox/sandbox-runtime.js` - 沙箱运行时
- `monitors/fs-monitor.js` - 文件系统监控器
- `monitors/network-monitor.js` - 网络监控器
- `monitors/process-monitor.js` - 进程监控器
- `tests/injection-tests.json` - 注入测试用例

**输出格式**:
```json
{
  "dynamicAnalysis": {
    "status": "passed|warning|danger",
    "behaviors": [
      {
        "type": "file_access|network_request|process_spawn",
        "target": "/etc/passwd",
        "operation": "read",
        "riskLevel": "high",
        "timestamp": "2026-03-13T10:00:00Z"
      }
    ],
    "testResults": {
      "promptInjection": {"passed": 8, "failed": 2},
      "inputValidation": {"passed": 10, "failed": 0},
      "privilegeEscalation": {"passed": 5, "failed": 0}
    }
  }
}
```

---

### 📦 4. Dependency Audit Team（依赖审计团队）

**负责人**: 供应链安全专家
**核心职责**:
- 第三方依赖安全审计
- CVE 漏洞扫描
- 恶意包检测
- 版本锁定检查

**检测维度**:

| 检查项 | 检查内容 | 风险等级 | 负责人 |
|-------|---------|:-------:|--------|
| 5.1 已知漏洞 | CVE 数据库匹配 | 🔴 高 | 漏洞分析师 |
| 5.2 可疑包检测 | typosquatting 检测 | 🔴 高 | 供应链安全分析师 |
| 5.3 废弃包检测 | 长期未维护依赖 | 🟡 中 | 维护性分析师 |
| 5.4 权限要求 | 过度权限申请 | 🟠 中高 | 权限审计师 |
| 5.5 依赖树分析 | 依赖深度和数量 | 🟢 低 | 架构师 |

**交付物**:
- `auditors/cve-scanner.js` - CVE 扫描器
- `auditors/typosquat-detector.js` - 拼写劫持检测器
- `auditors/license-checker.js` - 许可证检查器
- `databases/cve-cache.json` - CVE 缓存数据库

**输出格式**:
```json
{
  "dependencyAudit": {
    "status": "passed|warning|danger",
    "dependencies": {
      "total": 45,
      "direct": 12,
      "transitive": 33
    },
    "vulnerabilities": [
      {
        "package": "lodash",
        "version": "4.17.20",
        "severity": "high",
        "cve": "CVE-2021-23337",
        "description": "命令注入漏洞",
        "fixedIn": "4.17.21"
      }
    ],
    "suspiciousPackages": [
        {
          "name": "express-js",
          "reason": "可能的 typosquatting (express)",
          "risk": "high"
        }
    ],
    "outdatedPackages": 8
  }
}
```

---

### 🌐 5. Network Analysis Team（网络分析团队）

**负责人**: 网络安全专家
**核心职责**:
- 出站连接分析
- 数据传输监控
- 第三方 API 审计
- 域名信誉检查

**检测维度**:

| 检查项 | 检查内容 | 风险等级 | 负责人 |
|-------|---------|:-------:|--------|
| 4.1 出站连接分析 | 外部域名/IP 连接 | 🟡 中 | 网络分析师 |
| 4.2 数据传输监控 | POST/PUT 请求体 | 🟠 中高 | 数据安全分析师 |
| 4.3 第三方 API 审计 | 引用的外部 API | 🟡 中 | API 审计师 |
| 4.4 DNS 查询分析 | 异常域名解析 | 🟡 中 | 威胁情报分析师 |
| 4.5 TLS/SSL 检查 | 加密通信配置 | 🟢 低 | 加密专家 |

**API 分类清单**:

| 类别 | 示例 | 风险等级 |
|-----|------|:-------:|
| 官方云服务 | AWS, Azure, GCP API | 🟢 低 |
| 知名 SaaS | Slack, Notion, GitHub API | 🟢 低 |
| 分析监控 | Google Analytics, Mixpanel | 🟡 中 |
| 广告追踪 | Facebook Pixel, AdMob | 🟠 中高 |
| 未知第三方 | 未分类域名 | 🔴 高 |

**交付物**:
- `analyzers/traffic-analyzer.js` - 流量分析器
- `analyzers/api-classifier.js` - API 分类器
- `analyzers/domain-reputation.js` - 域名信誉检查器
- `databases/known-apis.json` - 已知 API 清单

**输出格式**:
```json
{
  "networkAnalysis": {
    "status": "passed|warning|danger",
    "externalApis": [
      {
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "method": "POST",
        "category": "ai_service",
        "reputation": "trusted",
        "riskLevel": "low",
        "dataType": "user_prompt",
        "description": "OpenAI GPT API"
      },
      {
        "endpoint": "https://suspicious-domain.com/collect",
        "method": "POST",
        "category": "unknown",
        "reputation": "unknown",
        "riskLevel": "high",
        "dataType": "unknown",
        "description": "未分类的数据收集端点"
      }
    ],
    "statistics": {
      "totalRequests": 15,
      "trustedApis": 12,
      "suspiciousApis": 2,
      "unknownApis": 1
    }
  }
}
```

---

### 🔒 6. Privacy & Compliance Team（隐私合规团队）

**负责人**: 隐私合规专家
**核心职责**:
- 数据隐私合规检查
- 权限申请审查
- 隐私政策分析
- 数据最小化评估

**检测维度**:

| 检查项 | 检查内容 | 风险等级 | 负责人 |
|-------|---------|:-------:|--------|
| 6.1 数据收集审查 | 超出功能范围的数据收集 | 🔴 高 | 隐私审计师 |
| 6.2 权限申请审查 | 过度权限申请 | 🟠 中高 | 权限分析师 |
| 6.3 隐私政策 | 是否明确告知数据使用 | 🟡 中 | 合规专家 |
| 6.4 数据存储 | 敏感数据加密存储 | 🟠 中高 | 数据安全工程师 |
| 6.5 用户控制 | 数据删除/导出机制 | 🟡 中 | 产品经理 |

**交付物**:
- `auditors/privacy-auditor.js` - 隐私审计器
- `auditors/permission-analyzer.js` - 权限分析器
- `checklists/gdpr-checklist.json` - GDPR 检查清单
- `checklists/ccpa-checklist.json` - CCPA 检查清单

**输出格式**:
```json
{
  "privacyCompliance": {
    "status": "passed|warning|danger",
    "dataCollection": {
      "types": ["user_input", "system_info"],
      "purposes": ["functionality", "analytics"],
      "consentRequired": true,
      "consentObtained": true
    },
    "permissions": [
      {
        "permission": "filesystem.read",
        "required": true,
        "justified": true,
        "risk": "low"
      },
      {
        "permission": "network.all",
        "required": false,
        "justified": false,
        "risk": "high"
      }
    ],
    "compliance": {
      "gdpr": {"compliant": true, "issues": []},
      "ccpa": {"compliant": false, "issues": ["缺少数据删除机制"]}
    }
  }
}
```

---

### 🛡️ 7. Threat Intelligence Team（威胁情报团队）

**负责人**: 威胁情报分析师
**核心职责**:
- 威胁模式情报收集
- 恶意代码特征库维护
- 行为模式分析
- 情报关联分析

**交付物**:
- `intel/malware-signatures.json` - 恶意代码签名库
- `intel/suspicious-patterns.json` - 可疑行为模式库
- `intel/threat-actors.json` - 威胁行为者情报
- `intel/ioc-feed.json` - IoC 情报源

---

## 团队协作流程

### 检测流程

```
┌─────────────┐
│  接收 Skill  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ 前置检查     │ ──→ Core Team
│ (来源分级)   │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────┐
│          并行检测阶段                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ 静态分析 │ │ 动态分析 │ │ 依赖审计 │  │
│  │  (5min) │ │ (10min) │ │ (3min)  │  │
│  └────┬────┘ └────┬────┘ └────┬────┘  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ 网络分析 │ │ 隐私合规 │ │ 威胁情报 │  │
│  │  (2min) │ │  (3min) │ │ (1min)  │  │
│  └────┬────┘ └────┬────┘ └────┬────┘  │
└───────┼──────────┼──────────┼─────────┘
        │          │          │
        └──────────┼──────────┘
                   ▼
        ┌──────────────────┐
        │   结果聚合        │ ──→ Core Team
        │  (评级判定)       │
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │   生成报告        │ ──→ Core Team
        │  (结构化输出)     │
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │   保存/展示报告   │
        └──────────────────┘
```

### 协作接口

```yaml
# 团队间通信协议
version: "2.0"

message_formats:
  request:
    skill_path: string
    skill_name: string
    source_level: T1|T2|T3
    priority: normal|high|urgent

  response:
    team_id: string
    status: success|partial|failed
    findings: array
    confidence: 0-100
    processing_time: number

error_handling:
  timeout: 30s
  retry: 3
  fallback: continue_with_warning
```

---

## 版本管理

### 版本发布计划

| 版本 | 目标 | 主要功能 | 预计发布 |
|-----|------|---------|---------|
| v2.0 | 架构升级 | 团队化分工、结构化报告 | 2026-03 |
| v2.1 | 性能优化 | 并行检测、缓存优化 | 2026-04 |
| v2.2 | 智能增强 | AI 辅助分析、误报降低 | 2026-05 |
| v2.5 | 生态扩展 | 支持更多 Skill 类型 | 2026-06 |

---

## 质量保证

### 代码审查要求

- 所有检测代码必须通过单元测试
- 误报率 < 5%
- 漏报率 < 1%
- 性能：大型 Skill (< 10MB) 检测时间 < 30s

### 持续集成

```yaml
ci_pipeline:
  - lint
  - unit_test
  - integration_test
  - performance_test
  - security_scan
  - report_validation
```

---

*文档版本: v1.0*
*最后更新: 2026-03-13*
*维护团队: CLS-Certify Core Team*
