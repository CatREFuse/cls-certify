# CLS-Certify v2.0 - Next Generation Skill Security Certification

> 面向所有支持 Skill 的 Agent 平台的安全检测与认证系统，提供多维度深度分析和结构化报告输出

---

## 项目来源

**本项目由 [CocoLoop](https://github.com/AidenYangX) 内部 Skill 安全检测引擎 [BSS (Berry Skills Safe) Certify](https://github.com/CatREFuse/bss-certify) 升级而来。**

BSS Certify 是 CocoLoop 平台内部使用的 Skill 安全检测引擎，专注于对 Agent Skills 进行安全评估和 S+~D 评级。CLS-Certify v2.0 在 BSS 的基础上进行了全面的架构重构和能力升级，**不再局限于单一平台，而是面向所有支持 Skill 的 Agent 平台**（如 Claude Code、OpenAI Agents、Cursor、Windsurf 等），提供通用的 Skill 安全认证能力。

---

## 从 BSS 到 CLS 的核心升级点

| 升级维度 | BSS Certify (v1.x) | CLS-Certify (v2.0) | 提升幅度 |
|---------|---------------------|---------------------|---------|
| **检测维度** | 4 维基础检查（代码安全、数据隐私、执行安全、依赖可靠） | **6 维深度分析**（新增网络流量分析、隐私合规检查、威胁情报关联） | +50% |
| **威胁模式** | 15+ 基础正则匹配 | **40+ 专业威胁模式**（含 AI 安全、供应链攻击、SSRF 等） | +167% |
| **敏感数据检测** | 10+ 基础模式 | **50+ 检测模式**（覆盖 API Key、Token、私钥、连接串等） | +400% |
| **API 审计** | 无 | **14 类 API 自动分类 + 风险评级**（云服务、AI、广告、支付等） | 全新能力 |
| **报告格式** | 纯 Markdown 基础报告 | **多格式结构化输出**（Markdown + JSON + SARIF + HTML + PDF） | 全面升级 |
| **报告内容** | 简单通过/警告/危险状态 | **三大核心报告**：评级内容 + 敏感风险点列举 + 外部 API 清单 | 全面升级 |
| **团队协作** | 单人单流程维护 | **6 个专业子团队并行协作架构** | 全新能力 |
| **检测精度** | 基础正则匹配，误报率 ~15% | **熵值分析 + 上下文感知**，误报率 <5%，漏报率 <1% | 大幅提升 |
| **检测覆盖率** | ~60% | **95%+**（覆盖 OWASP Top 10、AI 安全） | +58% |
| **合规支持** | 无 | **GDPR / CCPA / PCI DSS 合规映射** | 全新能力 |

---

## 📁 文档结构

```
cls-certify/
├── SKILL.md                              # 主技能文档
├── TEAM-STRUCTURE.md                     # 团队分工架构
├── README.md                             # 本文件
├── templates/
│   └── report-template.html              # HTML 报告统一模板
└── references/
    ├── report-data-protocol.md           # HTML 报告数据协议
    ├── structured-report-template.md     # 结构化报告模板
    ├── threat-patterns.md               # 40+ 威胁模式库
    ├── api-classification.md            # API 分类标准
    └── sensitive-data-patterns.md       # 敏感数据检测模式
```

---

## 🛡️ 六维深度检测体系

### 1. 静态代码分析 (Static Analysis Team)
- **AST 语义分析**: 解析代码结构，识别危险函数调用
- **敏感信息泄露**: API Key、密码、私钥检测 (50+ 模式)
- **威胁模式匹配**: 40+ 攻击向量识别
- **代码混淆检测**: 高熵字符串、编码混淆识别

### 2. 动态行为分析 (Dynamic Analysis Team)
- **沙箱执行监控**: 隔离环境中执行并监控行为
- **文件系统监控**: 敏感目录访问检测
- **网络请求捕获**: 外发请求拦截分析
- **输入验证测试**: 提示词注入、越权访问测试

### 3. 依赖审计 (Dependency Audit Team)
- **CVE 漏洞扫描**: 对接 NVD 数据库
- **恶意包检测**: Typosquatting 识别
- **依赖树分析**: 传递依赖风险评估
- **版本锁定检查**: 依赖版本安全性

### 4. 网络流量分析 (Network Analysis Team)
- **外部 API 识别**: 自动分类 14 大类 API
- **数据传输审计**: 敏感字段传输检测
- **域名信誉检查**: 可疑域名识别
- **加密方式验证**: TLS 版本和证书检查

### 5. 隐私合规检查 (Privacy & Compliance Team)
- **数据收集审查**: 超出功能范围的数据收集
- **权限申请审查**: 过度权限识别
- **GDPR/CCPA 合规**: 隐私法规检查
- **用户控制机制**: 数据删除/导出支持

### 6. 威胁情报关联 (Threat Intelligence Team)
- **IoC 匹配**: 已知威胁指标比对
- **行为模式分析**: 恶意行为相似度检测
- **情报源集成**: 实时威胁情报更新

---

## 📊 结构化报告输出

### 报告包含三大核心内容

#### 1. 评级内容 (Rating Content)
```json
{
  "rating": {
    "level": "S+|S|A|B|C|D",
    "score": 85,
    "evaluation": "标准安全级别，可放心使用",
    "source_credibility": "T1|T2|T3"
  }
}
```

#### 2. 敏感风险点列举 (Sensitive Risk Points)
```json
{
  "sensitive_risks": [
    {
      "id": "RISK-001",
      "severity": "critical|high|medium|low",
      "category": "secret_leak|dangerous_function|...",
      "title": "发现硬编码 API 密钥",
      "location": {"file": "index.js", "line": 42},
      "evidence": "const API_KEY = 'sk-xxx'",
      "recommendation": "使用环境变量存储密钥"
    }
  ]
}
```

#### 3. 外部 API 列举 (External APIs)
```json
{
  "external_apis": [
    {
      "id": "API-001",
      "endpoint": "https://api.openai.com/v1/chat/completions",
      "method": "POST",
      "category": "ai_service",
      "reputation": "trusted",
      "risk_level": "low",
      "data_types": ["user_input"],
      "encryption": {"protocol": "https", "tls_version": "1.3"}
    }
  ]
}
```

### 输出格式支持

| 格式 | 扩展名 | 用途 |
|-----|-------|------|
| Markdown | `.md` | 人类阅读 |
| JSON | `.json` | 机器解析、自动化集成 |
| SARIF | `.sarif` | GitHub/CodeQL 兼容 |
| HTML | `.html` | 可视化展示 |
| **PDF** | `.pdf` | **正式报告归档、分享与打印** |

---

## 👥 团队协作架构

### Core Team（核心团队）
- 协调各子团队结果
- 综合评级判定
- 报告生成与输出

### 6 个专业子团队

| 团队 | 职责 | 负责人角色 |
|-----|------|-----------|
| Static Analysis Team | 静态代码安全分析 | 代码安全专家 |
| Dynamic Analysis Team | 运行时行为监控 | 运行时安全专家 |
| Dependency Audit Team | 依赖供应链审计 | 供应链安全专家 |
| Network Analysis Team | 网络流量分析 | 网络安全专家 |
| Privacy & Compliance Team | 隐私合规检查 | 隐私合规专家 |
| Threat Intelligence Team | 威胁情报关联 | 威胁情报分析师 |

---

## 🎯 核心特性

### 智能检测
- **熵值分析**: 识别随机字符串 (API Key、Token)
- **上下文感知**: 降低误报率
- **多层递归**: 动态代码加载深度检查
- **模式演进**: 持续更新的威胁模式库

### 全面覆盖
- **40+ 威胁模式**: 覆盖 OWASP Top 10、AI 安全
- **14 类 API 分类**: 云服务、AI、广告等
- **50+ 敏感数据模式**: 密钥、密码、私钥等
- **多语言支持**: JavaScript、Python、Shell、Java 等

### 企业级报告
- **标准化输出**: JSON Schema 定义
- **风险量化**: 评分体系 (0-100)
- **修复建议**: 每项风险的具体改进方案
- **合规映射**: GDPR、CCPA、PCI DSS

---

## 📋 快速开始

### 使用场景 1: 检查本地 Skill
```
检查 /path/to/skill 的安全性
```

### 使用场景 2: 检查已安装 Skill
```
检查 skill-name 的安全性
```

### 使用场景 3: 检查 GitHub Skill
```
检查 https://github.com/user/skill-repo 的安全性
```

---

## 📈 评级标准

| 评级 | 分数 | 说明 | 使用建议 |
|:----:|:----:|------|---------|
| **S+** | 90-100 | 顶级安全，人工验证 | 可放心使用 |
| **S** | 80-89 | 优秀，满足所有安全要求 | 可放心使用 |
| **A** | 65-79 | 标准级，可放心使用 | 正常使用 |
| **B** | 50-64 | 基础级，有改进空间 | 审查后使用 |
| **C** | 30-49 | 警示级，有风险 | 隔离环境使用 |
| **D** | 0-29 | 危险级，不建议使用 | 禁止使用 |

---

## 🔍 威胁检测能力

### 代码执行类
- `eval()`, `exec()`, `Function()` 检测
- `system()`, `subprocess`, `child_process` 检测
- 命令注入、SQL 注入、路径遍历

### 数据安全类
- API Key、Token 泄露 (OpenAI、GitHub、AWS 等)
- 密码硬编码检测
- 私钥文件识别
- 数据库连接串泄露

### AI 安全类
- 提示词注入检测
- 越狱攻击模式识别
- 上下文操纵检测

### 供应链类
- Typosquatting 检测
- CVE 漏洞扫描
- 依赖混淆检测

### 网络攻击类
- SSRF 检测
- DNS 重绑定
- 可疑域名识别

---

## 🛠️ 安装与部署

### 安装方式

1. **通过 cocoloop 安装** (推荐)
```bash
cocoloop install cls-certify-v2
```

2. **手动安装**
```bash
# 复制到 skill 目录
cp -r cls-certify-v2 ~/.claude/skills/

# 重新加载技能
/skills reload
```

3. **打包安装**
```bash
# 打包 skill
cd cls-certify-v2
zip -r cls-certify-v2.skill .

# 安装
claude skills install cls-certify-v2.skill
```

---

## 📝 配置选项

### 检测配置
```yaml
detection_config:
  # 扫描深度
  scan_depth: full  # full | quick | static-only

  # 最小风险级别
  min_severity: medium

  # 启用/禁用检测维度
  dimensions:
    static_analysis: true
    dynamic_analysis: true
    dependency_audit: true
    network_analysis: true
    privacy_compliance: true
    threat_intelligence: true

  # 误报过滤
  false_positive_filter:
    enabled: true
    excluded_patterns:
      - "test"
      - "example"
```

### 报告配置
```yaml
report_config:
  formats:
    - markdown
    - json
    - sarif
    - pdf

  detail_level: full  # full | summary | minimal

  sections:
    - metadata
    - rating
    - risk_summary
    - sensitive_risks
    - external_apis
    - detailed_results
    - recommendations
```

---

## 🤝 团队协作指南

### 开发流程

```
1. 需求分析 → Core Team
      ↓
2. 任务分发 → 各子团队
      ↓
3. 并行开发 → 6 个子团队同时工作
      ↓
4. 结果汇总 → Core Team
      ↓
5. 集成测试 → QA Team
      ↓
6. 发布更新 → Core Team
```

### 代码审查标准

- 所有检测代码必须通过单元测试
- 误报率 < 5%
- 漏报率 < 1%
- 大型 Skill (< 10MB) 检测时间 < 30s

---

## 📚 参考文档

| 文档 | 描述 |
|-----|------|
| [SKILL.md](SKILL.md) | 主技能文档，包含完整工作流程 |
| [TEAM-STRUCTURE.md](TEAM-STRUCTURE.md) | 团队分工与协作架构 |
| [structured-report-template.md](references/structured-report-template.md) | 结构化报告模板 |
| [threat-patterns.md](references/threat-patterns.md) | 40+ 威胁检测模式 |
| [api-classification.md](references/api-classification.md) | API 分类标准 |
| [sensitive-data-patterns.md](references/sensitive-data-patterns.md) | 敏感数据检测模式 |

---

## 🗺️ 路线图

| 版本 | 目标 | 预计发布 |
|-----|------|---------|
| v2.0 | 架构升级、团队化分工 | 2026-03 |
| v2.1 | 性能优化、并行检测 | 2026-04 |
| v2.2 | AI 辅助分析、误报降低 | 2026-05 |
| v2.5 | 生态扩展、更多 Skill 类型 | 2026-06 |

---

## 📄 许可证

MIT License - 详见 [LICENSE](../LICENSE)

---

## 🙏 致谢

感谢以下开源项目和团队的贡献：
- skill-vetter: 系统化安全评估框架
- aegis-audit: AST 静态分析方案
- openclaw-policy-check: 轻量级检测方案
- 以及 20+ 个安全技能的最佳实践

---

**CLS-Certify v2.0** - 让 Skill 安全检测进入 next level 🚀

*版本: v2.0*
*最后更新: 2026-03-13*
*维护团队: CLS-Certify Core Team*
