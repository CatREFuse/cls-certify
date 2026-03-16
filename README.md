# CLS-Certify - Agent Skill 安全认证系统

> 面向所有支持 Skill 的 Agent 平台，提供六维深度安全分析和结构化报告输出

CLS-Certify 是一个开源的 Agent Skill 安全认证工具，对 Skill 进行静态代码、动态行为、依赖审计、网络流量、隐私合规、威胁情报六个维度的深度分析，输出 S+ ~ D 等级评估和 HTML/PDF 可视化报告。

适用平台：Claude Code、OpenAI Agents、Cursor、Windsurf 等所有支持 Skill 的 Agent 平台。

---

## 快速开始

### 安装

**通过 cocoloop 安装（推荐）**
```bash
cocoloop install cls-certify
```

**手动安装**
```bash
git clone https://github.com/CatREFuse/cls-certify.git ~/.claude/skills/cls-certify
```

### 使用

安装后在 Agent 对话中直接使用：

```
# 检查本地 Skill
检查 /path/to/skill 的安全性

# 检查已安装的 Skill
检查 skill-name 的安全性

# 检查 GitHub 上的 Skill
检查 https://github.com/user/skill-repo 的安全性
```

CLS-Certify 会自动执行六维分析，输出评级报告。

---

## 评级标准

| 评级 | 分数 | 说明 | 使用建议 |
|:----:|:----:|------|---------|
| S+ | 90-100 | 顶级安全，通过人工验证 | 可放心使用 |
| S | 80-89 | 优秀，满足所有安全要求 | 可放心使用 |
| A | 65-79 | 标准安全级别 | 正常使用 |
| B | 50-64 | 基础级，有改进空间 | 审查后使用 |
| C | 30-49 | 警示级，存在风险 | 隔离环境使用 |
| D | 0-29 | 危险级 | 禁止使用 |

---

## 六维检测体系

### 1. 静态代码分析
危险函数检测、敏感信息泄露（50+ 模式）、威胁模式匹配（40+ 模式）、代码混淆检测、动态代码下载深度追踪（L0-L3）

### 2. 动态行为分析
沙箱执行监控、文件系统访问检测、网络请求捕获、提示词注入测试

### 3. 依赖审计
CVE 漏洞扫描、Typosquatting 恶意包检测、依赖树分析、版本锁定检查

### 4. 网络流量分析
14 类外部 API 自动分类与风险评级、数据传输审计、域名信誉检查、TLS 验证

### 5. 隐私合规检查
数据收集审查、权限申请审查、GDPR/CCPA 合规检查、用户控制机制评估

### 6. 威胁情报关联
IoC 匹配、已知恶意行为模式识别、情报源集成

---

## 报告输出

每份报告包含三大核心内容：

1. **评级内容** — 综合安全评级（S+ ~ D）、评分（0-100）、来源可信度（T1/T2/T3）
2. **敏感风险点列举** — 按严重程度排序的详细风险清单，含位置、证据和修复建议
3. **外部 API 列举** — 所有外部 API 调用的分类、信誉和风险评估

支持输出格式：Markdown / JSON / SARIF / HTML / PDF

---

## 内置检测工具

`tools/` 目录下包含 7 个 bash 检测脚本，覆盖硬编码可扫描的检测功能：

| 工具 | 功能 |
|-----|------|
| `threat-scan.sh` | 威胁模式匹配 |
| `threat-verify.sh` | 威胁意图二次验证 |
| `secret-scan.sh` | 敏感信息扫描 |
| `entropy-detect.sh` | Shannon 熵值检测（识别随机密钥） |
| `dep-audit.sh` | 依赖审计 |
| `url-audit.sh` | URL/域名审计 |
| `github-repo-check.sh` | GitHub 仓库信誉检查 |
| `code-stats.sh` | 代码统计 |
| `score-calc.sh` | 评分计算 |

---

## 项目结构

```
cls-certify/
├── SKILL.md                    # 主技能文档（完整检测工作流）
├── README.md                   # 本文件
├── TEAM-STRUCTURE.md           # 六子团队分工架构
├── V2-UPGRADE-GUIDE.md         # 升级指南
├── render.sh                   # HTML/PDF 报告渲染脚本
├── tools/                      # 内置 bash 检测工具
├── templates/
│   └── report-template.html    # HTML 报告模板
└── references/
    ├── threat-patterns.md      # 40+ 威胁模式库
    ├── sensitive-data-patterns.md # 50+ 敏感数据检测模式
    ├── structured-report-template.md # 结构化报告 JSON Schema
    ├── report-data-protocol.md # HTML 渲染数据协议
    ├── api-classification.md   # 14 类 API 分类标准
    ├── known-malicious-patterns.md # 已知恶意模式
    ├── gdpr-checklist.md       # GDPR 合规检查清单
    └── cve-sources.md          # CVE 数据源配置
```

---

## 参考文档

| 文档 | 描述 |
|-----|------|
| [SKILL.md](SKILL.md) | 主技能文档，包含完整检测工作流 |
| [TEAM-STRUCTURE.md](TEAM-STRUCTURE.md) | 团队分工与协作架构 |
| [threat-patterns.md](references/threat-patterns.md) | 40+ 威胁检测模式 |
| [sensitive-data-patterns.md](references/sensitive-data-patterns.md) | 敏感数据检测模式 |
| [api-classification.md](references/api-classification.md) | API 分类标准 |
| [structured-report-template.md](references/structured-report-template.md) | 结构化报告模板 |

---

## 许可证

MIT License

---

*维护: CLS-Certify Core Team*
