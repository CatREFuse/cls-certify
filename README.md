# CLS-Certify - Agent Skill 安全认证系统

> 面向所有支持 Skill 的 Agent 平台，提供六维深度安全分析和 S+ ~ D 等级评估

适用平台：Claude Code / OpenAI Agents / Cursor / Windsurf 等

---

## 检测维度与检查项

### 维度 1: 静态代码分析

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| 危险函数检测 | eval/exec/system/child_process 等 | `tools/threat-scan.sh` |
| 敏感信息泄露 | API Key、密码、私钥、连接串（50+ 模式） | `tools/secret-scan.sh`, `references/sensitive-data-patterns.md` |
| 威胁模式匹配 | 40+ 攻击向量（注入、外泄、SSRF 等） | `tools/threat-scan.sh`, `references/threat-patterns.md` |
| 代码混淆检测 | 高熵字符串、Unicode 转义、Base64 嵌套 | `tools/entropy-detect.sh` |
| 动态代码下载 | L0-L3 嵌套深度追踪，L2+ 强制 D 级 | `tools/threat-scan.sh` |
| 提示词投毒 | HTML 注释隐藏指令、零宽字符、角色覆写 | `tools/threat-scan.sh`, `tools/threat-verify.sh` |
| 权限升级诱导 | dangerouslyDisableSandbox、sudo 诱导 | `tools/threat-scan.sh` |
| 隐蔽信息外传 | DNS 外带、Git 外传、编码外传、剪贴板 | `tools/threat-scan.sh` |
| 延迟/条件触发 | 时间、计数、环境条件下的隐藏恶意 | `tools/threat-scan.sh` |
| 功能-行为一致性 | 声明功能与实际代码行为偏离度分析 | Agent 语义分析 |
| MCP 工具滥用 | 通过提示词引导 agent 滥用 MCP 工具 | Agent 语义分析 |

### 维度 2: 动态行为分析

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| 沙箱执行监控 | 隔离环境中监控文件/网络/进程行为 | Agent 运行时分析 |
| 文件系统监控 | 敏感目录访问检测（~/.ssh, /etc 等） | Agent 运行时分析 |
| 网络请求捕获 | 外发 HTTP/HTTPS 请求拦截分析 | Agent 运行时分析 |
| 输入验证测试 | 提示词注入、越权访问、路径遍历测试 | Agent 运行时分析 |

### 维度 3: 依赖审计

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| CVE 漏洞扫描 | 对接 NVD 数据库检测已知漏洞 | `tools/dep-audit.sh`, `references/cve-sources.md` |
| 恶意包检测 | Typosquatting、维护状态、下载量异常 | `tools/dep-audit.sh` |
| 依赖树分析 | 直接/传递依赖风险，漏洞传播路径 | `tools/dep-audit.sh` |
| 版本锁定检查 | 依赖版本固定与安全性评估 | `tools/dep-audit.sh` |

### 维度 4: 网络流量分析

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| API 分类与风险评级 | 14 类外部 API 自动识别分类 | `tools/url-audit.sh`, `references/api-classification.md` |
| 数据传输审计 | 敏感字段传输检测（token, password, key） | `tools/url-audit.sh` |
| 域名信誉检查 | 短链接、纯 IP、动态 DNS、可疑 TLD | `tools/url-audit.sh` |
| TLS 验证 | 加密协议版本和证书检查 | `tools/url-audit.sh` |

### 维度 5: 隐私合规检查

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| 数据收集审查 | 超出功能范围的数据收集识别 | Agent 语义分析 |
| 环境变量访问分级 | 低/中/高/极高四级分类评估 | Agent 语义分析 |
| 权限申请审查 | 与功能不匹配的过度权限识别 | Agent 语义分析 |
| GDPR/CCPA 合规 | 用户同意、数据删除权利、可携带性 | `references/gdpr-checklist.md` |

### 维度 6: 来源信誉与威胁情报

| 检查项 | 说明 | 相关文件 |
|-------|------|---------|
| GitHub 仓库信誉 | Star、年龄、作者、提交活跃度评估 | `tools/github-repo-check.sh` |
| URL/域名信誉 | 代码中所有 URL 的安全性检查 | `tools/url-audit.sh` |
| 已知恶意模式比对 | 黑名单、恶意代码指纹、钓鱼模式 | `references/known-malicious-patterns.md` |

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

## 安装

**通过 cocoloop 安装（推荐）**

```bash
cocoloop install cls-certify
```

**手动安装**

```bash
git clone https://github.com/CatREFuse/cls-certify.git ~/.claude/skills/cls-certify
```

---

## 使用方式

安装后在 Agent 对话中用自然语言发起检查即可：

```
检查 summarize 这个 skill 的安全性
```

```
帮我看看 /Users/me/Developer/my-skill 这个目录下的 skill 是否安全
```

```
对 https://github.com/user/awesome-skill 进行安全认证
```

```
我想安装一个叫 proactive-agent 的 skill，先帮我做个安全检查
```

```
用 CLS-Certify 扫描一下已安装的 chrome skill
```

```
这个 skill 看起来有点可疑，帮我做一个完整的六维安全分析并生成 HTML 报告
```

```
开启 batch mode，依次检查 summarize、chrome、web-fetcher 三个 skill
```

```
静默模式检查 my-skill，不要问我问题
```

```
把报告保存到桌面，检查 my-skill 的安全性
```

```
检查 my-skill，报告保存到 /tmp/reports 目录
```

CLS-Certify 会自动定位 skill、执行六维分析、输出评级报告。如果检测到 D 级触发项（如提示词投毒、反向 Shell、凭证窃取），会立即强制降级并给出警告。

> **提示**：`batch_mode` 开启后静默运行，不询问输出格式，仅保存 Markdown 报告；`output_dir` 控制报告保存位置，默认为 `~/Downloads`。两者均可通过自然语言临时指定，也可在 SKILL.md frontmatter 中永久配置。

---

## 配置

在 SKILL.md 的 frontmatter 中支持以下配置项：

```yaml
# 批量模式 — 跳过所有用户交互，仅输出 Markdown 报告
batch_mode: false        # true: 静默运行，不询问用户，仅输出 Markdown
                         # false: 正常交互模式（默认）

# 报告保存目录
output_dir: ~/Downloads  # 报告文件的默认保存位置
                         # 支持 ~ 和绝对路径，如 ~/Desktop、/tmp/reports

# 扫描模式
scan_mode: full          # full: 完整六维扫描（默认）
                         # quick: 仅硬编码快检 + 评分
                         # static-only: 仅静态分析

# 报告输出格式
report_formats:
  - markdown             # Markdown 报告（默认，始终输出）
  - json                 # JSON 结构化数据
  - html                 # HTML 可视化报告（需 render.sh）
  - pdf                  # PDF 报告（需 Chrome，通过 render.sh --pdf）
  - sarif                # SARIF 格式（GitHub/CodeQL 兼容）

# 报告详细程度
report_detail: full      # full: 包含所有发现和详细分析
                         # summary: 仅评级和风险摘要
                         # minimal: 仅评级和分数

# 最低报告风险级别（低于此级别的发现不输出）
min_severity: low        # critical / high / medium / low / info

# 检测维度开关（按需关闭不需要的维度）
dimensions:
  static_analysis: true       # 静态代码分析
  dynamic_analysis: true      # 动态行为分析
  dependency_audit: true      # 依赖审计
  network_analysis: true      # 网络流量分析
  privacy_compliance: true    # 隐私合规检查
  threat_intelligence: true   # 来源信誉与威胁情报

# 来源可信度覆盖（跳过自动检测，手动指定）
trust_level: auto        # auto: 自动检测（默认）
                         # T1: 知名大公司/顶级基金会
                         # T2: 可信组织/GitHub 组织账号
                         # T3: 个人开发者/社区项目

# 误报过滤
false_positive_filter:
  enabled: true          # 启用误报过滤
  excluded_patterns:     # 排除的文件路径模式
    - "test/**"
    - "example/**"
    - "docs/**"
```

配置方式：在发起检查时用自然语言指定即可，例如：

```
用 quick 模式检查 my-skill，只输出 high 以上的风险
```

```
对这个 skill 做完整扫描，生成 HTML 报告，跳过依赖审计
```

```
开启 batch mode，批量检查这三个 skill 的安全性
```

```
把报告保存到桌面，检查 my-skill 的安全性
```

> **batch_mode 说明**：开启后 CLS-Certify 将以静默模式运行 — 不询问输出格式，不调用 `open` 打开文件，仅自动保存 Markdown 报告到 `output_dir` 并输出文字摘要。适用于批量检测、CI 集成或脚本调用场景。

> **output_dir 说明**：所有报告文件（Markdown / HTML / PDF）均保存到此目录，默认为 `~/Downloads`。可通过自然语言临时指定（如"保存到桌面"），也可在 SKILL.md frontmatter 中永久修改。

---

## 项目结构

```
cls-certify/
├── SKILL.md                         # 主技能文档（完整检测工作流）
├── README.md                        # 本文件
├── TEAM-STRUCTURE.md                # 六子团队分工架构
├── render.sh                        # HTML/PDF 报告渲染脚本
├── tools/                           # 内置 bash 检测工具
│   ├── threat-scan.sh               #   威胁模式匹配
│   ├── threat-verify.sh             #   威胁意图二次验证
│   ├── secret-scan.sh               #   敏感信息扫描
│   ├── entropy-detect.sh            #   Shannon 熵值检测
│   ├── dep-audit.sh                 #   依赖审计
│   ├── url-audit.sh                 #   URL/域名审计
│   ├── github-repo-check.sh         #   GitHub 仓库信誉检查
│   ├── code-stats.sh                #   代码统计
│   └── score-calc.sh                #   评分计算
├── templates/
│   └── report-template.html         # HTML 报告模板
└── references/
    ├── threat-patterns.md           # 40+ 威胁模式库
    ├── sensitive-data-patterns.md   # 50+ 敏感数据检测模式
    ├── api-classification.md        # 14 类 API 分类标准
    ├── structured-report-template.md # 报告 JSON Schema
    ├── report-data-protocol.md      # HTML 渲染数据协议
    ├── known-malicious-patterns.md  # 已知恶意模式
    ├── gdpr-checklist.md            # GDPR 合规检查清单
    └── cve-sources.md               # CVE 数据源配置
```

---

## 许可证

MIT License
