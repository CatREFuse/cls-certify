---
name: cls-certify
description: "CocoLoop Safe (CLS) Skill 安全认证。对 Agent Skills 进行六维深度安全分析（静态代码、动态行为、依赖审计、网络流量、隐私合规、威胁情报），输出 S+/S/A/B/C/D 等级评估和 HTML/PDF 可视化报告。使用当用户需要检查 skill 安全性、验证 skill 是否可信、分析 skill 代码安全性、评估 skill 风险等级时。"
metadata:
  version: "2.1.0"
  build: "20260317.0002"
  author: "tanshow"
  batch_mode: "false"
  output_dir: "~/Downloads"
  scan_mode: "auto"
---

# CLS-Certify v2.1.0 - 下一代 Skill 安全认证

对 Agent Skills 进行企业级六维安全检测和认证，输出 S+/S/A/B/C/D 安全等级和结构化报告。

## 核心能力

- **六维深度检测**: 静态分析、动态监控、依赖审计、网络分析、隐私合规、威胁情报
- **结构化报告**: JSON/Markdown/HTML/PDF 多格式输出
- **供应链安全**: CVE 漏洞、恶意包、typosquatting 检测
- **API 审计**: 外部 API 分类与数据外泄风险评估
- **隐私合规**: GDPR、CCPA 合规性检查

## 工作流程

### 阶段 0: 版本检查

```bash
bash {skill_path}/tools/check-update.sh --json > /tmp/cls-update.json
```

读取 `/tmp/cls-update.json`。若 `update_available` 为 `true`，使用 AskUserQuestion 询问用户是否更新（"更新后继续" / "跳过，使用当前版本"）。若检查失败，静默跳过。

### 阶段 1: 前置检查与来源分级

**1.1 定位 Skill** — 根据用户输入（本地路径 / skill 名称 / GitHub 链接）定位 skill 位置。名称查找路径: `~/.claude/skills/`、`~/.openclaw/skills/`、`~/.molili/skills/`。

**1.2 加载 Skill 内容** — 读取: SKILL.md、scripts/、references/、assets/、依赖文件 (package.json/requirements.txt)。提取 Markdown 中所有带语言标记的代码块。

**1.3 代码块风险分级**:
- **低风险**: 配置文件、代码片段演示
- **中风险**: 可执行脚本、网络请求、文件操作
- **高风险**: 危险函数（eval/exec）、系统破坏性命令、硬编码密钥

**1.4 来源可信度 (T1/T2/T3)**:

| 等级 | 定义 | 检测宽松度 |
|-----|------|-----------|
| **T1** | 知名大公司/顶级基金会 | 放宽至 B 级要求 |
| **T2** | 可信组织/GitHub 组织 | 放宽至 C 级要求 |
| **T3** | 个人/社区项目 | 严格禁止未验证动态代码 |

**验证点**: 确认 skill 已定位、内容已加载、来源等级已判定后继续。

---

### 阶段 1.5: Skill 分类与策略选择

根据文件结构和代码统计自动选择检查策略。

```bash
bash {skill_path}/tools/code-stats.sh {target_path} --json > /tmp/code-stats.json
bash {skill_path}/tools/skill-classify.sh {target_path} --stats /tmp/code-stats.json --json > /tmp/classify.json
```

**验证点**: 确认 `/tmp/classify.json` 存在且包含有效 tier 后继续。

**分类体系** (首次命中即确定):

| Tier | 名称 | 判定条件 | 策略 |
|:----:|------|---------|------|
| **T-MD** | 纯 Markdown | 全部 `.md`，无 medium/high 代码块 | MD 语义为主，跳过 secret/entropy/dep |
| **T-HEAVY** | 大型代码 | 可执行行 >200 或文件 >10 或体积 >100KB | Targeted: 仅审查命中点上下文 |
| **T-REF** | 引用代码 | 存在 `references/` 代码或含 medium/high 代码块 | 全量 + 引用溯源 |
| **T-LITE** | 轻量代码 | 以上均不满足 | 全量检查 |

**各 Tier 策略对照**:

| 检查项 | T-MD | T-LITE | T-REF | T-HEAVY |
|--------|:----:|:------:|:-----:|:-------:|
| threat-scan.sh | MD-ONLY | FULL | FULL | FULL |
| secret-scan.sh | SKIP | FULL | FULL | FULL |
| entropy-detect.sh | SKIP | FULL | FULL | FULL |
| url-audit.sh | MD-ONLY | FULL | FULL | FULL |
| dep-audit.sh | SKIP | FULL | FULL | FULL |
| github-repo-check.sh | FULL | FULL | FULL | FULL |
| 维度 1: 静态分析 | MD-ONLY | FULL | FULL | TARGETED |
| 维度 2: 动态行为 | SKIP | FULL | FULL | TARGETED |
| 维度 3: 依赖审计 | SKIP | FULL | FULL | FULL |
| 维度 4: 网络分析 | MD-ONLY | FULL | FULL+REF | FULL |
| 维度 5: 隐私合规 | LITE | FULL | FULL | FULL |
| 维度 6: 威胁情报 | FULL | FULL | FULL | FULL |

**scan_mode 覆盖**: `auto` 按分类选择；`full` 忽略分类执行全量；`quick` 按 T-MD 策略执行。

---

### 阶段 1.6: 硬编码快检 + 意图验证

所有工具仅产出"候选/疑似点"，是否危险由 Agent 最终判断。

#### Step 1: 按策略执行检测工具

根据 `/tmp/classify.json` 中的 `strategy`，有条件地运行工具。策略值为 `"skip"` 时跳过。

```bash
bash {skill_path}/tools/threat-scan.sh {threat_target} --json --context 3 > /tmp/threat.json
bash {skill_path}/tools/secret-scan.sh {secret_target} --json --context 3 > /tmp/secret.json
bash {skill_path}/tools/entropy-detect.sh {target_path} --json --context 3 > /tmp/entropy.json
bash {skill_path}/tools/url-audit.sh {url_target} --json --context 3 > /tmp/url.json
bash {skill_path}/tools/dep-audit.sh {target_path} --json > /tmp/dep.json
bash {skill_path}/tools/github-repo-check.sh {owner}/{repo} --json > /tmp/github.json
```

**验证点**: 确认每个非 skip 工具的输出 JSON 文件存在后继续。

#### Step 2: Agent 意图验证

使用 `threat-verify.sh` 生成验证 prompt，逐条审查候选命中:

```bash
bash {skill_path}/tools/threat-verify.sh /tmp/threat.json
```

Agent 同时审查 secret-scan、entropy-detect、url-audit、dep-audit 的候选命中。对每条候选判定为 confirmed / confirmed_low_risk / false_positive / low_risk / comment。判定依据和计分规则见 `references/scoring-matrix.md`。

仅将 `confirmed` 威胁传入 `tools/score-calc.sh`。降级模式（AI 不可用时）直接使用 Step 1 原始候选。

---

### 阶段 2: 六维深度检测

> 执行范围受阶段 1.5 分类结果控制。T-MD 仅执行维度 1（提示词投毒/权限升级/MCP 滥用）、维度 5（LITE）、维度 6。T-HEAVY 维度 1/2 采用 Targeted 模式。

#### 维度 1: 静态代码分析

检查项（完整模式列表见 `references/threat-patterns.md`）:

1. **危险函数检测** — eval/exec/system/child_process 等
2. **敏感信息泄露** — 模式库见 `references/sensitive-data-patterns.md`
3. **威胁模式匹配** — 140+ 模式，见 `references/threat-patterns.md`
4. **代码混淆检测** — 高熵字符串（>4.5）、Unicode 转义、Base64 嵌套
5. **动态代码下载** — L0 (本地安全) → L1 (需审查) → L2+ (**强制 D 级**)。L1 有来源校验仅 -5，无校验 -20；L2+ 直接 -40 强制 D 级
6. **提示词投毒** — HTML 注释隐藏指令、零宽字符、角色覆写。发现 → **-40 强制 D 级**
7. **权限升级诱导** — dangerouslyDisableSandbox、sudo 诱导、社工引导。发现 → **-40 强制 D 级**
8. **隐蔽信息外传** — DNS 外带、Git 外传、剪贴板、编码外传。发现 → **-35**
9. **延迟/条件触发** — 时间/计数/环境条件下隐藏恶意。发现 → **-30 最高 C 级**
10. **功能-行为一致性** — 对比声明功能与实际代码行为。严重偏离 -30，轻度 -10
11. **MCP 工具滥用** — 检查提示词是否引导 agent 通过 MCP 工具执行恶意操作。发现 → **-35 最高 C 级**
12. **Agent 上下文注入** — 记忆注入/系统提示篡改/配置注入/Hook 滥用/终端注入。三步流程: 模式标记（不扣分）→ Agent 恶意行为分析 → 确认后归类计分。确认恶意 → **-40 强制 D 级**

#### 维度 2: 动态行为分析（模拟运行）

> T-MD 跳过。T-HEAVY 采用 Targeted 模式。

创建子 Agent 进行 dry-run 模拟分析（不实际执行代码）:
- 逐文件推理运行时行为（文件访问、网络请求、进程创建）
- 模拟异常输入场景（提示注入、越权访问、路径遍历、边界测试）
- 标注风险等级和置信度，置信度 <70% 标记 `needs_sandbox_verification`

#### 维度 3: 依赖审计

- **CVE 漏洞扫描** — 对接 NVD 数据库，见 `references/cve-sources.md`
- **恶意包检测** — Typosquatting、维护状态、下载量异常
- **依赖树分析** — 直接/传递依赖风险路径

#### 维度 4: 网络流量分析

> T-MD 仅扫描 SKILL.md 中的 URL。T-REF 额外追溯 references/ 中引用代码的 URL 来源。

- **API 分类与风险评级** — 14 类分类标准见 `references/api-classification.md`
- **数据传输审计** — 请求方法、敏感字段传输、TLS 版本
- **域名信誉** — 短链接、纯 IP、可疑 TLD、动态 DNS、Base64 编码 URL

#### 维度 5: 隐私合规

> T-MD 仅执行 LITE 模式（提示词投毒/权限升级/MCP 滥用）。

- **数据收集审查** — 超出功能范围的数据收集
- **环境变量访问分级** — 低风险(PATH/HOME) / 高风险(API Key/Token, -20) / 极高(遍历全部 os.environ, -35 最高 C 级)
- **权限申请审查** — 功能匹配性评估
- **GDPR/CCPA 合规** — 检查清单见 `references/gdpr-checklist.md`

#### 维度 6: 来源信誉与威胁情报

```bash
gh api repos/{owner}/{repo}
gh api users/{owner}
gh api repos/{owner}/{repo}/commits --jq '.[].commit.author.date'
```

- **GitHub 仓库信誉** — Star、年龄、作者、活跃度、Contributors
- **URL/域名信誉** — 代码中所有 URL 安全性检查
- **已知恶意模式比对** — 见 `references/known-malicious-patterns.md`

**验证点**: 六维检测全部完成后，汇总发现并继续评级。

---

### 阶段 3: 综合评级判定

将所有 confirmed 发现传入评分计算:

```bash
bash {skill_path}/tools/score-calc.sh [工具输出 JSON 文件...] > /tmp/score.json
```

评分矩阵、评级标准和判定流程见 `references/scoring-matrix.md`。

**验证点**: 确认 `/tmp/score.json` 包含 `grade` 和 `score` 字段后继续。

---

### 阶段 4: 结构化报告生成

报告格式严格遵循 `references/report-data-protocol.md`。采用 YAML frontmatter + Markdown body 双层结构。

**必需区块**:
- Frontmatter: 23 个必填字段（report_id, grade, score, radar[6], compliance[6], sample_hash 等）
- Body: pattern_tags / summary / external_apis / findings / recommendations

**sample_hash 计算**:
```bash
find {skill_path} -type f ! -path '*/.git/*' | sort | xargs cat | shasum -a 256 | cut -d' ' -f1
```

**协议合规检查** — 输出前确认:
- [ ] Frontmatter 含全部 23 字段
- [ ] grade 为 S+/S/A/B/C/D 之一
- [ ] stamp_color 与等级匹配（S+/S/A/B → green，C/D → red）
- [ ] radar 恰好 6 维，每维含 name/short/score/status/detail
- [ ] Body 含全部 5 个 `##` 区块
- [ ] findings 每项含 severity/category/title/location/description/recommendation
- [ ] external_apis 表含 6 列

JSON 结构参考 `references/structured-report-template.md`。

**报告保存与输出**:

1. 自动保存 Markdown: `{output_dir}/CLS-v2-{skill-name}-{评级}-{时间戳}.md`
2. 若 `batch_mode: true` → 跳过询问，仅输出 Markdown 和文字摘要
3. 否则用 AskUserQuestion 多选格式 (Markdown/HTML/PDF/JSON)
4. 按选择执行渲染

---

### 阶段 5: HTML 报告渲染

```bash
# 仅 HTML
bash {skill_path}/render.sh {md_path} {html_path}

# HTML + PDF
bash {skill_path}/render.sh {md_path} {html_path} --pdf
```

脚本自动解析 Markdown 数据协议并注入 HTML 模板 (`templates/report-template.html`)。占位符注入规则和雷达图坐标计算见 `references/report-data-protocol.md`。

用 `open` 打开报告（batch_mode 下仅输出文字摘要）。

---

## 参考文档

- `references/scoring-matrix.md` - 评分矩阵、评级标准、意图验证判定
- `references/report-data-protocol.md` - HTML 报告数据协议规范
- `references/structured-report-template.md` - 结构化报告模板（JSON Schema）
- `references/threat-patterns.md` - 威胁模式库（140+ 模式）
- `references/sensitive-data-patterns.md` - 敏感数据检测模式
- `references/api-classification.md` - API 分类标准
- `references/gdpr-checklist.md` - GDPR 合规检查清单
- `references/cve-sources.md` - CVE 数据源配置
- `references/known-malicious-patterns.md` - 已知恶意模式库
- `templates/report-template.html` - HTML 报告统一模板

## 使用示例

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
开启 batch mode，依次检查 summarize、chrome、web-fetcher 三个 skill
```
