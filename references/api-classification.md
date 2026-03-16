# CLS-Certify API 分类标准 v2.0

> 对外部 API 进行标准化分类和风险评估的参考指南

---

## API 风险评级体系

### 风险等级定义

| 等级 | 描述 | 处理建议 |
|:----:|------|---------|
| 🟢 **Low** | 可信服务，低风险 | 正常使用 |
| 🟡 **Medium** | 需要关注，了解数据用途 | 确认数据共享范围 |
| 🟠 **High** | 风险较高，谨慎使用 | 审查隐私政策 |
| 🔴 **Critical** | 未加密或可疑服务 | 避免传输敏感数据 |

### 信誉评级

| 等级 | 描述 |
|-----|------|
| **Trusted** | 知名公司官方 API，有良好安全记录 |
| **Verified** | 经过验证的第三方服务 |
| **Unknown** | 未知或新兴服务 |
| **Suspicious** | 存在可疑行为或投诉 |
| **Malicious** | 已知恶意服务 |

---

## API 分类目录

### 1. 云服务 API (Cloud Services) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| AWS | `*.amazonaws.com` | 对象存储、计算 | 用户文件、配置 |
| Azure | `*.azure.com`, `*.windows.net` | 云服务 | 用户数据 |
| GCP | `*.googleapis.com` | AI/ML、存储 | 用户输入、文件 |
| 阿里云 | `*.aliyuncs.com` | 存储、计算 | 用户数据 |
| 腾讯云 | `*.tencentcloudapi.com` | 云服务 | 用户数据 |
| 火山引擎 | `*.volces.com` | AI/ML | 用户输入 |

**风险评估**: 🟢 Low
- 企业级安全保障
- 数据加密传输和存储
- 合规认证 (SOC2, ISO27001)

---

### 2. AI/ML 服务 API (AI Services) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| OpenAI | `api.openai.com` | GPT 对话 | 用户提示词 |
| Anthropic | `api.anthropic.com` | Claude 对话 | 用户提示词 |
| Google AI | `generativelanguage.googleapis.com` | Gemini | 用户输入 |
| Azure OpenAI | `*.openai.azure.com` | GPT 企业版 | 用户提示词 |
| Cohere | `api.cohere.ai` | NLP 服务 | 文本数据 |
| Mistral | `api.mistral.ai` | LLM 服务 | 用户提示词 |
| 文心一言 | `aip.baidubce.com` | 中文对话 | 用户提示词 |
| 通义千问 | `dashscope.aliyuncs.com` | 中文对话 | 用户提示词 |
| DeepSeek | `api.deepseek.com` | 代码生成 | 代码片段 |
| Kimi | `api.moonshot.cn` | 长文本处理 | 文档内容 |

**风险评估**: 🟢 Low to 🟡 Medium
- 数据用于模型训练需确认
- 建议查看数据保留政策

**关注点**:
- 数据是否用于模型训练
- 数据保留期限
- 企业版 vs 消费版数据政策差异

---

### 3. 开发者工具 API (Developer Tools) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| GitHub | `api.github.com` | 代码托管 | 代码、Issue |
| GitLab | `gitlab.com/api` | 代码托管 | 代码、MR |
| Bitbucket | `api.bitbucket.org` | 代码托管 | 代码 |
| Docker Hub | `hub.docker.com/v2` | 镜像管理 | 镜像元数据 |
| npm | `registry.npmjs.org` | 包管理 | 包信息 |
| PyPI | `pypi.org/pypi` | 包管理 | 包信息 |
| crates.io | `crates.io/api` | Rust 包管理 | 包信息 |

**风险评估**: 🟢 Low
- 主要是元数据交换
- 认证保护完善

---

### 4. SaaS 生产力工具 (SaaS Productivity) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Slack | `slack.com/api` | 消息通知 | 消息内容 |
| Discord | `discord.com/api` | 社区通知 | 消息内容 |
| Notion | `api.notion.com` | 文档管理 | 文档内容 |
| Linear | `api.linear.app` | 项目管理 | 任务数据 |
| Trello | `api.trello.com` | 看板管理 | 看板数据 |
| Asana | `app.asana.com/api` | 任务管理 | 任务数据 |
| Monday | `api.monday.com` | 工作管理 | 工作数据 |

**风险评估**: 🟢 Low to 🟡 Medium
- 数据共享范围需确认
- 建议限制敏感数据传输

---

### 5. 通信服务 API (Communication) 🟡 Medium

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Twilio | `api.twilio.com` | 短信/电话 | 电话号码、消息 |
| SendGrid | `api.sendgrid.com` | 邮件发送 | 邮件内容 |
| Mailgun | `api.mailgun.net` | 邮件发送 | 邮件内容 |
| AWS SES | `email.*.amazonaws.com` | 邮件服务 | 邮件内容 |
| Pusher | `api.pusherapp.com` | 实时消息 | 消息数据 |
| Ably | `rest.ably.io` | 实时消息 | 消息数据 |

**风险评估**: 🟡 Medium
- 涉及个人通讯数据
- 需确认数据处理和存储政策

---

### 6. 数据分析/监控 (Analytics) 🟡 Medium

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Google Analytics | `google-analytics.com` | 访问统计 | 用户行为 |
| Mixpanel | `api.mixpanel.com` | 事件分析 | 用户行为 |
| Amplitude | `api.amplitude.com` | 产品分析 | 用户行为 |
| Segment | `api.segment.io` | 数据路由 | 用户行为 |
| PostHog | `app.posthog.com` | 产品分析 | 用户行为 |
| Plausible | `plausible.io/api` | 隐私分析 | 匿名统计 |

**风险评估**: 🟡 Medium
- 用户行为追踪
- 可能涉及 PII 数据

**关注点**:
- 是否匿名化
- GDPR/CCPA 合规性
- 数据保留期限

---

### 7. 广告追踪 (Advertising) 🟠 High

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Google Ads | `googleads.googleapis.com` | 广告管理 | 转化数据 |
| Facebook | `graph.facebook.com` | 广告追踪 | 用户行为 |
| TikTok | `business-api.tiktok.com` | 广告追踪 | 用户行为 |
| Twitter/X | `ads-api.twitter.com` | 广告管理 | 用户数据 |
| LinkedIn | `api.linkedin.com` | 广告追踪 | 职业数据 |

**风险评估**: 🟠 High
- 广泛的用户追踪
- 数据共享给广告网络
- 隐私政策复杂

**建议**:
- 明确告知用户数据用途
- 提供退出选项
- 最小化数据收集

---

### 8. 社交媒体 API (Social Media) 🟡 Medium

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Twitter/X | `api.twitter.com` | 推文操作 | 推文内容 |
| Reddit | `oauth.reddit.com` | 帖子管理 | 帖子内容 |
| LinkedIn | `api.linkedin.com` | 内容分享 | 职业数据 |
| Instagram | `graph.instagram.com` | 内容管理 | 媒体内容 |
| YouTube | `youtube.googleapis.com` | 视频管理 | 视频数据 |
| 小红书 | `edith.xiaohongshu.com` | 内容获取 | 笔记数据 |
| 微博 | `api.weibo.com` | 内容管理 | 微博数据 |

**风险评估**: 🟡 Medium
- 平台政策变动频繁
- 数据使用限制较多
- 可能涉及公开个人信息

---

### 9. 支付服务 API (Payment) 🟢 Low (需严格合规)

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Stripe | `api.stripe.com` | 支付处理 | 支付信息 |
| PayPal | `api.paypal.com` | 支付处理 | 支付信息 |
| Square | `connect.squareup.com` | 支付处理 | 支付信息 |
| 支付宝 | `openapi.alipay.com` | 支付处理 | 支付信息 |
| 微信支付 | `api.mch.weixin.qq.com` | 支付处理 | 支付信息 |

**风险评估**: 🟢 Low (服务本身安全)
⚠️ **特别注意**: PCI DSS 合规要求
- 不得存储信用卡号
- 使用 tokenization
- 加密传输

---

### 10. 搜索/知识 API (Search/Knowledge) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Google Search | `customsearch.googleapis.com` | 搜索 | 查询词 |
| Bing | `api.bing.microsoft.com` | 搜索 | 查询词 |
| Brave | `api.search.brave.com` | 搜索 | 查询词 |
| SerpAPI | `serpapi.com/search` | 搜索聚合 | 查询词 |
| Wolfram| `api.wolframalpha.com` | 知识计算 | 查询 |

**风险评估**: 🟢 Low
- 主要是查询词数据
- 不传输敏感信息

---

### 11. 地图/位置服务 (Location) 🟡 Medium

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Google Maps | `maps.googleapis.com` | 地图服务 | 位置数据 |
| Mapbox | `api.mapbox.com` | 地图服务 | 位置数据 |
| 高德地图 | `restapi.amap.com` | 地图服务 | 位置数据 |
| 百度地图 | `api.map.baidu.com` | 地图服务 | 位置数据 |

**风险评估**: 🟡 Medium
- 精确位置数据敏感
- 可能暴露用户行踪

---

### 12. CDN/静态资源 (CDN) 🟢 Low

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Cloudflare | `api.cloudflare.com` | CDN 管理 | 配置数据 |
| Fastly | `api.fastly.com` | CDN 管理 | 配置数据 |
| jsDelivr | `data.jsdelivr.com` | 包 CDN | 包信息 |
| unpkg | `unpkg.com` | npm CDN | 包文件 |
| cdnjs | `cdnjs.cloudflare.com` | 资源 CDN | 静态资源 |

**风险评估**: 🟢 Low
- 主要是静态资源
- 不传输敏感用户数据

---

### 13. 区块链/Web3 API (Blockchain) 🟡 Medium

| 服务商 | API 端点 | 典型用途 | 数据类型 |
|-------|---------|---------|---------|
| Etherscan | `api.etherscan.io` | 链上数据 | 地址、交易 |
| Infura | `*.infura.io` | 节点服务 | 交易数据 |
| Alchemy | `*.alchemyapi.io` | 节点服务 | 交易数据 |
| Moralis | `deep-index.moralis.io` | Web3 数据 | 链上数据 |

**风险评估**: 🟡 Medium
- 区块链数据公开
- 但地址可关联身份
- 交易金额敏感

---

### 14. 可疑/高风险 API 🟠 High to 🔴 Critical

#### 数据收集服务

| 类型 | 特征 | 风险 |
|-----|------|------|
| 未分类数据上报 | 域名包含 `collect`, `track`, `log` | 🟠 High |
| 短生命周期域名 | 域名注册时间 < 30 天 | 🔴 Critical |
| 可疑 TLD | `.tk`, `.ml`, `.ga` 等免费域名 | 🔴 Critical |
| IP 直接访问 | 无域名，直接访问 IP | 🔴 Critical |

#### 已知恶意模式

```yaml
suspicious_patterns:
  - pattern: "*collector*"
    risk: high
  - pattern: "*tracker*"
    risk: high
  - pattern: "*telemetry*"
    risk: medium
  - pattern: "*beacon*"
    risk: medium
  - pattern: "*metrics*"
    risk: low
```

---

## API 检测规则

### 自动分类规则

```yaml
classification_rules:
  trusted_cloud:
    domains:
      - "*.amazonaws.com"
      - "*.azure.com"
      - "*.googleapis.com"
      - "*.aliyuncs.com"
    category: cloud_service
    reputation: trusted
    risk_level: low

  ai_services:
    domains:
      - "api.openai.com"
      - "api.anthropic.com"
      - "generativelanguage.googleapis.com"
      - "api.deepseek.com"
    category: ai_service
    reputation: trusted
    risk_level: low

  advertising:
    domains:
      - "*.facebook.com/tr"
      - "*.google.com/ads"
      - "*.tiktok.com/ads"
    category: advertising
    reputation: suspicious
    risk_level: high

  unknown_third_party:
    default:
      category: unknown
      reputation: unknown
      risk_level: medium
```

### 加密检查

```yaml
encryption_requirements:
  sensitive_data_apis:
    require_https: true
    min_tls_version: "1.2"
    certificate_validation: true

  non_sensitive_apis:
    require_https: recommended
    min_tls_version: "1.2"
```

---

## 数据类型敏感度

| 数据类型 | 敏感度 | 传输要求 |
|---------|:------:|---------|
| 用户输入 (文本) | 🟢 Low | HTTPS |
| 文件内容 | 🟡 Medium | HTTPS |
| 系统信息 | 🟡 Medium | HTTPS |
| 位置数据 | 🟠 High | HTTPS + 用户同意 |
| 个人身份信息 | 🔴 Critical | HTTPS + 加密 |
| 支付信息 | 🔴 Critical | HTTPS + PCI 合规 |
| 凭证/密钥 | 🔴 Critical | 禁止直接传输 |

---

*文档版本: v2.0*
*最后更新: 2026-03-13*
*API 分类数: 14 大类*
