# security-scan 需求分析文档

| 属性 | 值 |
|------|-----|
| 文档版本 | V1.0 |
| 开发语言 | Python |
| 目标项目 | Java 项目 |
| 文档日期 | 2026-06-03 |

---

# 第1章 项目概述与背景

## 1.1 项目背景

随着企业数字化转型的深入推进，Java 项目已成为企业级应用开发的主流技术栈。在软件开发过程中，代码仓库中频繁出现明文密码、硬编码密钥、弱密码等敏感信息泄露问题，这些安全隐患一旦被恶意利用，将导致严重的数据泄露、系统被入侵等安全事件。

当前业界主流的敏感信息检测工具（如 truffleHog、detect-secrets、git-secrets 等）主要侧重于通用场景的密钥和凭证扫描，缺乏针对 Java 项目特性的深度支持。例如，这些工具无法有效识别 Spring 框架中 `@Value` 注解的默认值是否为真正的密码，也无法基于 Java 语法结构进行精准的安全扫描。因此，公司亟需一款专门面向 Java 项目、基于 Python 开发的代码安全扫描组件——**security-scan**。

## 1.2 项目目标

security-scan 的核心目标是构建一个轻量、精准、可集成的代码安全扫描工具，具体包括：

- **安全防护**：有效检测 Java 项目代码中的明文密码、弱密码、硬编码密钥等敏感信息
- **全量覆盖**：支持对整个代码仓库进行主动全量扫描，包括 Java 源码及各类配置文件
- **实时拦截**：通过 Git pre-commit hook 实现代码提交时的增量扫描，在敏感信息进入代码仓库前进行拦截
- **精准检测**：基于 AST（抽象语法树）技术实现语义级别的代码扫描，大幅降低误判率
- **灵活集成**：提供便捷的 Hook 注册与退出机制，支持开发团队快速部署和移除

## 1.3 项目范围

### 1.3.1 包含范围

| 范围项 | 说明 |
|--------|------|
| Java 源代码扫描 | 支持 `.java` 文件的 AST 级别安全扫描 |
| 配置文件扫描 | 支持 XML、JSON、YAML、Properties、TXT、Markdown 等格式 |
| 全量扫描模式 | 支持对整个项目目录的主动扫描 |
| 增量扫描模式 | 基于 Git diff 实现变更文件的定向扫描 |
| Git Hook 集成 | 支持 pre-commit hook 的自动注册与退出 |
| 误判防护 | 支持白名单、注解识别等误判过滤机制 |
| 操作系统支持 | 支持 Windows（10+）、macOS（10.15+）、Linux（CentOS 7+/Ubuntu 18.04+） |
| 环境依赖管理 | 仅依赖 Python 3.8+，其余依赖在初始化时自动检测并安装 |
| pip 仓库配置 | 支持配置公司私有 pip 仓库地址 |

### 1.3.2 不包含范围

- 不包含二进制文件（如 `.class`、`.jar`）的扫描
- 不包含运行时安全检测（如 RASP）
- 不包含依赖库的已知漏洞扫描（如 CVE 检测）
- 不包含 CI/CD 流水线的深度集成（当前版本聚焦本地 Git Hook，CI/CD 集成作为远期特性，预留退出码和输出格式接口，详见 2.9 节）

## 1.4 术语定义

| 术语 | 定义 |
|------|------|
| **AST** | 抽象语法树（Abstract Syntax Tree），源代码语法结构的树状表示 |
| **全量扫描** | 对项目所有文件进行完整的安全扫描 |
| **增量扫描** | 仅对 Git 暂存区中变更的文件进行扫描 |
| **pre-commit hook** | Git 在执行 commit 操作前自动触发的钩子脚本 |
| **明文密码** | 以可读文本形式直接写入代码中的密码 |
| **弱密码** | 强度不足、容易被暴力破解的密码 |
| **误判（False Positive）** | 扫描器将非敏感信息错误识别为敏感信息 |
| **Tree-sitter** | 一个增量解析系统，用于生成代码的语法树 |

---

# 第2章 功能需求分析

## 2.1 全量代码扫描

### 2.1.1 需求描述

security-scan 需要提供全量代码扫描能力，允许用户主动对整个 Java 项目进行一次性的完整安全扫描。全量扫描应覆盖项目中的所有 Java 源代码文件及各类配置文件，全面排查明文密码、弱密码、硬编码密钥等安全隐患。

### 2.1.2 功能要点

**触发方式**：支持以下触发方式：

| 触发方式 | 命令示例 | 适用场景 |
|----------|----------|----------|
| 命令行手动触发 | `security-scan scan --path /project` | 日常安全巡检、新项目接入 |
| 定时任务触发 | `security-scan scan --path /project --cron "0 2 * * *"` | 每日夜间自动扫描 |
| CI/CD 集成触发（预留） | `security-scan scan --path . --ci` | 流水线构建前扫描（当前版本预留接口，详见 2.9 节） |

**扫描范围**：

- **Java 源码**：所有 `.java` 文件，包括 `src/main/java`、`src/test/java` 等目录
- **配置文件**：`application.yml`、`application.properties`、`application-*.yml` 等配置文件
- **通用文件**：XML、JSON、YAML、Properties、TXT、Markdown 等格式的文件
- **排除规则**：支持通过 `.security-scan-ignore` 文件配置排除目录（如 `target/`、`build/`、`node_modules/`、`.git/` 等）

**扫描结果输出**：

| 输出格式 | 说明 |
|----------|------|
| 控制台输出 | 实时显示扫描进度和发现的敏感信息，包含文件路径、行号、风险等级 |
| HTML 报告 | 生成可视化的 HTML 扫描报告，支持按文件、风险等级筛选 |
| JSON 报告 | 输出结构化 JSON 格式，便于与其他工具集成 |
| SARIF 格式 | 输出标准 SARIF 格式，可与 GitHub Code Scanning 等平台集成 |

### 2.1.3 性能要求

- 扫描速度：10 万行 Java 代码的全量扫描应在 60 秒内完成
- 内存占用：峰值内存不超过 512MB
- 支持多线程并行扫描，默认线程数为 CPU 核心数

---

## 2.2 增量扫描与 Git Commit Hook 集成

### 2.2.1 需求描述

security-scan 需要支持增量扫描模式，基于 Git pre-commit hook 在开发者执行 `git commit` 时自动扫描暂存区中的变更文件。当检测到敏感信息时，阻止提交并给出明确的提示信息，从源头防止敏感信息进入代码仓库。

### 2.2.2 工作流程

增量扫描的核心工作流程如下：

```
开发者执行 git add → 文件进入暂存区 → 开发者执行 git commit
       ↓
触发 pre-commit hook → security-scan 扫描暂存区变更文件
       ↓
  ┌────┴────┐
  │ 扫描结果  │
  ├─────────┤
  │ 通过     │ → 允许 commit 完成
  │ 发现问题  │ → 阻止 commit，输出详细报告
  └─────────┘
```

### 2.2.3 功能要点

- **变更文件识别**：通过 `git diff --cached --name-only` 获取暂存区中的变更文件列表
- **文件过滤**：仅扫描受支持的文件类型，跳过二进制文件和排除目录中的文件
- **实时反馈**：扫描结果实时输出到控制台，包含文件名、行号、匹配的敏感信息类型
- **提交阻断**：当发现高危敏感信息（如明文密码）时，返回非零退出码阻止提交
- **合并冲突处理**：当存在合并冲突时，扫描冲突标记区域，提示开发者先解决冲突

### 2.2.4 增量扫描 vs 全量扫描对比

| 对比维度 | 全量扫描 | 增量扫描 |
|----------|----------|----------|
| 触发方式 | 手动/定时/CI | Git pre-commit 自动触发 |
| 扫描范围 | 整个项目 | 仅暂存区变更文件 |
| 扫描速度 | 较慢（分钟级） | 极快（秒级） |
| 适用场景 | 安全巡检、存量排查 | 日常开发实时防护 |
| 结果处理 | 生成报告文件 | 控制台实时输出 |

---

## 2.3 扫描器注册与退出机制

### 2.3.1 需求描述

security-scan 需要提供便捷的命令行工具，支持将扫描器一键注册到 Git pre-commit hook 中，同时提供完善的退出机制，允许开发者在不需要时轻松移除 Hook。

### 2.3.2 功能设计

**注册命令**：

```bash
# 注册到当前项目的 Git Hook
security-scan hook install

# 注册时指定扫描配置
security-scan hook install --config .security-scan.yml

# 注册到全局 Git Hook 模板（新项目自动生效）
security-scan hook install --global
```

**退出命令**：

```bash
# 从当前项目移除 Hook
security-scan hook uninstall

# 从全局 Git Hook 模板移除
security-scan hook uninstall --global

# 临时禁用 Hook（不删除，仅重命名）
security-scan hook disable

# 重新启用已禁用的 Hook
security-scan hook enable
```

**注册机制说明**：

- 注册时在 `.git/hooks/pre-commit` 中写入调用 security-scan 的 Shell 脚本
- 注册前检测是否已存在其他 pre-commit hook，若存在则进行智能合并（追加而非覆盖）
- 退出时仅移除 security-scan 相关内容，保留其他 Hook 逻辑
- 注册完成后输出验证信息，确认 Hook 已正确安装

---

## 2.4 误判防护机制

### 2.4.1 需求描述

在实际扫描过程中，扫描器需要具备智能的误判防护能力，避免将非敏感信息错误标记为安全问题。特别是在 Java Spring 项目中，`@Value` 注解的默认值经常包含 `true`、`false`、`0`、`1` 等非密码值，这些不应被误报为弱密码。

### 2.4.2 常见误判场景与防护策略

| 误判场景 | 示例 | 防护策略 |
|----------|------|----------|
| @Value 布尔默认值 | `@Value("${feature.enabled:true}")` | AST 识别注解上下文，排除布尔值 |
| @Value 数值默认值 | `@Value("${max.retry:3}")` | AST 识别数值类型默认值 |
| @Value 枚举默认值 | `@Value("${mode:DEV}")` | 白名单匹配已知枚举值 |
| 日志占位符 | `log.info("password: {}", password)` | 上下文分析，识别日志模板 |
| 测试数据 | `assertEquals("test123", result)` | 排除 test 目录中的非敏感匹配 |
| URL 中的端口号 | `localhost:8080` | 识别 URL 模式，排除端口号 |
| 版本号 | `version=1.0.0` | 正则排除版本号模式 |
| 已加密值 | `password = "BEE_abc123xyz=="` | 匹配加密值前缀（如 `BEE_`），识别为已加密数据，详见 2.4.5 节 |

### 2.4.3 白名单机制

- **项目级白名单**：通过 `.security-scan-whitelist` 文件配置，支持按文件路径、行号、正则表达式排除特定匹配
- **全局白名单**：通过 `~/.security-scan/whitelist.yml` 配置全局排除规则
- **行内忽略**：支持在代码行尾添加 `// security-scan:ignore` 注释来忽略特定行
- **误判率目标**：整体误判率控制在 5% 以内

### 2.4.4 AST 级别的误判防护

对于 Java 代码，security-scan 将利用 AST 解析技术实现语义级别的误判防护：

- 解析 `@Value` 注解表达式，提取属性名和默认值
- 通过类型推断判断默认值是否为布尔值、数值等非密码类型
- 分析变量命名约定（如 `enabled`、`debug`、`port` 等命名暗示非密码语义）
- 结合数据流分析，判断字符串是否被赋值给密码相关字段

### 2.4.5 加密值前缀配置

#### 需求背景

公司内部通常使用统一的加密服务对敏感数据进行加密，加密后的字符串带有固定的标识前缀（如 `BEE_`、`ENC(`、`{cipher}` 等）。这类加密值虽然看起来像"密文"，但实际上是**经过安全处理的合法加密数据**，不应被误报为"明文密码"或"硬编码密钥"。

#### 设计

提供 `encrypted_prefixes` 配置项，允许用户指定一个或多个加密值前缀。规则引擎在匹配到字符串类型的敏感值时，会先检查其是否以配置的前缀开头——若是，则跳过该匹配，不产生告警。

```yaml
# .security-scan.yml
encrypted_prefixes:
  - "BEE_"          # 公司自研加密服务输出前缀
  - "ENC("          # jasypt 加密前缀
  - "{cipher}"      # Spring Cloud Config 加密前缀
  - "$2a$"          # BCrypt 哈希前缀
  - "$5$"           # SHA-256 哈希前缀
  - "$6$"           # SHA-512 哈希前缀
```

#### 匹配规则

| 场景 | 配置 | 匹配内容 | 是否告警 |
|------|------|----------|----------|
| 加密值 | `prefixes: ["BEE_"]` | `password = "BEE_7x9k2m4n8q"` | ❌ 不告警（已加密） |
| 明文密码 | `prefixes: ["BEE_"]` | `password = "123456"` | ✅ 告警（无加密前缀） |
| 非加密值巧合 | `prefixes: ["BEE_"]` | `username = "BEETLE"` | ❌ 不告警（严格前缀匹配，非子串匹配） |

#### 输出标记

当匹配到的值带有加密前缀时，扫描结果中标记 `encrypted: true`，并在报告中归类为"已加密值（非风险）"类别，供审计追溯：

```json
{
  "matched_content": "BEE_7x9k2m4n8q",
  "issue_type": "PLAINTEXT_PASSWORD",
  "encrypted": true,
  "encrypted_prefix_matched": "BEE_",
  "severity": "LOW",
  "severity_name": "提示",
  "confidence": 0.0,
  "remediation": "该值已被识别为加密数据，无需处理（如需调整规则，请修改 encrypted_prefixes 配置）"
}
```

#### 误判率影响

| 配置项 | 适用企业 | 典型误判率降低 |
|--------|---------|---------------|
| 未配置（默认） | 所有企业 | 基线水平 |
| 配置 `BEE_` 等前缀 | 使用自研加密的公司 | 降低约 10%-20%（因企业加密使用率而异） |
| 配置 `ENC(` + `{cipher}` | 使用 jasypt / Spring Cloud Config | 降低约 5%-10% |

---

## 2.5 AST 扫描技术方案

### 2.5.1 AST 技术概述

AST（Abstract Syntax Tree，抽象语法树）是源代码语法结构的树状表示形式。每个节点代表源代码中的一个语法构造，如变量声明、方法调用、注解等。基于 AST 的代码扫描通过解析源代码的语法结构，能够实现语义级别的精准分析，远超传统正则表达式的匹配能力。

### 2.5.2 Python 解析 Java AST 的技术选型

| 技术方案 | 说明 | 优势 | 劣势 |
|----------|------|------|------|
| **tree-sitter** | 增量解析框架，支持多语言 | 解析速度快、支持增量解析、社区活跃 | 需要编译语言库 |
| **javalang** | 纯 Python 的 Java 解析库 | 纯 Python 实现、API 简洁 | 解析速度较慢、对 Java 新语法支持有限 |
| **JavaParser (via subprocess)** | 调用 Java 工具解析 | 解析最完整、支持最新 Java 语法 | 依赖 JVM 环境 |

**推荐方案**：优先采用 **tree-sitter** 作为核心 AST 解析引擎，辅以 **javalang** 作为补充解析方案。tree-sitter 具有极高的解析性能（增量解析），且支持包括 Java 在内的多种编程语言，适合作为安全扫描工具的底层引擎。

### 2.5.3 AST 扫描 vs 正则表达式扫描对比

| 对比维度 | 正则表达式扫描 | AST 扫描 |
|----------|----------------|----------|
| **理解代码语义** | 无法理解，仅做文本匹配 | 能理解语法结构和语义 |
| **误判率** | 较高（30%-50%） | 较低（< 5%） |
| **漏判率** | 较高（复杂场景易漏） | 较低（语义分析更全面） |
| **注解处理** | 无法精确解析注解参数 | 可精确提取注解内容和默认值 |
| **字符串拼接** | 无法追踪变量值 | 可分析字符串拼接和数据流 |
| **上下文感知** | 无上下文概念 | 理解变量作用域和类型 |
| **性能** | 极快 | 较快（tree-sitter 增量解析） |
| **维护成本** | 正则规则难以维护 | 规则基于语法结构，更易维护 |
| **多语言支持** | 通用性强 | 需要各语言语法定义 |

### 2.5.4 AST 扫描的核心优势

1. **语义精准**：能区分 `password = "123456"`（明文密码）和 `@Value("${enabled:true}")`（布尔默认值），正则表达式难以做到
2. **注解解析**：精确解析 `@Value`、`@Autowired`、`@ConfigurationProperties` 等 Spring 注解，提取属性名和默认值
3. **数据流追踪**：追踪敏感字符串的赋值和传递路径，判断是否最终用于密码相关用途
4. **类型推断**：通过变量类型（boolean、int、String）推断默认值是否为密码
5. **结构化规则**：安全规则基于 AST 节点类型编写，比正则表达式更直观、更易维护
6. **增量解析**：tree-sitter 支持增量解析，仅重新解析变更部分，大幅提升扫描性能

### 2.5.5 AST 扫描的局限性

- 无法检测运行时生成的密码（如动态加密后的字符串）
- 对混淆代码的解析能力有限
- 需要维护各语言版本的语法规则文件
- 无法理解业务逻辑层面的安全问题

---

## 2.6 多文件格式支持

### 2.6.1 需求描述

security-scan 需要支持对 Java 项目中常见的多种文件格式进行安全扫描，覆盖源代码和配置文件两大类。

### 2.6.2 支持的文件格式及扫描策略

| 文件格式 | 扩展名 | 扫描策略 | 扫描重点 |
|----------|--------|----------|----------|
| **Java 源码** | `.java` | AST 解析 + 正则补充 | 明文密码、硬编码密钥、SQL 注入风险 |
| **XML** | `.xml` | 正则 + XPath 解析 | 数据源密码、API 密钥、连接字符串 |
| **JSON** | `.json` | JSON 解析 + 正则 | 配置中的密码字段、密钥字段 |
| **YAML** | `.yml`, `.yaml` | YAML 解析 + 正则 | Spring 配置密码、数据库连接信息 |
| **Properties** | `.properties` | 键值对解析 + 正则 | `password=`、`secret=`、`key=` 等键值 |
| **TXT** | `.txt` | 正则匹配 | 明文密码、密钥字符串 |
| **Markdown** | `.md` | 正则匹配（排除代码块） | 文档中泄露的密码和密钥 |

### 2.6.3 配置文件扫描规则

配置文件是敏感信息泄露的高发区域，security-scan 将针对配置文件内置以下扫描规则：

**高风险键名模式**：

- `password`、`passwd`、`pwd`
- `secret`、`secret_key`、`secret.key`
- `api_key`、`apikey`、`api-key`
- `access_key`、`access_key_secret`
- `token`、`auth_token`、`bearer_token`
- `connection_string`、`jdbc_url`、`redis.password`
- `private_key`、`ssh_key`

**高风险值模式**：

- Base64 编码的长字符串（可能为编码后的密钥）
- UUID 格式的字符串（可能为 API 密钥）
- 特定前缀的字符串（如 `AKIA` 开头的 AWS Access Key）
- JDBC 连接字符串中的密码部分

### 2.6.4 文件格式扩展机制

security-scan 将采用插件化的文件格式支持架构，允许用户通过配置文件添加自定义文件格式的扫描规则：

```yaml
# .security-scan.yml
file_formats:
  - name: custom_config
    extensions: [".conf", ".cfg"]
    scan_strategy: regex
    rules:
      - pattern: "password\\s*=\\s*(.+)"

  - name: env_file
    extensions: [".env"]
    scan_strategy: key_value
    high_risk_keys: ["DB_PASSWORD", "API_KEY", "SECRET_KEY"]
```

---

## 2.7 AI 辅助扫描（二次分类模式）

### 2.7.1 需求描述

在规则引擎（AST + 正则）完成初步扫描后，引入 AI 大语言模型（LLM）对扫描结果进行二次智能分类。AI 模型不直接扫描代码，而是对规则引擎输出的候选结果进行 **确认/误判** 的二分类判断，从而进一步降低误判率。

### 2.7.2 AI 辅助工作流程

```
规则引擎扫描完成
    ↓
输出候选敏感信息列表（含上下文）
    ↓
AI 分类器逐条分析
    ↓
  ┌──────────────┬──────────────┐
  │ 确认为敏感信息  │ 判定为误报     │
  ↓              ↓              ↓
保留在最终报告中  标记为误报并移除  记录误判原因（可追溯）
```

### 2.7.3 AI 分类器的输入设计

每条候选结果发送给 AI 模型时，需包含以下上下文信息以确保分类准确性：

| 输入字段 | 说明 | 示例 |
|----------|------|------|
| 文件路径 | 所在文件的全路径 | `src/main/java/com/example/Config.java` |
| 行号 | 匹配内容所在行号 | 第 42 行 |
| 匹配内容 | 规则引擎匹配到的敏感字符串 | `"123456"` |
| 上下文代码 | 匹配行前后各 5 行代码 | 完整方法/注解上下文 |
| AST 节点信息 | 该字符串在 AST 中的节点类型 | `@Value 注解默认值` |
| 规则类型 | 触发的规则名称和类型 | `PLAINTEXT_PASSWORD` |
| 变量名/字段名 | 相关的变量名或配置键名 | `feature.enabled` |

### 2.7.4 AI 分类 Prompt 设计

AI 分类器使用结构化 Prompt 进行判断，核心逻辑如下：

```
你是一个代码安全分析专家。请判断以下代码片段中匹配到的字符串是否为真正的敏感信息（如密码、密钥、Token 等）。

【文件路径】{file_path}
【行号】{line_number}
【匹配内容】{matched_content}
【上下文代码】
{context_code}

【判断规则】
1. 如果是 @Value 注解中的布尔值（true/false）、数值、枚举值等非密码默认值 → 误报
2. 如果是日志模板中的占位符 → 误报
3. 如果是测试代码中的模拟数据 → 误报
4. 如果是版本号、端口号、URL 等非敏感信息 → 误报
5. 如果是真正的密码、密钥、Token、连接串等 → 确认敏感信息

请以 JSON 格式输出：
{"is_sensitive": true/false, "confidence": 0.0-1.0, "reason": "判断理由"}
```

### 2.7.5 AI 模式配置

```yaml
# .security-scan.yml
ai:
  enabled: true                          # 是否启用 AI 辅助分类
  mode: "secondary_classification"       # 模式：二次分类（非直接扫描）
  provider: "openai"                     # AI 服务提供商
  model: "gpt-4o-mini"                  # 模型名称
  api_key_env: "SECURITY_SCAN_AI_KEY"   # API Key 环境变量名
  base_url: "https://api.openai.com/v1" # API 地址（支持自定义）
  timeout: 10                           # 单次请求超时（秒）
  max_retries: 3                         # 最大重试次数
  batch_size: 20                         # 批量分类大小
  confidence_threshold: 0.7             # 置信度阈值，低于此值保留原始结果
  fallback_on_error: "keep_original"    # AI 不可用时：keep_original / mark_unreviewed
```

### 2.7.6 AI 辅助模式的核心设计原则

| 设计原则 | 说明 |
|----------|------|
| **规则优先** | 规则引擎始终作为第一道防线，AI 仅做二次优化 |
| **可降级** | AI 服务不可用时自动降级为纯规则模式，不影响核心扫描功能 |
| **可追溯** | 每条 AI 分类结果记录判断理由，支持人工审计 |
| **批量处理** | 支持批量发送候选结果，减少 API 调用次数和延迟 |
| **成本控制** | 仅对规则引擎的候选结果调用 AI，而非全量代码，大幅降低 Token 消耗 |
| **多模型支持** | 支持 OpenAI、Azure OpenAI、本地部署模型（Ollama）等多种后端 |

### 2.7.7 性能与成本估算

| 场景 | 规则引擎候选数量 | AI 调用次数 | 预估 Token 消耗 | 预估延迟 |
|------|-----------------|-------------|-----------------|----------|
| 增量扫描（10 个变更文件） | 5-20 条 | 1 次（批量） | ~2000 Token | +2-3 秒 |
| 全量扫描（中型项目） | 50-200 条 | 3-10 次（批量） | ~20000 Token | +10-30 秒 |
| 全量扫描（大型项目） | 200-1000 条 | 10-50 次（批量） | ~100000 Token | +1-3 分钟 |

---

## 2.8 扫描结果分级分类

### 2.8.1 需求描述

security-scan 需要对识别出的每个安全问题进行多维度的分级分类，帮助开发团队和安全团队快速定位和处理风险。每条扫描结果必须包含：**类型分类**、**严重等级**、**置信度**三个核心维度。

### 2.8.2 类型分类（Issue Type）

| 类型代码 | 类型名称 | 说明 | 典型示例 |
|----------|----------|------|----------|
| `PLAINTEXT_PASSWORD` | 明文密码 | 代码中直接以明文形式书写的密码 | `password = "123456"` |
| `WEAK_PASSWORD` | 弱密码 | 强度不足、容易被暴力破解的密码 | `password = "admin"` |
| `HARDCODED_SECRET` | 硬编码密钥 | 代码中硬编码的 API 密钥、Secret Key | `secretKey = "AKIAIOSFODNN7EXAMPLE"` |
| `HARDCODED_TOKEN` | 硬编码 Token | 代码中硬编码的认证 Token | `token = "Bearer eyJhbG..."` |
| `CONNECTION_STRING` | 连接字符串泄露 | 包含密码的数据库/缓存连接串 | `jdbc:mysql://user:pass@host/db` |
| `PRIVATE_KEY` | 私钥泄露 | 代码中包含私钥内容 | `-----BEGIN RSA PRIVATE KEY-----` |
| `CREDENTIAL_IN_CONFIG` | 配置文件凭证泄露 | 配置文件中的密码/密钥配置 | `spring.datasource.password=xxx` |
| `PASSWORD_IN_COMMENT` | 密码泄露在注释中 | 注释中记录的密码信息 | `// TODO: password is temp123` |
| `DEFAULT_CREDENTIAL` | 默认凭证 | 使用框架/组件的默认密码 | `admin/admin`、`root/root` |
| `SENSITIVE_LOG` | 敏感信息日志 | 日志中输出敏感信息 | `log.info("password: {}", pwd)` |

### 2.8.3 严重等级（Severity Level）

严重等级基于泄露信息的敏感程度、可利用性和影响范围综合判定：

| 等级 | 标识 | 颜色 | 判定标准 | 处理要求 |
|------|------|------|----------|----------|
| **高危** | `CRITICAL` | 🔴 红色 | 生产环境明文密码、私钥、生产数据库连接串 | **必须立即修复，阻断提交** |
| **中危** | `HIGH` | 🟠 橙色 | 测试环境密码、API Secret、硬编码 Token | **建议本次迭代修复** |
| **低危** | `MEDIUM` | 🟡 黄色 | 弱密码、配置文件中的非生产凭证、注释中的密码 | **建议排期修复** |
| **提示** | `LOW` | 🟢 绿色 | 疑似敏感信息但置信度较低、历史遗留的测试数据 | **关注即可，不阻断** |

**严重等级判定规则**：

```
IF 类型 IN [PLAINTEXT_PASSWORD, PRIVATE_KEY, CONNECTION_STRING]
   AND 文件路径包含 ["prod", "production", "release"]
   AND 置信度 >= 0.8
   → CRITICAL

IF 类型 IN [HARDCODED_SECRET, HARDCODED_TOKEN, DEFAULT_CREDENTIAL]
   AND 置信度 >= 0.7
   → HIGH

IF 类型 IN [WEAK_PASSWORD, CREDENTIAL_IN_CONFIG, PASSWORD_IN_COMMENT]
   AND 置信度 >= 0.6
   → MEDIUM

其他情况 → LOW（仅记录，不阻断）
```

### 2.8.4 置信度（Confidence Score）

置信度表示扫描结果的可信程度，由规则引擎和 AI 分类器共同计算：

| 置信度来源 | 权重 | 说明 |
|------------|------|------|
| 规则引擎置信度 | 60% | 基于规则匹配强度（精确匹配 > 模糊匹配） |
| AST 上下文分析 | 20% | 基于 AST 语义分析的上下文一致性评分 |
| AI 分类置信度 | 20% | AI 模型返回的 `confidence` 值（未启用 AI 时权重归 0） |

**综合置信度计算公式**：

```
confidence = (rule_confidence * 0.6) + (ast_context_score * 0.2) + (ai_confidence * 0.2)
```

| 置信度区间 | 含义 | 处理策略 |
|------------|------|----------|
| 0.90 - 1.00 | 极高置信 | 直接确认，无需人工复核 |
| 0.70 - 0.89 | 高置信 | 默认确认，可在报告中标记为"高可信度" |
| 0.50 - 0.69 | 中等置信 | 保留在报告中，建议人工复核 |
| 0.30 - 0.49 | 低置信 | 标记为"待确认"，不阻断提交 |
| 0.00 - 0.29 | 极低置信 | 视为误报，自动过滤 |

### 2.8.5 分级分类的输出格式

每条扫描结果以结构化 JSON 输出，包含完整的分级分类信息：

```json
{
  "id": "scan-20260603-001",
  "file_path": "src/main/java/com/example/DatabaseConfig.java",
  "line_number": 42,
  "column_start": 15,
  "column_end": 35,
  "matched_content": "password123",
  "issue_type": "PLAINTEXT_PASSWORD",
  "issue_type_name": "明文密码",
  "severity": "CRITICAL",
  "severity_name": "高危",
  "confidence": 0.92,
  "rule_name": "java_plaintext_password",
  "rule_confidence": 0.95,
  "ast_context_score": 0.90,
  "ai_confidence": 0.85,
  "ai_reason": "变量名 'dbPassword' 明确指向数据库密码，且赋值为明文字符串",
  "context_code": "    @Value(\"${db.password:password123}\")\n    private String dbPassword;",
  "remediation": "使用环境变量或密钥管理服务（如 Vault）替代硬编码密码",
  "created_at": "2026-06-03T10:30:00Z"
}
```

### 2.8.6 分级分类的过滤与阻断策略

| 扫描模式 | 阻断阈值 | 说明 |
|----------|----------|------|
| **增量扫描（pre-commit）** | CRITICAL + HIGH | 发现高危或中危问题时阻断提交 |
| **全量扫描（主动触发）** | 无阻断 | 生成完整报告，不阻断任何操作 |
| **CI/CD 集成（预留）** | CRITICAL | 远期特性，仅阻断高危问题，允许中危及以下通过（详见 2.9 节） |

**可配置阻断策略**：

```yaml
# .security-scan.yml
severity:
  block_on_commit:
    - CRITICAL
    - HIGH
  block_on_ci:                          # 预留配置，CI/CD 集成远期生效（详见 2.9 节）
    - CRITICAL
  min_confidence_to_report: 0.50
  min_confidence_to_block: 0.70
```

### 2.8.7 报告中的分级展示

扫描报告按严重等级分组展示，高危问题优先显示：

```
═══════════════════════════════════════════════
  security-scan 扫描报告
═══════════════════════════════════════════════

🔴 高危问题 (3)
───────────────────────────────────────────────
[CRITICAL] 明文密码  置信度: 92%
  文件: src/main/java/DatabaseConfig.java:42
  内容: password = "password123"
  建议: 使用环境变量替代硬编码密码

🟠 中危问题 (5)
───────────────────────────────────────────────
[HIGH] 硬编码密钥  置信度: 85%
  文件: src/main/resources/application.yml:15
  内容: api-key: AKIAIOSFODNN7EXAMPLE
  建议: 使用密钥管理服务

🟡 低危问题 (2)
🟢 提示 (1)
───────────────────────────────────────────────
总计: 11 个问题 | 已阻断: 3 个高危问题
```

**注**：上述报告示例中的 emoji 符号（🔴🟠🟡🟢）在 Windows CMD（GBK 编码）下会自动降级为文字符号 `[危]` `[高]` `[中]` `[低]`，确保各平台正常显示。详见第 4 章 4.2.4 编码兼容性要求。

---

## 2.9 CI/CD 集成接口预留设计

### 2.9.1 设计定位

CI/CD 流水线的深度集成是 security-scan 的**远期特性**，当前版本不包含以下能力：

- 不提供 Jenkins / GitLab CI / GitHub Actions 等 CI/CD 平台的官方插件或集成脚本
- 不在 CI 流水线中默认阻断构建
- 不支持 CI 环境下的自动报告上传（如 GitHub Code Scanning SARIF 上传）

但为了确保未来平滑过渡，当前版本在架构设计上预留了 CI/CD 集成所需的接口规范，确保后续版本无需破坏性变更即可对接 CI/CD 流水线。

### 2.9.2 CI/CD 集成场景

远期 CI/CD 集成主要面向以下场景：

| 场景 | 说明 | 预期工作方式 |
|------|------|-------------|
| **合并请求前置扫描** | 开发者在 Git 平台发起 PR/MR 时自动扫描变更代码 | CI 流水线执行 `security-scan scan --ci`，结果以 Comment 或 Check Run 形式展示 |
| **定时全量扫描** | 每日定时扫描整个仓库，生成安全报告 | CI 定时任务执行 `security-scan scan --path .`，结果归档至制品库 |
| **发布前门禁** | 代码合并到 release 分支前执行安全门禁检查 | CI 执行 `security-scan scan --ci --gate`，高危问题阻断发布 |

### 2.9.3 预留接口规范

#### 退出码规范

security-scan 为 CI/CD 集成预留了一套标准的退出码，不同退出码对应不同扫描结果状态，CI 流水线可基于退出码决定是否阻断构建：

| 退出码 | 含义 | CI 处理建议 | 说明 |
|--------|------|------------|------|
| `0` | 扫描完成，未发现安全问题 | ✅ 构建通过 | 无需处理 |
| `1` | 扫描完成，发现安全问题（含高危） | ❌ 建议阻断 | 至少存在一个 CRITICAL 或 HIGH 级别的问题 |
| `2` | 扫描完成，发现安全问题（仅中/低危） | ⚠️ 警告，不阻断 | 问题等级低于阻断阈值 |
| `10` | 扫描中断（用户取消或超时） | 🔄 重新触发 | 非正常结束，建议重试 |
| `20` | 配置错误（配置解析失败、参数无效） | ❌ 阻断 | 需检查配置文件 |
| `21` | 依赖缺失（tree-sitter 编译失败等） | ❌ 阻断 | 需检查运行环境 |
| `22` | 路径错误（指定的扫描路径不存在或不可读） | ❌ 阻断 | 需检查扫描路径 |
| `30` | 内部错误（未预期的异常） | ❌ 阻断 | 需排查工具运行日志 |

**退出码判断逻辑**（伪代码）：

```python
def determine_exit_code(results, config):
    """根据扫描结果和配置确定退出码"""
    if has_critical_error(config):
        return 20  # 配置错误

    if has_fatal_runtime_error():
        return 30  # 内部错误

    if not results:
        return 0   # 未发现安全问题

    severities = [r.severity for r in results if r.confidence >= config.min_confidence_to_report]

    block_levels = config.get('block_on_ci', ['CRITICAL'])
    has_blocked = any(s in block_levels for s in severities)

    if has_blocked:
        return 1   # 存在需要阻断的问题
    elif severities:
        return 2   # 存在安全问题但低于阻断阈值
    else:
        return 0   # 所有结果置信度低于报告阈值，视为无问题
```

#### `--ci` 模式的行为约定

当前版本中，`--ci` 参数仅作为一个**标记位**被接收和解析，其行为与普通模式一致（不阻断、不产生交互式输出）。但预留了以下行为约定，供后续版本实现：

```yaml
# .security-scan.yml（预留的 CI 模式配置）
ci:
  enabled: false                          # 当前版本默认为 false
  block_on: ["CRITICAL"]                  # CI 模式下阻断的问题等级
  exit_code_on_block: 1                   # 阻断时的退出码
  output_format: "json"                   # CI 模式下默认输出格式
  report_artifact: "security-report.json" # 报告产物路径
  max_scan_time: 300                      # CI 模式扫描超时时间（秒）
```

#### 输出格式的 CI 兼容性

当前版本输出的 JSON / SARIF 格式已天然兼容 CI/CD 平台：

| 输出格式 | CI 集成用途 | 对接平台示例 |
|----------|------------|-------------|
| **JSON** | 自定义流水线逻辑解析结果 | Jenkins Pipeline 解析，GitLab CI 解析 |
| **SARIF** | 直接在 PR 中展示代码扫描结果 | GitHub Code Scanning、GitLab SAST |

#### 典型 CI/CD 集成脚本（示例，当前版本即可使用）

虽然没有官方 CI 插件，但用户**现在**就可以通过简单的 Shell 脚本将 security-scan 集成到流水线中（基于已预留的接口规范）：

```bash
#!/bin/bash
# .gitlab-ci.yml 集成示例（当前版本可用）

security-scan-scan:
  stage: test
  script:
    - pip install security-scan
    - security-scan init
    - security-scan scan --path . --output-format json --output-file security-report.json
  artifacts:
    paths:
      - security-report.json
    when: always
```

```yaml
# Jenkinsfile 集成示例（当前版本可用）
stage('Security Scan') {
    steps {
        sh 'pip install security-scan'
        sh 'security-scan init'
        sh 'security-scan scan --path . --output-format json --output-file security-report.json'
    }
    post {
        always {
            archiveArtifacts artifacts: 'security-report.json'
        }
    }
}
```

### 2.9.4 设计原则

| 原则 | 说明 |
|------|------|
| **无侵入** | security-scan 不作为 CI 流水线的强制依赖，即使不配置 CI 集成，本地扫描功能完全正常 |
| **向前兼容** | 预留的退出码规范、`--ci` 参数签名、输出格式在后续版本中不会破坏性变更 |
| **降级友好** | CI 模式下遇到配置缺失、依赖不足等问题时，给出明确错误信息和退出码，方便 CI 流水线定位问题 |
| **标准输出** | CI 模式下禁止交互式提示，所有输出均为结构化 JSON/SARIF，便于流水线解析 |
| **可观测** | 预留 `--progress` 参数支持 CI 日志中的进度条展示（非交互式终端自动禁用颜色和动画） |

### 2.9.5 与 1.3.2 不包含范围的一致性说明

| CI/CD 相关能力 | 当前版本状态 | 说明 |
|----------------|------------|------|
| 官方 CI 插件/模板 | ❌ 不包含 | 需社区或后续版本贡献 |
| CI 流水线自动阻断 | ❌ 不包含 | 需用户自行根据退出码处理 |
| SARIF 自动上传 | ❌ 不包含 | 需用户自行对接 GitHub Code Scanning 等平台 |
| 退出码规范 | ✅ 已预留 | 当前版本即按此规范实现退出码 |
| `--ci` 参数签名 | ✅ 已预留 | 参数可解析，行为与普通模式一致 |
| JSON/SARIF 输出格式 | ✅ 已支持 | 当前版本即可输出，CI 平台可解析 |

---

# 第3章 技术架构设计

## 3.1 系统整体架构

security-scan 采用分层架构设计，整体分为四个核心层次：入口层、扫描引擎层、规则引擎层和输出层。各层之间通过清晰的接口进行交互，确保系统的可维护性和可扩展性。

### 3.1.1 架构分层说明

**入口层（Entry Layer）**：

- **CLI 命令行接口**：基于 `argparse` 或 `click` 实现的命令行工具，提供 `scan`、`hook install`、`hook uninstall` 等子命令
- **Git Hook 接口**：pre-commit hook 脚本，负责触发增量扫描并处理扫描结果
- **配置加载器**：加载项目级和全局级配置文件（`.security-scan.yml`）

**扫描引擎层（Scan Engine Layer）**：

- **文件收集器**：根据扫描模式（全量/增量）收集待扫描文件列表
- **文件分类器**：根据文件扩展名将文件分配给对应的扫描器
- **AST 扫描器**：基于 tree-sitter/javalang 对 Java 文件进行 AST 级别扫描
- **正则扫描器**：对配置文件和其他文本文件进行正则表达式匹配扫描
- **结果聚合器**：汇总所有扫描器的结果，进行去重和优先级排序

**规则引擎层（Rule Engine Layer）**：

- **内置规则库**：预置的敏感信息检测规则，覆盖密码、密钥、Token 等常见类型
- **自定义规则加载器**：加载用户自定义的扫描规则
- **白名单过滤器**：根据白名单配置过滤误报结果
- **上下文分析器**：基于 AST 上下文进行语义分析，降低误判率

**输出层（Output Layer）**：

- **控制台报告器**：实时输出扫描进度和结果到终端
- **HTML 报告生成器**：生成可视化的 HTML 扫描报告
- **JSON/SARIF 导出器**：输出结构化格式，便于工具集成

## 3.2 核心模块设计

### 3.2.1 模块划分

```
security-scan/
├── cli/                    # 命令行接口模块
│   ├── __init__.py
│   ├── main.py            # CLI 入口
│   ├── scan_command.py    # scan 子命令
│   └── hook_command.py    # hook 子命令
├── scanner/               # 扫描引擎模块
│   ├── __init__.py
│   ├── collector.py       # 文件收集器
│   ├── classifier.py       # 文件分类器
│   ├── ast_scanner.py     # AST 扫描器
│   ├── regex_scanner.py   # 正则扫描器
│   └── aggregator.py      # 结果聚合器
├── rules/                 # 规则引擎模块
│   ├── __init__.py
│   ├── builtin_rules.py   # 内置规则库
│   ├── custom_rules.py     # 自定义规则
│   ├── whitelist.py       # 白名单过滤器
│   └── context_analyzer.py # 上下文分析器
├── ai/                    # AI 辅助分类模块
│   ├── __init__.py
│   ├── classifier.py       # AI 分类器（二次分类）
│   ├── prompt_builder.py   # Prompt 构建器
│   ├── provider.py         # 多模型适配器（OpenAI/Azure/Ollama）
│   └── batch_processor.py  # 批量处理与结果解析
├── hook/                  # Git Hook 模块
│   ├── __init__.py
│   ├── installer.py       # Hook 安装器
│   ├── uninstaller.py     # Hook 卸载器
│   └── template.py        # Hook 脚本模板
├── output/                # 输出模块
│   ├── __init__.py
│   ├── console.py         # 控制台输出
│   ├── html_report.py     # HTML 报告
│   ├── json_report.py     # JSON 报告
│   └── sarif_report.py    # SARIF 报告
├── config/                # 配置模块
│   ├── __init__.py
│   └── loader.py          # 配置加载器
├── utils/                 # 工具模块
│   ├── __init__.py
│   ├── git_utils.py       # Git 操作工具
│   └── file_utils.py      # 文件操作工具
└── tests/                 # 测试模块
```

### 3.2.2 核心模块职责

| 模块 | 核心类 | 职责描述 |
|------|--------|----------|
| CLI | `SecurityScanCLI` | 命令行参数解析、子命令路由 |
| 文件收集器 | `FileCollector` | 全量/增量模式下收集待扫描文件 |
| AST 扫描器 | `ASTScanner` | 基于 tree-sitter 解析 Java AST 并执行规则匹配 |
| 正则扫描器 | `RegexScanner` | 对非 Java 文件执行正则表达式匹配 |
| 规则引擎 | `RuleEngine` | 管理内置规则和自定义规则，执行匹配逻辑 |
| 白名单过滤器 | `WhitelistFilter` | 根据白名单配置过滤扫描结果 |
| 上下文分析器 | `ContextAnalyzer` | 基于 AST 上下文分析，降低误判 |
| AI 分类器 | `AIClassifier` | 对规则引擎候选结果进行 AI 二次确认/误判分类 |
| Prompt 构建器 | `PromptBuilder` | 构建结构化 Prompt，包含代码上下文和判断规则 |
| 多模型适配器 | `AIProvider` | 适配 OpenAI、Azure OpenAI、Ollama 等多种 AI 后端 |
| Hook 安装器 | `HookInstaller` | 将扫描器注册到 Git pre-commit hook |
| 报告生成器 | `ReportGenerator` | 生成多种格式的扫描报告 |
| 结果分类器 | `ResultClassifier` | 对扫描结果进行类型分类、严重等级判定、置信度计算 |

## 3.3 数据流设计

扫描流程的核心数据流如下：

```
用户触发扫描
    ↓
CLI 解析命令和配置
    ↓
FileCollector 收集文件列表
    ↓
FileClassifier 按类型分配扫描器
    ↓
  ┌──────────────┬──────────────┐
  │  .java 文件   │  配置文件      │
  ↓              ↓              ↓
ASTScanner    RegexScanner   RegexScanner
    ↓              ↓              ↓
RuleEngine    RuleEngine     RuleEngine
    ↓              ↓              ↓
ContextAnalyzer  WhitelistFilter
    ↓              ↓              ↓
  └──────────────┴──────────────┘
    ↓
Aggregator 聚合去重
    ↓
ResultClassifier 分级分类（类型/等级/置信度）
    ↓
AIClassifier（可选）二次分类确认/误判
    ↓
ReportGenerator 输出结果
```

## 3.4 关键技术选型

| 技术组件 | 选型方案 | 选型理由 |
|----------|----------|----------|
| AST 解析引擎 | tree-sitter | 高性能增量解析、多语言支持、社区活跃 |
| Java 解析补充 | javalang | 纯 Python 实现、API 友好、适合注解解析 |
| 命令行框架 | click | API 简洁、支持子命令、自动生成帮助文档 |
| 配置管理 | PyYAML | YAML 格式配置文件解析 |
| 正则引擎 | Python re (内置) | 内置库、无需额外依赖、性能足够 |
| HTML 报告 | Jinja2 | 模板引擎灵活、支持自定义报告样式 |
| 并发处理 | concurrent.futures | 内置库、线程池管理简洁 |
| AI 接口 | openai (Python SDK) | 官方 SDK，支持 OpenAI/Azure/兼容接口 |
| 测试框架 | pytest | Python 生态标准测试框架 |

---

# 第4章 非功能需求

## 4.1 性能需求

| 性能指标 | 目标值 | 说明 |
|----------|--------|------|
| 全量扫描速度 | ≤ 60 秒 / 10 万行代码 | 基于 AST 解析的扫描性能基准 |
| 增量扫描速度 | ≤ 3 秒 / 100 个变更文件 | 单次 commit 的扫描耗时上限 |
| 内存占用 | ≤ 512MB | 扫描过程中的峰值内存使用量 |
| 启动时间 | ≤ 1 秒 | 从执行命令到开始扫描的延迟 |
| 并发支持 | 支持 1-16 线程 | 可配置的并行扫描线程数 |

## 4.2 可用性需求

### 4.2.1 操作系统兼容性矩阵

| 操作系统 | 支持版本 | 安装方式 | CLI 工具 | Git Hook | tree-sitter 编译 |
|----------|----------|----------|----------|----------|------------------|
| **Windows** | Windows 10 及以上 | `pip install` | ✅ cmd / PowerShell | ✅ Git Bash / WSL | ✅ 预编译二进制 |
| **macOS** | macOS 10.15（Catalina）及以上 | `pip install` / Homebrew | ✅ 原生 Terminal | ✅ 原生 Terminal | ✅ 预编译二进制 |
| **Linux** | CentOS 7+、Ubuntu 18.04+、Debian 10+ | `pip install` | ✅ Bash / Zsh | ✅ Bash / Zsh | ✅ 源码编译 |

### 4.2.2 各平台详细支持说明

**Windows 支持**：

- 原生支持 Windows 10/11（64 位）
- 提供 PowerShell 和 CMD 双命令行支持
- Git Hook 支持通过 Git Bash 或 WSL（Windows Subsystem for Linux）运行
- tree-sitter 预编译二进制包，无需额外编译
- 文件路径自动处理（支持正斜杠 `/` 和反斜杠 `\` 自动转换）

**macOS 支持**：

- 支持 macOS 10.15（Catalina）及以上版本
- 提供 `pip install` 和 Homebrew 双重安装方式
- 原生支持 Apple Silicon（M1/M2/M3）和 Intel 芯片
- tree-sitter 提供跨架构预编译二进制包
- 与系统自带 Git 无缝集成

**Linux 支持**：

- 主流发行版支持：CentOS 7+、RHEL 8+、Ubuntu 18.04+、Debian 10+、Fedora 35+
- 通过系统包管理器安装 Python 3.8+（`apt`/`yum`/`dnf`）
- 支持 Bash、Zsh、Fish 等主流 Shell
- tree-sitter 优先使用预编译二进制，必要时支持源码编译
- 与系统自带 Git 无缝集成

### 4.2.3 其他可用性需求

| 需求项 | 说明 |
|--------|------|
| **Python 版本** | 支持 Python 3.8、3.9、3.10、3.11、3.12 及以上版本 |
| **Git 版本** | 支持 Git 2.0 及以上版本 |
| **安装便捷性** | 支持通过 `pip install security-scan` 一键安装 |
| **零配置启动** | 安装后无需额外配置即可使用默认规则进行扫描 |
| **帮助文档** | 提供完整的 CLI 帮助信息和使用文档 |

### 4.2.4 编码兼容性要求

**字符编码处理**：

| 场景 | 编码要求 | 处理策略 |
|------|----------|----------|
| **源代码文件读取** | 自动检测文件编码（UTF-8 / GBK / GB2312 / GB18030） | 使用 `chardet` 或 `charset-normalizer` 自动检测编码 |
| **控制台输出** | 适配终端编码（Windows CMD 默认 GBK） | 检测终端编码，必要时进行编码转换 |
| **报告文件生成** | 统一使用 UTF-8 编码 | HTML/JSON/SARIF 报告强制 UTF-8，带 BOM 头 |
| **配置文件解析** | 支持 UTF-8 和 GBK | `.security-scan.yml` 优先 UTF-8，兼容 GBK |

**Windows 系统编码特殊处理**：

Windows 系统默认使用 GBK（Code Page 936）编码，与 macOS/Linux 的 UTF-8 存在差异，需特殊处理：

```python
# 控制台输出编码适配
import sys
import os

def get_console_encoding():
    """获取当前控制台编码"""
    if sys.platform == 'win32':
        # Windows: 使用 chcp 命令获取当前代码页
        import subprocess
        result = subprocess.run(['chcp'], capture_output=True, shell=True)
        # 默认返回 GBK (936)，但现代 Windows Terminal 可能使用 UTF-8 (65001)
        return 'gbk'  # 保守策略：默认 GBK，必要时转换
    return 'utf-8'

def safe_print(text):
    """安全输出，自动处理编码问题"""
    encoding = get_console_encoding()
    if encoding != 'utf-8':
        text = text.encode('utf-8').decode(encoding, errors='replace')
    print(text)
```

**Emoji 符号编码策略**：

在严重等级展示中使用 emoji 符号（🔴🟠🟡🟢）增强可读性，但需处理 Windows GBK 编码下的显示问题：

| 平台 | Emoji 支持 | 处理策略 |
|------|-----------|----------|
| **Windows CMD** | 不支持或显示为方框 | 自动降级为文字符号：`[危]` `[高]` `[中]` `[低]` |
| **Windows PowerShell** | 部分支持（取决于版本） | 检测 PowerShell 版本，5.x 以下降级为文字符号 |
| **Windows Terminal** | 完全支持 | 正常使用 emoji |
| **macOS Terminal** | 完全支持 | 正常使用 emoji |
| **Linux Terminal** | 完全支持 | 正常使用 emoji |

**Emoji 降级映射表**：

```python
EMOJI_SEVERITY = {
    'utf-8': {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    },
    'gbk': {
        'CRITICAL': '[危]',
        'HIGH': '[高]',
        'MEDIUM': '[中]',
        'LOW': '[低]'
    }
}

def get_severity_icon(severity, encoding='utf-8'):
    """根据编码返回对应的严重等级图标"""
    if encoding.lower() in ['gbk', 'gb2312', 'cp936']:
        return EMOJI_SEVERITY['gbk'].get(severity, '[?]')
    return EMOJI_SEVERITY['utf-8'].get(severity, '?')
```

**文件编码自动检测实现**：

```python
import chardet

def read_file_with_encoding_detection(file_path):
    """自动检测文件编码并读取"""
    with open(file_path, 'rb') as f:
        raw_data = f.read()

    # 检测编码
    result = chardet.detect(raw_data)
    encoding = result['encoding'] or 'utf-8'
    confidence = result['confidence']

    # 对中文编码做保守处理
    if encoding.lower() in ['gb2312', 'gbk', 'gb18030']:
        encoding = 'gb18030'  # 使用最宽泛的 GB18030

    # 解码内容
    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError:
        # 解码失败时尝试 UTF-8 with BOM 或 latin-1
        content = raw_data.decode('utf-8-sig', errors='replace')

    return content, encoding, confidence
```

## 4.3 环境依赖与自动安装

### 4.3.1 运行时环境要求

security-scan 的运行时环境要求极简，**仅依赖 Python 3.8 及以上版本**，所有其他依赖在初始化时自动检测并安装。

| 依赖项 | 最低版本 | 是否必需 | 安装方式 |
|--------|----------|----------|----------|
| **Python** | 3.8 | ✅ 必需 | 系统预装或手动安装 |
| **pip** | 21.0 | ✅ 必需 | Python 自带 |
| **Git** | 2.0 | ✅ 必需（Hook 功能） | 系统预装 |
| **tree-sitter** | 0.20 | ❌ 可选（初始化自动安装） | `pip install` |
| **javalang** | 1.3 | ❌ 可选（初始化自动安装） | `pip install` |
| **openai** | 1.0 | ❌ 可选（AI 功能，初始化自动安装） | `pip install` |
| **chardet** | 5.0 | ❌ 可选（初始化自动安装） | `pip install` |
| **PyYAML** | 6.0 | ❌ 可选（初始化自动安装） | `pip install` |
| **click** | 8.0 | ❌ 可选（初始化自动安装） | `pip install` |
| **Jinja2** | 3.0 | ❌ 可选（初始化自动安装） | `pip install` |

### 4.3.2 pip 仓库配置（支持公司私有仓库）

security-scan 支持配置自定义 pip 仓库地址，满足公司内部网络环境需求：

**配置方式一：环境变量**

```bash
# Linux / macOS
export PIP_INDEX_URL="https://pypi.company.com/simple"
export PIP_TRUSTED_HOST="pypi.company.com"

# Windows CMD
set PIP_INDEX_URL=https://pypi.company.com/simple
set PIP_TRUSTED_HOST=pypi.company.com

# Windows PowerShell
$env:PIP_INDEX_URL="https://pypi.company.com/simple"
$env:PIP_TRUSTED_HOST="pypi.company.com"
```

**配置方式二：pip 配置文件**

```ini
# Linux/macOS: ~/.pip/pip.conf
# Windows: %APPDATA%\pip\pip.ini

[global]
index-url = https://pypi.company.com/simple
trusted-host = pypi.company.com

[install]
use-mirrors = true
mirrors = https://pypi.company.com/simple
```

**配置方式三：security-scan 配置文件**

```yaml
# .security-scan.yml
pip:
  index_url: "https://pypi.company.com/simple"
  trusted_host: "pypi.company.com"
  extra_index_urls:
    - "https://pypi.org/simple"  # 备用官方源
  cert: "/path/to/company-ca.crt"  # 自定义 CA 证书（HTTPS 自签证书场景）
  timeout: 30
  retries: 3
```

### 4.3.3 初始化时的自动检测与安装

security-scan 在首次运行时执行初始化流程，自动检测并安装缺失的依赖：

```
security-scan 首次运行
    ↓
检测 Python 版本 >= 3.8
    ↓
  ┌────┴────┐
  │ 版本检查  │
  ├─────────┤
  │ 通过     │ → 继续初始化
  │ 不通过   │ → 报错退出，提示升级 Python
  └─────────┘
    ↓
检测 pip 配置（私有仓库 / 官方源）
    ↓
检测核心依赖是否已安装
    ↓
  ┌────┴────┐
  │ 依赖检查  │
  ├─────────┤
  │ 全部已安装 │ → 跳过安装
  │ 部分缺失   │ → 自动 pip install 安装
  └─────────┘
    ↓
tree-sitter 语言库编译/下载
    ↓
初始化完成，开始扫描
```

**初始化命令**：

```bash
# 显式执行初始化（首次运行会自动触发）
security-scan init

# 强制重新初始化（更新依赖或修复环境）
security-scan init --force

# 指定 pip 仓库初始化
security-scan init --index-url https://pypi.company.com/simple

# 离线初始化（使用本地预下载的依赖包）
security-scan init --offline --deps-dir /path/to/pre-downloaded-deps
```

**自动安装实现代码示例**：

```python
import sys
import subprocess
import importlib

REQUIRED_DEPENDENCIES = {
    'tree_sitter': 'tree-sitter>=0.20.0',
    'javalang': 'javalang>=1.3.0',
    'yaml': 'PyYAML>=6.0',
    'click': 'click>=8.0.0',
    'jinja2': 'Jinja2>=3.0.0',
    'chardet': 'chardet>=5.0.0',
}

OPTIONAL_DEPENDENCIES = {
    'openai': 'openai>=1.0.0',  # AI 功能可选
}

def check_python_version():
    """检查 Python 版本"""
    if sys.version_info < (3, 8):
        print(f"错误: Python {sys.version_info.major}.{sys.version_info.minor} 版本过低")
        print("security-scan 需要 Python 3.8 或更高版本")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

def check_and_install_dependencies(deps, pip_config=None):
    """检测并安装缺失的依赖"""
    missing = []
    for module_name, package_spec in deps.items():
        try:
            importlib.import_module(module_name)
            print(f"✓ {package_spec} 已安装")
        except ImportError:
            missing.append(package_spec)
            print(f"✗ {package_spec} 未安装，将自动安装...")

    if missing:
        install_deps(missing, pip_config)

def install_deps(packages, pip_config=None):
    """执行 pip install 安装依赖"""
    cmd = [sys.executable, '-m', 'pip', 'install']

    if pip_config:
        if pip_config.get('index_url'):
            cmd.extend(['--index-url', pip_config['index_url']])
        if pip_config.get('trusted_host'):
            cmd.extend(['--trusted-host', pip_config['trusted_host']])
        if pip_config.get('cert'):
            cmd.extend(['--cert', pip_config['cert']])

    cmd.extend(packages)

    print(f"正在安装依赖: {' '.join(packages)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"安装失败: {result.stderr}")
        sys.exit(1)
    print("✓ 依赖安装完成")

def init_environment(config=None):
    """初始化运行环境"""
    print("=" * 50)
    print("security-scan 环境初始化")
    print("=" * 50)

    # 1. 检查 Python 版本
    check_python_version()

    # 2. 检测 pip 配置
    pip_config = config.get('pip', {}) if config else {}
    if pip_config.get('index_url'):
        print(f"使用自定义 pip 仓库: {pip_config['index_url']}")

    # 3. 安装核心依赖
    check_and_install_dependencies(REQUIRED_DEPENDENCIES, pip_config)

    # 4. 安装可选依赖（AI 功能）
    if config and config.get('ai', {}).get('enabled'):
        check_and_install_dependencies(OPTIONAL_DEPENDENCIES, pip_config)

    # 5. 编译/下载 tree-sitter 语言库
    setup_tree_sitter_languages()

    print("=" * 50)
    print("✓ 初始化完成，可以开始使用 security-scan")
    print("=" * 50)
```

### 4.3.4 离线环境支持

对于无法连接外网的公司内部环境，security-scan 支持离线初始化：

```bash
# 步骤1: 在有网络的机器上预下载依赖
pip download security-scan -d ./security-scan-deps
pip download tree-sitter javalang PyYAML click Jinja2 chardet -d ./security-scan-deps

# 步骤2: 将依赖包复制到离线环境
scp -r ./security-scan-deps user@offline-server:/tmp/

# 步骤3: 在离线环境执行初始化
security-scan init --offline --deps-dir /tmp/security-scan-deps
```

## 4.4 安全性需求

| 需求项 | 说明 |
|--------|------|
| **扫描结果保密** | 扫描结果仅在本地输出，不上传任何数据到外部服务器 |
| **规则加密** | 自定义规则文件支持加密存储，防止规则泄露 |
| **权限控制** | 扫描操作遵循当前操作系统的文件系统权限 |
| **日志安全** | 日志中不记录扫描到的敏感信息的具体内容，仅记录位置和类型 |
| **自身安全** | 工具自身不引入安全漏洞，依赖库定期更新 |

## 4.5 可扩展性需求

| 需求项 | 说明 |
|--------|------|
| **规则插件化** | 支持用户编写自定义扫描规则插件 |
| **文件格式扩展** | 支持通过配置添加新的文件格式扫描支持 |
| **输出格式扩展** | 支持通过插件机制添加新的报告输出格式 |
| **语言扩展** | 架构设计支持未来扩展到其他编程语言（如 Python、Go） |
| **Hook 类型扩展** | 除 pre-commit 外，预留 pre-push、commit-msg 等 Hook 的扩展接口 |

## 4.6 可维护性需求

| 需求项 | 说明 |
|--------|------|
| **代码覆盖率** | 单元测试覆盖率不低于 80% |
| **日志系统** | 完善的日志记录，支持 DEBUG、INFO、WARNING、ERROR 四个级别 |
| **版本管理** | 遵循语义化版本规范（Semantic Versioning） |
| **文档完备** | 提供安装指南、使用手册、规则开发指南、API 文档 |

---

# 第5章 技术选型与可行性分析

## 5.1 Python 技术栈选型

security-scan 选择 Python 作为开发语言，基于以下考量：

| 优势 | 说明 |
|------|------|
| **丰富的解析生态** | tree-sitter、javalang 等 AST 解析库均有成熟的 Python 绑定 |
| **开发效率高** | Python 的简洁语法和丰富标准库可显著提升开发效率 |
| **正则表达式强大** | Python 内置 `re` 模块功能完善，适合文本匹配类任务 |
| **跨平台** | Python 天然支持跨平台运行，无需额外适配 |
| **Git 集成便捷** | 可通过 `subprocess` 调用 Git 命令，或使用 `GitPython` 库 |
| **社区资源丰富** | 大量开源安全扫描工具基于 Python 开发，可参考借鉴 |

## 5.2 AST 解析库对比选型

### 5.2.1 tree-sitter vs javalang 详细对比

| 对比维度 | tree-sitter | javalang |
|----------|------------|----------|
| **解析方式** | 增量解析（C 语言实现） | 全量解析（纯 Python） |
| **解析速度** | 极快（毫秒级/文件） | 较慢（百毫秒级/文件） |
| **语法覆盖** | 完整 Java 语法（通过 grammar 定义） | 支持 Java 8-14 部分语法 |
| **错误恢复** | 支持语法错误恢复，不中断解析 | 语法错误可能导致解析失败 |
| **节点信息** | 提供详细的节点类型和位置信息 | 提供类型化的 AST 节点 |
| **安装复杂度** | 需要编译语言库（.so 文件） | `pip install javalang` 即可 |
| **维护状态** | GitHub 活跃维护 | 更新较慢 |
| **适用场景** | 高性能批量扫描 | 注解解析、类型分析 |

### 5.2.2 推荐策略

采用 **tree-sitter 为主 + javalang 为辅** 的双引擎策略：

- **tree-sitter** 作为主力解析引擎，负责高性能的文件级 AST 解析和基础规则匹配
- **javalang** 作为辅助解析引擎，负责需要深度语义分析的注解解析和类型推断
- 当 tree-sitter 解析失败时（如语法错误），自动降级到 javalang 进行尝试

## 5.3 与现有工具对比

| 对比维度 | security-scan | detect-secrets | truffleHog | git-secrets |
|----------|---------------|----------------|------------|-------------|
| **开发语言** | Python | Python | Go | Shell |
| **Java AST 支持** | ✅ 支持 | ❌ 不支持 | ❌ 不支持 | ❌ 不支持 |
| **@Value 误判防护** | ✅ AST 级别防护 | ❌ 不支持 | ❌ 不支持 | ❌ 不支持 |
| **全量扫描** | ✅ 支持 | ✅ 支持 | ✅ 支持 | ❌ 仅增量 |
| **Git Hook 集成** | ✅ 一键注册 | ⚠️ 需手动配置 | ⚠️ 需手动配置 | ✅ 支持 |
| **多文件格式** | ✅ 7 种格式 | ✅ 通用格式 | ✅ 通用格式 | ⚠️ 仅文本 |
| **自定义规则** | ✅ 插件化 | ✅ 插件化 | ⚠️ 有限 | ❌ 不支持 |
| **报告输出** | ✅ 多格式 | ⚠️ JSON | ⚠️ JSON | ❌ 控制台 |
| **中文支持** | ✅ 原生支持 | ⚠️ 有限 | ❌ 不支持 | ❌ 不支持 |

**security-scan 的差异化优势**：

1. **Java 深度支持**：基于 AST 的 Java 代码语义分析，是现有工具所不具备的
2. **误判防护**：专门针对 Spring `@Value` 注解等 Java 框架特性设计误判防护
3. **AI 辅助分类**：首创"规则+AI"二次分类模式，误判率可降至 2% 以下
4. **中文友好**：原生中文支持，包括报告输出和提示信息
5. **一键集成**：提供完善的 Hook 注册/退出机制，降低使用门槛

## 5.4 AI 模型选型分析

### 5.4.1 AI 模型对比

security-scan 的 AI 辅助分类模块需要选择合适的 LLM 后端，以下是主要候选方案的对比：

| 对比维度 | OpenAI GPT-4o-mini | Azure OpenAI | Ollama（本地部署） | DeepSeek API |
|----------|-------------------|--------------|-------------------|-------------|
| **部署方式** | 云端 API | 云端 API（企业级） | 本地部署 | 云端 API |
| **响应延迟** | 低（1-3 秒） | 低（1-3 秒） | 取决于硬件 | 低（1-3 秒） |
| **数据隐私** | 数据发送至 OpenAI | 数据保留在企业内网 | 完全本地，最高安全性 | 数据发送至 DeepSeek |
| **成本** | 低（$0.15/1M Token） | 中等 | 免费（硬件成本） | 极低 |
| **分类准确率** | 高（~95%） | 高（~95%） | 中高（取决于模型） | 高（~93%） |
| **可用性** | 需要网络 + API Key | 需要网络 + 企业订阅 | 离线可用 | 需要网络 + API Key |
| **推荐场景** | 通用场景，快速接入 | 企业级，数据合规要求高 | 高安全要求，离线环境 | 成本敏感场景 |

### 5.4.2 推荐策略

采用 **可插拔多后端架构**，通过统一接口适配不同 AI 服务提供商：

- **默认推荐**：OpenAI GPT-4o-mini（性价比最优，分类准确率高）
- **企业合规场景**：Azure OpenAI（数据不出企业网络）
- **高安全/离线场景**：Ollama + Qwen2.5 或 CodeLlama（本地部署，数据零泄露）
- **成本敏感场景**：DeepSeek API（价格极低，中文能力强）

### 5.4.3 AI SDK 选型

| SDK | 说明 | 优势 |
|-----|------|------|
| **openai (Python)** | OpenAI 官方 Python SDK | 同时支持 OpenAI 和 Azure OpenAI，兼容 Ollama/DirectAI 等兼容接口 |
| **langchain** | LLM 应用框架 | 抽象层完善，但引入依赖较重 |
| **httpx (直接调用)** | 直接 HTTP 调用 | 最轻量，但需自行处理重试、解析等逻辑 |

**推荐**：使用 `openai` 官方 Python SDK，通过 `base_url` 参数即可适配多种后端，无需引入额外框架。

## 5.5 风险评估与缓解

| 风险项 | 风险等级 | 影响 | 缓解措施 |
|--------|----------|------|----------|
| tree-sitter 编译兼容性 | 中 | 部分平台可能无法编译 | 提供预编译二进制包；降级到 javalang |
| Java 新语法支持滞后 | 低 | 新 Java 特性可能无法解析 | 定期更新 tree-sitter-java grammar |
| 正则规则维护成本 | 中 | 规则可能产生误报或漏报 | 建立规则测试集，持续优化 |
| 性能瓶颈 | 低 | 大型项目扫描可能较慢 | 多线程并行 + 增量解析优化 |
| Hook 冲突 | 低 | 与其他 pre-commit 工具冲突 | 智能合并机制，保留已有 Hook |
| AI 服务不可用 | 中 | AI 分类功能暂时失效 | 自动降级为纯规则模式，不影响核心扫描 |
| AI 分类延迟 | 低 | 增量扫描时增加提交等待时间 | 批量处理 + 异步调用；可配置关闭 AI |
| Windows 路径兼容性 | 低 | 反斜杠路径导致扫描失败 | 路径处理层统一使用 `pathlib`，自动适配各平台 |
| macOS ARM 兼容性 | 低 | Apple Silicon 芯片架构差异 | tree-sitter 提供 arm64 预编译包 |

## 5.6 跨平台技术方案

### 5.6.1 Python 跨平台优势

security-scan 选择 Python 作为开发语言，天然具备跨平台能力：

| 跨平台要素 | Python 支持方案 |
|------------|----------------|
| **文件路径** | `pathlib.Path` 自动处理 Windows/Unix 路径差异 |
| **进程调用** | `subprocess` 模块自动适配各平台 Shell |
| **环境变量** | `os.environ` 统一访问，自动适配各平台 |
| **配置文件路径** | `appdirs` / `platformdirs` 自动定位各平台配置目录 |
| **二进制分发** | `PyInstaller` / `nuitka` 可打包为各平台可执行文件 |

### 5.6.2 tree-sitter 跨平台编译策略

tree-sitter 的 Java 解析器需要编译为动态链接库（`.so`/`.dylib`/`.dll`），跨平台策略如下：

| 平台 | 文件格式 | 分发策略 |
|------|----------|----------|
| **Windows** | `.dll` | 提供 x64 预编译二进制包，随 `pip install` 自动下载 |
| **macOS** | `.dylib` | 提供 x64 + arm64（Apple Silicon）双架构预编译包 |
| **Linux** | `.so` | 提供 glibc 2.17+ 兼容的预编译包；必要时支持源码编译 |

**编译降级方案**：当预编译包不可用时，自动尝试本地源码编译；若编译失败，自动降级到纯 Python 的 `javalang` 解析器。

## 5.7 依赖管理方案

### 5.7.1 依赖安装策略

security-scan 采用 **"运行时按需安装"** 策略，而非传统的 `requirements.txt` 预安装模式：

| 策略 | 说明 | 优势 |
|------|------|------|
| **最小预装** | 仅预装 security-scan 本体，不预装任何运行时依赖 | 安装包体积小，安装速度快 |
| **首次初始化** | 首次运行时自动检测并安装缺失依赖 | 用户无感知，降低使用门槛 |
| **按需加载** | AI 相关依赖仅在启用 AI 功能时安装 | 避免为不需要的功能安装依赖 |
| **版本兼容** | 支持依赖版本范围（如 `tree-sitter>=0.20.0`） | 兼容不同环境的依赖版本 |

### 5.7.2 公司私有仓库适配

| 场景 | 解决方案 |
|------|----------|
| **HTTPS 自签证书** | 支持 `--cert` 参数指定 CA 证书，或 `--trusted-host` 跳过证书验证 |
| **需要代理** | 自动读取 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量 |
| **多源备份** | 支持 `extra_index_urls` 配置多个备用源，主源失败时自动切换 |
| **离线环境** | 支持 `--offline` + `--deps-dir` 使用本地预下载的依赖包 |

### 5.7.3 依赖版本锁定

为确保环境一致性，security-scan 支持依赖版本锁定：

```yaml
# .security-scan.yml
pip:
  lock_file: ".security-scan.lock"  # 依赖版本锁定文件
  # 锁定文件内容示例（自动生成）
  # tree-sitter==0.20.4
  # javalang==1.3.0
  # PyYAML==6.0.1
```

## 5.8 可行性结论

基于以上分析，security-scan 项目在技术上是完全可行的：

- **技术成熟度**：tree-sitter、javalang 等 AST 解析技术已经成熟，有大量成功案例
- **开发资源**：Python 生态完善，开发效率高，预计 2-3 人月可完成核心功能
- **差异化价值**：针对 Java 项目的 AST 级别安全扫描填补了市场空白
- **扩展潜力**：插件化架构设计支持未来功能扩展和多语言支持

---

# 第6章 实施计划与里程碑

## 6.1 项目阶段划分

security-scan 项目建议分为五个阶段实施，每个阶段有明确的里程碑和交付物。

| 阶段 | 名称 | 周期 | 核心目标 |
|------|------|------|----------|
| 第一阶段 | 基础框架搭建 | 2 周 | 完成项目骨架、CLI 框架、配置系统、环境初始化 |
| 第二阶段 | 核心扫描引擎 | 3 周 | 完成 AST 扫描器、正则扫描器、规则引擎 |
| 第三阶段 | Git Hook 集成 | 2 周 | 完成 Hook 注册/退出、增量扫描 |
| 第四阶段 | 完善与发布 | 1 周 | 报告生成、测试覆盖、文档编写、发布 |
| 第五阶段 | AI 辅助分类 | 2 周 | AI 二次分类模块、多模型适配、集成测试 |

## 6.2 详细里程碑

### 第一阶段：基础框架搭建（第 1-2 周）

| 里程碑 | 交付物 | 验收标准 |
|--------|--------|----------|
| M1.1 项目初始化 | 项目目录结构、依赖配置 | `pip install -e .` 可正常安装 |
| M1.2 CLI 框架 | `security-scan scan`、`security-scan hook` 命令 | 命令可执行，帮助信息正确显示 |
| M1.3 配置系统 | 配置加载器、默认配置文件 | 支持项目级和全局级配置加载 |
| M1.4 环境初始化 | `security-scan init` 命令 | 自动检测 Python 版本、自动安装缺失依赖 |
| M1.5 pip 仓库配置 | 私有仓库适配 | 支持 `--index-url`、`--trusted-host`、`--cert` 参数 |

### 第二阶段：核心扫描引擎（第 3-5 周）

| 里程碑 | 交付物 | 验收标准 |
|--------|--------|----------|
| M2.1 正则扫描器 | 配置文件扫描功能 | 能检测 Properties/YAML 中的明文密码 |
| M2.2 AST 扫描器 | Java 文件 AST 扫描功能 | 能基于 tree-sitter 解析 Java AST |
| M2.3 规则引擎 | 内置规则库、自定义规则加载 | 至少 20 条内置规则 |
| M2.4 误判防护 | 白名单、@Value 上下文分析 | 误判率 < 5% |

### 第三阶段：Git Hook 集成（第 6-7 周）

| 里程碑 | 交付物 | 验收标准 |
|--------|--------|----------|
| M3.1 Hook 注册 | `hook install` 命令 | Hook 正确安装到 `.git/hooks/` |
| M3.2 Hook 退出 | `hook uninstall`、`disable`、`enable` 命令 | Hook 可正确移除和恢复 |
| M3.3 增量扫描 | pre-commit 触发扫描 | commit 时自动扫描并阻断含敏感信息的提交 |

### 第四阶段：完善与发布（第 8 周）

| 里程碑 | 交付物 | 验收标准 |
|--------|--------|----------|
| M4.1 报告生成 | HTML、JSON、SARIF 报告 | 三种格式报告正确生成 |
| M4.2 测试覆盖 | 单元测试、集成测试 | 代码覆盖率 ≥ 80% |
| M4.3 文档编写 | 使用手册、规则开发指南 | 文档完整、示例可运行 |
| M4.4 发布 | PyPI 发布包 | `pip install security-scan` 可正常安装使用 |

### 第五阶段：AI 辅助分类（第 9-10 周）

| 里程碑 | 交付物 | 验收标准 |
|--------|--------|----------|
| M5.1 AI 分类器核心 | AI 二次分类模块 | 能对规则引擎候选结果进行确认/误判分类 |
| M5.2 多模型适配 | OpenAI/Azure/Ollama 适配器 | 至少支持 2 种 AI 后端切换 |
| M5.3 Prompt 优化 | 结构化 Prompt + 批量处理 | AI 分类准确率 ≥ 90%，误判率 < 2% |
| M5.4 降级与容错 | AI 不可用时自动降级 | AI 服务异常时自动回退到纯规则模式 |
| M5.5 AI 集成测试 | 端到端测试 | AI 辅助模式下的全流程测试通过 |

## 6.3 资源需求

| 资源类型 | 需求 |
|----------|------|
| **开发人员** | 1-2 名 Python 开发工程师 |
| **测试人员** | 1 名（可由开发兼任） |
| **Java 顾问** | 1 名兼职（提供 Java 语法和 Spring 框架方面的指导） |
| **测试环境** | Linux/macOS/Windows 各一台 |
| **测试项目** | 2-3 个真实 Java 项目用于验证扫描效果 |
| **AI 服务** | OpenAI API Key 或本地 Ollama 部署环境 |

---

# 第7章 总结与建议

## 7.1 核心需求总结

security-scan 是一款面向 Java 项目的代码安全扫描组件，基于 Python 开发，核心需求可总结为以下九个方面：

1. **全量代码扫描**：支持对整个项目进行主动扫描，覆盖 Java 源码和各类配置文件，输出多格式扫描报告
2. **增量扫描**：基于 Git pre-commit hook 实现代码提交时的实时扫描，从源头阻止敏感信息进入代码仓库
3. **Hook 注册与退出**：提供一键注册/退出机制，支持全局和项目级部署，兼容已有 Hook
4. **误判防护**：基于 AST 语义分析识别 `@Value` 注解等场景中的非密码默认值，误判率控制在 5% 以内
5. **AST 扫描技术**：采用 tree-sitter + javalang 双引擎策略，实现语义级别的精准扫描，相比正则表达式大幅降低误判率
6. **多文件格式支持**：覆盖 Java、XML、JSON、YAML、Properties、TXT、Markdown 等七种文件格式
7. **AI 辅助分类**：引入 LLM 大模型对规则引擎候选结果进行二次确认/误判分类，误判率可降至 2% 以下
8. **扫描结果分级分类**：每条扫描结果包含类型分类（10 种）、严重等级（4 级）、置信度评分，支持按等级配置阻断策略
9. **CI/CD 集成接口预留**：当前版本聚焦本地 Git Hook 集成，同时预留退出码规范、`--ci` 参数签名和标准输出格式，为未来 CI/CD 流水线对接打下基础（详见 2.9 节）

## 7.2 关键实施建议

1. **优先实现核心价值**：建议第一阶段先实现正则扫描器 + Git Hook 集成，快速交付可用的 MVP 版本，再逐步引入 AST 扫描能力
2. **建立规则测试集**：从真实 Java 项目中收集敏感信息样本和误判样本，建立持续回归测试集，确保扫描质量
3. **渐进式推广**：先在 1-2 个试点项目中部署试用，收集反馈后优化规则，再推广到全公司
4. **与 CI/CD 集成**：虽然初期聚焦本地 Git Hook，但已按 2.9 节的设计预留退出码、参数签名和输出格式接口，后续可无缝对接 Jenkins、GitLab CI 等平台
5. **规则共享机制**：建立公司级的扫描规则共享仓库，各团队可贡献和复用安全规则

## 7.3 后续演进方向

- **多语言扩展**：基于 tree-sitter 的多语言能力，后续可扩展支持 Python、Go、JavaScript 等语言的扫描
- **AI 模型持续优化**：基于误判样本持续优化 Prompt 和分类模型，探索小模型微调方案降低 API 依赖
- **IDE 插件**：开发 VS Code / IntelliJ 插件，在编码阶段实时提示敏感信息风险
- **漏洞数据库集成**：集成 NVD 等漏洞数据库，扩展到依赖库的已知漏洞扫描
- **合规报告**：支持生成符合等保 2.0、GDPR 等安全合规要求的扫描报告
- **自动修复对接（远期探索）**：探索通过 MCP（Model Context Protocol）等协议对接公司加密服务，将扫描发现的明文密码自动加密替换。**注意**：此方向涉及代码写入权限和加密凭证管理，安全风险较高，仅作为远期探索项，当前版本不纳入规划
