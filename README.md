# security-scan

**security-scan** 是一款面向 Java 项目的代码安全扫描工具，基于 Python 3.12+ 开发。
通过 **tree-sitter AST 语义分析 + 结构化 KV 分析 + 正则匹配三引擎**，精准检测代码中的明文密码、硬编码密钥、弱密码等敏感信息。

## 特性

### 🔬 扫描引擎

| 引擎 | 适用文件 | 能力 |
|------|----------|------|
| **🌲 tree-sitter AST 语义分析** | `.java` | 解析 Java AST，精准识别 `@Value("${key:default}")` 中隐藏的明文密码默认值；根据变量类型（boolean/numeric）和命名自动降级误报 |
| **🔑 结构化 KV 扫描器** | `.yml` `.yaml` `.properties` | YAML 嵌套键解析（`spring.datasource.password`），key 名模式匹配 + whitelist + value 加密/占位符检测 |
| **🔍 正则匹配引擎** | XML / JSON / YAML / Properties / TXT / Markdown 等 | 覆盖连接字符串、私钥、AWS Key、JWT 等通用凭据模式 |

### 🧠 智能降级

- **加密值前缀识别** — 可配置加密前缀（`BEE_` / `ENC(` / `{cipher}` / `$2a$` / `encrypt:` 等），自动将加密值降级为 LOW
- **占位符识别** — `${...}` / `$(...)` / `<...>` / `@...@` 等占位符引用视为安全
- **上下文分析** — 智能降级布尔值、数值、版本号、URL、端口号等非密码场景

### ⚡ 扫描模式

- **📦 全量扫描** — 递归扫描整个项目目录，支持 `.security-scan-ignore` 排除规则
- **⚡ 增量扫描** — Git pre-commit hook 自动扫描暂存区变更，秒级反馈
- **🛡️ 文件大小保护** — 超 20 MiB 的文件自动跳过，防止大文件 OOM

### 📋 白名单机制

- 项目级 `.security-scan-whitelist` 文件（支持 glob 路径 / 文件:行号 / 正则模式）
- 全局 `~/.security-scan/whitelist.yml`
- 行内 `// security-scan:ignore`
- 精确路径匹配（`src/test` 不会误匹配 `src/test-utils/`）

### 🤖 AI 辅助分类（可选）

LLM 二次分类，支持 OpenAI / Azure / DeepSeek / Ollama 等任意 OpenAI 兼容 API。
使用 stdlib HTTP 直连，**无需任何 SDK**。

### 📊 报告输出

控制台（彩色分级）/ HTML（无依赖内联 CSS）/ JSON / SARIF 2.1.0（兼容 GitHub Code Scanning）

### 🔌 CI/CD 集成

标准化退出码（0-通过 / 1-阻断 / 2-警告）+ `--ci` 参数，无缝对接任何 CI pipeline。

## 快速开始

```bash
# 安装（核心）
pip install security-scan

# 安装（完整，含可选依赖）
pip install "security-scan[all]"

# 全量扫描
security-scan scan --path /path/to/project

# 增量扫描（仅检测已 git add 的变更文件）
security-scan scan --incremental

# 注册 Git pre-commit hook（提交时自动增量扫描）
security-scan hook install

# 导出 HTML 报告
security-scan scan --path . --output-format html --output-file report.html
```

## 配置

在项目根目录创建 `.security-scan.yml`。完整示例：

```yaml
# 扫描范围
scan:
  include:
    - "src/"
    - "config/"
  exclude:
    - "target/"
    - "build/"
    - "node_modules/"
    - ".git/"
  file_extensions:
    - ".java" ".xml" ".json" ".yml" ".yaml" ".properties" ".txt" ".md"

# 严重等级与阻断策略
severity:
  block_on_commit:
    - CRITICAL
    - HIGH
  min_confidence_to_report: 0.50
  min_confidence_to_block: 0.70

# 加密值前缀（统一用于 AST / 正则扫描器）
encrypted_prefixes:
  - "BEE_"          # 公司自研加密服务输出前缀
  - "ENC("          # jasypt
  - "{cipher}"      # Spring Cloud Config

# 配置文件密钥检测（结构化 KV 扫描器）
config_file_secrets:
  enabled: true
  exclude_patterns:
    - "messages_*.properties"
  key_rules:
    - id: "config_plaintext_password"
      name: "配置文件明文密码"
      severity: "HIGH"
      patterns:
        - "(?i).*redis.*(?:password|auth|pass|secret)$"
        - "(?i).*(?:password|secret|pwd|key|token)$"
    - id: "config_plaintext_token"
      name: "配置文件明文Token"
      severity: "HIGH"
      patterns:
        - "(?i)sasl\\.jaas\\.config"
        - "(?i)bee\\.kafka\\.ds1\\.properties\\.sasl\\.jaas\\.config"
  key_whitelist:
    - "(?i)^(?:publicKey|pubKey|appKey|accesskey)$"
    - "(?i)^(?:topickey|relatedkey|binding-routing-key)$"
    - "(?i)^(?:ignoretoken|bee\\.microservice\\.token)$"
  value_encrypted_prefixes:
    - "BEE_" "ENC(" "{ciph" "encrypt:" "M_ENC" "LSFI_ENV_COMMON"
  value_placeholder_patterns:
    - "^\\$\\([^)]+\\)$"
    - "^\\$\\{[^}]+\\}$"
    - "^<[^>]+>$"
    - "^@[^@]+@$"

# AI 辅助分类（可选，无需 SDK）
ai:
  enabled: false
  provider: "openai"            # openai / azure / deepseek / ollama
  model: "deepseek-chat"
  api_key_env: "SECURITY_SCAN_AI_KEY"
  base_url: "https://api.openai.com/v1"
  timeout: 10
  max_retries: 3
  confidence_threshold: 0.7

# CI/CD 模式
ci:
  enabled: false
  block_on: ["CRITICAL"]
  output_format: "json"
  report_artifact: "security-report.json"
```

完整配置项说明见 [配置规范](docs/01-requirements/config-spec.md)。

## 白名单

```bash
# 方式1: 项目级白名单文件
echo "src/test/" >> .security-scan-whitelist
echo "src/generated/:42" >> .security-scan-whitelist    # 指定行
echo "/test[A-Z]+/" >> .security-scan-whitelist          # 正则模式

# 方式2: 全局白名单
mkdir -p ~/.security-scan
cat >> ~/.security-scan/whitelist.yml << 'EOF'
rules:
  - pattern: "test_data"
  - path: "src/legacy/*.java"
EOF

# 方式3: 行内忽略
password = "secret"  // security-scan:ignore
```

## 内置规则

| 规则 ID | 类型 | 严重等级 | 覆盖范围 |
|---------|------|---------|---------|
| `java_plaintext_password` | 明文密码 | 🔴 CRITICAL | Java 源码（AST + 正则） |
| `config_credential_key` | 配置文件凭证 | 🟠 HIGH | YAML / JSON / Properties / XML |
| `config_plaintext_password` | 配置文件密码 | 🟠 HIGH | 配置文件（KV 扫描器） |
| `config_plaintext_key` | 配置文件密钥 | 🟠 HIGH | 配置文件（KV 扫描器） |
| `config_plaintext_token` | 配置文件 Token | 🟠 HIGH | 配置文件（KV 扫描器） |
| `connection_string` | 连接字符串泄露 | 🔴 CRITICAL | 所有文本文件 |
| `private_key` | 私钥泄露 | 🔴 CRITICAL | 所有文本文件 |
| `aws_access_key` | AWS Access Key | 🟠 HIGH | 所有文本文件 |
| `aws_secret_key` | AWS Secret Key | 🟠 HIGH | 所有文本文件 |
| `jwt_token` | JWT / Bearer Token | 🟠 HIGH | 所有文本文件 |
| `default_password` | 默认/弱密码 | 🟡 MEDIUM | 所有文本文件 |
| `password_in_comment` | 注释中的密码 | 🟡 MEDIUM | 所有文本文件 |
| `sensitive_log` | 日志敏感信息 | 🟡 MEDIUM | 所有文本文件 |

## CLI 命令参考

```
security-scan scan         --path PATH [--incremental] [--ci]
                             [--output-format FORMAT] [--output-file FILE]
                             [--generate-config] [-v]

security-scan hook install [--global]
security-scan hook uninstall [--global]
security-scan hook disable
security-scan hook enable

security-scan init         [--force] [--index-url URL]
                             [--offline] [--deps-dir DIR]
```

### 使用示例

```bash
# 扫描 Java 项目
security-scan scan --path ~/my-project -v

# 生成默认配置文件（查看/导出）
security-scan scan --generate-config > .security-scan.yml

# CI 模式（阻止 CRITICAL + HIGH，输出 JSON）
security-scan scan --path . --ci --output-format json --output-file report.json

# Hook 管理
security-scan hook install              # 安装 pre-commit hook
security-scan hook uninstall            # 卸载
security-scan hook disable              # 临时禁用
security-scan hook enable               # 重新启用
```

### 退出码规范

| 退出码 | 含义 | CI 处理 |
|--------|------|---------|
| `0` | 扫描完成，未发现安全问题 | ✅ 构建通过 |
| `1` | 扫描完成，存在高危问题 | ❌ 建议阻断 |
| `2` | 扫描完成，存在中/低危问题 | ⚠️ 警告，不阻断 |
| `20` | 配置错误 | ❌ 阻断 |
| `21` | 依赖缺失 | ❌ 阻断 |
| `30` | 内部错误 | ❌ 阻断 |

## 项目结构

```
security-scan/
├── security_scan/              # 核心源码
│   ├── cli/main.py             # CLI 入口（click）
│   ├── config/loader.py        # 配置加载器（4 级优先级）
│   ├── scanner/                # 扫描引擎
│   │   ├── collector.py        #   文件收集（全量/增量）
│   │   ├── classifier.py       #   文件分类（扩展名→策略）
│   │   ├── ast_scanner.py      #   🌲 tree-sitter AST 扫描器
│   │   ├── regex_scanner.py    #   正则扫描器
│   │   ├── config_scanner.py   #   配置文件 KV 扫描器
│   │   └── aggregator.py       #   结果聚合去重排序
│   ├── rules/                  # 规则引擎
│   │   ├── builtin_rules.py    #   10 条内置规则
│   │   ├── custom_rules.py     #   自定义规则加载
│   │   ├── whitelist.py        #   白名单（项目+全局+行内）
│   │   ├── context_analyzer.py #   上下文分析降级
│   │   └── __init__.py         #   RuleEngine 编排
│   ├── ai/                     # AI 辅助分类（可选）
│   │   ├── classifier.py       #   顶层 API
│   │   ├── prompt_builder.py   #   结构化 Prompt
│   │   ├── provider.py         #   多模型适配器
│   │   └── batch_processor.py  #   批处理+降级
│   ├── hook/installer.py       # Git Hook 安装/卸载/禁用/启用
│   ├── output/                 # 报告输出
│   │   ├── console.py          #   控制台（彩色）
│   │   ├── html_report.py      #   HTML（无依赖）
│   │   ├── json_report.py      #   JSON
│   │   └── sarif_report.py     #   SARIF 2.1.0
│   └── utils/                  # 工具
│       ├── file_utils.py       #   编码检测（UTF-8/GB18030）
│       ├── encryption.py      #   加密前缀检测共享函数
│       └── git_utils.py       #   Git 操作
├── tests/                      # 252 个测试（全部通过）
│   ├── test_config/            #   配置加载器测试
│   ├── test_scanner/           #   扫描引擎 + AST + KV 扫描器测试
│   ├── test_rules/             #   规则引擎 + 白名单 + 上下文分析测试
│   ├── test_ai/                #   AI 模块测试（Mock DeepSeek API）
│   ├── test_hook/              #   Hook 安装/卸载/启用/禁用测试
│   ├── test_output/            #   控制台 / HTML / JSON / SARIF 输出测试
│   ├── test_cli/               #   CLI 集成测试
│   ├── test_utils/             #   文件工具 + 加密工具测试
│   └── fixtures/               #   测试夹具（Java 样本 + 配置文件）
├── docs/01-requirements/       # 设计文档
├── pyproject.toml              # 项目元数据与依赖分组
├── .security-scan.yml          # 默认配置文件
└── .security-scan-ignore       # 默认排除规则
```

## 依赖分组

```bash
pip install security-scan            # 核心: PyYAML + click
pip install security-scan[ast]       # + tree-sitter + javalang
pip install security-scan[ai]        # + AI 分类（直接 HTTP，无需 SDK）
pip install security-scan[encoding]  # + chardet
pip install security-scan[report]    # + jinja2（HTML 选用）
pip install security-scan[all]       # 全部
pip install security-scan[dev]       # 开发: pytest + pytest-cov
```

## 测试

```bash
# 运行全部测试
pytest tests/ -v

# 覆盖率报告
pytest tests/ --cov=security_scan --cov-report=html

# 仅运行特定模块
pytest tests/test_scanner/ -v                    # 扫描引擎
pytest tests/test_ai/ -v                         # AI 模块
pytest tests/test_rules/test_whitelist.py -v     # 白名单

# 当前状态: 252 tests, all passing ✅  (覆盖率 84%)
```

## 许可

内部工具 — 公司版权所有
