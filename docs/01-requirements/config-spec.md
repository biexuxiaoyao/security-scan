# 配置文件规范 (.security-scan.yml)

## 完整配置示例

```yaml
# security-scan 配置文件
# 放置在项目根目录下

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
    - ".java"
    - ".xml"
    - ".json"
    - ".yml"
    - ".yaml"
    - ".properties"
    - ".txt"
    - ".md"

# 严重等级与阻断策略
severity:
  block_on_commit:
    - CRITICAL
    - HIGH
  block_on_ci:                          # 预留，CI/CD 集成远期生效
    - CRITICAL
  min_confidence_to_report: 0.50
  min_confidence_to_block: 0.70

# 加密值前缀（避免误报加密数据）
encrypted_prefixes:
  - "BEE_"          # 公司自研加密服务输出前缀
  - "ENC("          # jasypt 加密前缀
  - "{cipher}"      # Spring Cloud Config 加密前缀
  - "$2a$"          # BCrypt
  - "$5$"           # SHA-256 哈希
  - "$6$"           # SHA-512 哈希

# 配置文件密钥检测（结构化 KV 扫描器）
config_file_secrets:
  enabled: true
  exclude_patterns:                 # glob 排除模式（如 messages_*.properties）
    - "messages_*.properties"
  key_rules:                        # key 名匹配规则（任意一条命中即触发）
    - id: "config_plaintext_password"
      name: "配置文件明文密码"
      severity: "HIGH"
      patterns:
        - "(?i).*redis.*(?:password|auth|pass|secret)$"
        - "(?i)ZOO_SERVER_PASSWORDS|ZOO\\.SERVER\\.PASSWORDS"
    - id: "config_plaintext_key"
      name: "配置文件明文密钥"
      severity: "HIGH"
      patterns:
        - "(?i).*(?:password|secret|pwd|key|token)$"
    - id: "config_plaintext_token"
      name: "配置文件明文Token"
      severity: "HIGH"
      patterns:
        - "(?i)sasl\\.jaas\\.config"
        - "(?i)spring\\.kafka\\.properties\\.sasl\\.jaas\\.config"
        - "(?i)bee\\.kafka\\.ds1\\.properties\\.sasl\\.jaas\\.config"
  key_whitelist:                    # key 名白名单（命中则跳过）
    - "(?i)^(?:publicKey|public.key|pubKey|appKey|accesskey)$"
    - "(?i)^(?:topickey|relatedkey|binding-routing-key)$"
    - "(?i).*RelatedKey.*"
    - "(?i).*poseidon.*"
    - "(?i)^(?:ignoretoken|bee\\.microservice\\.token)$"
  value_encrypted_prefixes:         # 加密值前缀（字符串前缀匹配）
    - "BEE_"            # 公司自研加密
    - "ENC("            # jasypt
    - "{ciph"           # Spring Cloud Config
    - "encrypt:"        # 其他加密标记
    - "M_ENC"
    - "LSFI_ENV_COMMON"
  value_placeholder_patterns:       # 占位符模式（视为安全）
    - "^\\$\\([^)]+\\)$"    # $(...)
    - "^\\$\\{[^}]+\\}$"    # ${...}
    - "^<[^>]+>$"           # <...>
    - "^@[^@]+@$"           # @...@

# 自定义规则
custom_rules:
  - id: "my_custom_rule"
    name: "My custom rule"
    scope: "properties"
    pattern: "my_secret\\s*=\\s*(.+)"
    severity: "HIGH"

# 文件格式扩展
  - name: "env_file"
    extensions: [".env"]
    scan_strategy: "key_value"
    high_risk_keys: ["DB_PASSWORD", "API_KEY", "SECRET_KEY"]

# AI 辅助分类（可选，使用 stdlib HTTP，无需 SDK）
ai:
  enabled: false
  provider: "openai"            # openai / azure / deepseek / ollama
  model: "deepseek-chat"        # 支持的模型由 provider 决定
  api_key_env: "SECURITY_SCAN_AI_KEY"
  base_url: "https://api.openai.com/v1"   # 通过 base_url 切换 provider
  timeout: 10
  max_retries: 3
  confidence_threshold: 0.7

# pip 仓库配置（私有仓库）
pip:
  index_url: "https://pypi.company.com/simple"
  trusted_host: "pypi.company.com"

# CI/CD 模式（预留）
ci:
  enabled: false
  block_on: ["CRITICAL"]
  output_format: "json"
  report_artifact: "security-report.json"
```

## 配置优先级

1. 命令行参数（最高优先级）
2. 项目级 `.security-scan.yml`
3. 项目级 `.security-scan-whitelist`
4. 全局 `~/.security-scan/config.yml`
5. 内置默认值（最低优先级）
