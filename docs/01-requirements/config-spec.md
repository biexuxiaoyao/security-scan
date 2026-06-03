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

# 自定义规则
custom_rules:
  - id: "my_custom_rule"
    name: "My custom rule"
    scope: "properties"
    pattern: "my_secret\\s*=\\s*(.+)"
    severity: "HIGH"

# 文件格式扩展
file_formats:
  - name: "env_file"
    extensions: [".env"]
    scan_strategy: "key_value"
    high_risk_keys: ["DB_PASSWORD", "API_KEY", "SECRET_KEY"]

# AI 辅助分类（可选）
ai:
  enabled: false
  provider: "openai"
  model: "gpt-4o-mini"
  api_key_env: "SECURITY_SCAN_AI_KEY"
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
