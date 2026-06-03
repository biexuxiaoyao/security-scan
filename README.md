# security-scan

**security-scan** 是一款面向 Java 项目的代码安全扫描工具，基于 Python 开发。
通过 AST 语义分析 + 正则匹配双引擎，精准检测代码中的明文密码、硬编码密钥、弱密码等敏感信息。

## 特性

- **全量扫描** — 对整个项目目录进行完整安全扫描
- **增量扫描** — Git pre-commit hook 自动扫描暂存区变更
- **AST 语义分析** — 基于 tree-sitter + javalang 解析 Java 语法树，精准识别 `@Value` 注解等场景
- **AI 辅助分类** — 规则引擎 + LLM 二次分类，误判率可降至 2% 以下
- **多格式支持** — Java / XML / JSON / YAML / Properties / TXT / Markdown
- **多格式报告** — 控制台 / HTML / JSON / SARIF
- **加密值前缀识别** — 可配置加密前缀（如 `BEE_`），避免误报

## 快速开始

```bash
# 安装
pip install security-scan

# 初始化环境
security-scan init

# 全量扫描
security-scan scan --path /path/to/project

# 注册 Git pre-commit hook
security-scan hook install
```

## 文档

| 文档 | 说明 |
|------|------|
| [需求分析文档](docs/01-requirements/requirements-analysis.md) | 完整需求、架构设计、实施计划 |
| [使用指南](docs/02-guides) | 安装、配置、扫描、Hook 管理 |

## 项目结构

```
security-scan/
├── security_scan/        # 核心源码
│   ├── cli/              # CLI 命令行接口
│   ├── scanner/          # 扫描引擎（收集器、分类器、AST/正则扫描器）
│   ├── rules/            # 规则引擎（内置规则、自定义规则、白名单、上下文分析）
│   ├── ai/               # AI 辅助分类模块
│   ├── hook/             # Git Hook 管理
│   ├── output/           # 报告输出（控制台、HTML、JSON、SARIF）
│   ├── config/           # 配置加载器
│   └── utils/            # 工具函数
├── tests/                # 测试套件
├── docs/                 # 文档
├── pyproject.toml        # 项目元数据
└── README.md
```

## 许可

内部工具 — 公司版权所有
