# 架构设计

## 分层架构

```
┌─────────────────────────────────────┐
│           入口层                      │
│  CLI  ·  Git Hook  ·  配置加载器      │
├─────────────────────────────────────┤
│           扫描引擎层                   │
│  文件收集器 → 文件分类器 → 扫描器      │
│  (AST 扫描器 / 正则扫描器) → 聚合器    │
├─────────────────────────────────────┤
│           规则引擎层                   │
│  内置规则 · 自定义规则 · 白名单 · 上下文分析 │
├─────────────────────────────────────┤
│  AI 辅助分类层（可选）                  │
│  Prompt 构建器 → AI Provider → 批处理  │
├─────────────────────────────────────┤
│           输出层                      │
│  控制台 · HTML · JSON · SARIF        │
└─────────────────────────────────────┘
```

## 核心模块

| 模块 | 职责 |
|------|------|
| `cli/` | 命令行参数解析、子命令路由 |
| `scanner/collector.py` | 全量/增量模式文件收集 |
| `scanner/classifier.py` | 按扩展名分发到对应扫描器 |
| `scanner/ast_scanner.py` | tree-sitter/javalang AST 解析 + 规则匹配 |
| `scanner/regex_scanner.py` | 配置文件和文本文件的正则匹配 |
| `scanner/aggregator.py` | 结果去重、排序、合并 |
| `rules/` | 规则管理、白名单过滤、上下文分析 |
| `ai/` | LLM 二次分类（OpenAI/Azure/Ollama） |
| `hook/` | Git pre-commit hook 安装/卸载/启用/禁用 |
| `output/` | 控制台 + HTML + JSON + SARIF 报告 |
| `config/loader.py` | 项目级 + 全局级配置加载与合并 |
| `utils/` | Git 操作、文件编码检测、路径处理 |

## 数据流

```
触发 → FileCollector → FileClassifier → [ASTScanner | RegexScanner]
       → RuleEngine → ContextAnalyzer → WhitelistFilter → Aggregator
       → ResultClassifier → [AIClassifier] → ReportGenerator
```
