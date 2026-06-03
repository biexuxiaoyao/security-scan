# security-scan 需求分析文档

本文档的完整版（含架构设计、技术选型、实施计划）请参阅项目根目录下的
[security-scan-requirements-analysis.md](../../security-scan-requirements-analysis.md)

## 概要

| 属性 | 值 |
|------|-----|
| 项目名称 | security-scan |
| 开发语言 | Python |
| 目标项目 | Java 项目 |
| 当前版本 | 0.1.0 |
| 文档日期 | 2026-06-03 |

## 核心需求

1. **全量代码扫描** — 对整个 Java 项目进行一次性完整安全扫描
2. **增量扫描** — Git pre-commit hook 自动扫描暂存区变更文件
3. **Hook 注册与退出** — 一键注册/移除 Git Hook
4. **误判防护** — AST 语义分析 + 加密前缀配置 + 白名单
5. **AST 扫描** — tree-sitter + javalang 双引擎精准扫描
6. **多文件格式** — 7 种常见格式支持
7. **AI 辅助分类** — LLM 二次分类降低误判率
8. **分级分类** — 类型 / 严重等级 / 置信度三维度输出
9. **CI/CD 接口预留** — 退出码 + `--ci` 参数 + 标准输出格式
