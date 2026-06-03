#!/bin/bash
# security-scan 开发环境初始化脚本
set -euo pipefail

echo "=== security-scan 开发环境初始化 ==="

# 创建虚拟环境
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "✓ 虚拟环境已创建"
fi

source .venv/bin/activate

# 安装项目（可编辑模式）
pip install -e ".[dev,ast,ai,report,encoding]"
echo "✓ 依赖已安装"

# 安装 pre-commit hook（开发阶段使用）
# security-scan hook install

echo "=== 初始化完成 ==="
