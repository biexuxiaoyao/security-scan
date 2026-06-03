#!/bin/bash
# 运行测试套件
set -euo pipefail

cd "$(dirname "$0")/.."
source .venv/bin/activate 2>/dev/null || true

echo "=== security-scan 测试 ==="

python -m pytest tests/ -v --cov=security_scan --cov-report=term --cov-report=html "$@"
echo "✓ 测试完成"
