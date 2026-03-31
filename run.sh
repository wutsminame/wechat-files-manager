#!/usr/bin/env bash
# 一键运行解密 — 无需手动激活虚拟环境
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/decrypt_db.py" "$@"
