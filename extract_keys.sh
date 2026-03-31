#!/usr/bin/env bash
# 微信密钥提取器 — 自动编译、运行、归档
#
# 前提:
#   - 微信正在运行且已登录
#   - 微信已 ad-hoc 签名（或 SIP 已关闭）
#   - 需要以 sudo 运行
#
# 用法:
#   sudo ./extract_keys.sh           # 提取密钥
#   sudo ./extract_keys.sh 12345     # 指定微信 PID
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE_DIR="$SCRIPT_DIR/all_keys_archive"
BINARY="$SCRIPT_DIR/find_all_keys_macos"
SOURCE="$SCRIPT_DIR/find_all_keys_macos.c"
KEYS_FILE="$SCRIPT_DIR/all_keys.json"

# ── 编译 C 程序 ──
if [ ! -f "$BINARY" ] || [ "$SOURCE" -nt "$BINARY" ]; then
    # 旧二进制可能由 root 创建导致当前用户无法覆盖，先尝试删除
    rm -f "$BINARY" 2>/dev/null
    echo "[*] 编译 find_all_keys_macos.c ..."
    cc -O2 -o "$BINARY" "$SOURCE" -framework Foundation
    echo "[+] 编译完成"
fi

# ── 归档已有的 all_keys.json ──
if [ -f "$KEYS_FILE" ]; then
    mkdir -p "$ARCHIVE_DIR"
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    ARCHIVE_PATH="$ARCHIVE_DIR/all_keys_${TIMESTAMP}.json"
    cp "$KEYS_FILE" "$ARCHIVE_PATH"
    # 统计旧密钥数量（去除元数据行后计算）
    OLD_COUNT=$(python3 -c "
import json, sys
try:
    with open('$KEYS_FILE') as f:
        d = json.load(f)
    print(sum(1 for k in d if not k.startswith('_')))
except: print(0)
" 2>/dev/null || echo "?")
    echo "[*] 已归档旧密钥: $ARCHIVE_PATH ($OLD_COUNT 个密钥)"
fi

# ── 运行密钥提取 ──
echo ""
echo "============================================================"
echo "  微信密钥提取 (macOS)"
echo "============================================================"
echo ""

# 确定微信 PID: 优先使用命令行参数，否则自动查找
WECHAT_PID="${1:-}"
if [ -z "$WECHAT_PID" ]; then
    # 先尝试 pgrep，再尝试 ps 兜底（sudo 下 pgrep 可能失败）
    WECHAT_PID=$(pgrep -x WeChat 2>/dev/null || true)
    if [ -z "$WECHAT_PID" ]; then
        WECHAT_PID=$(ps -o pid=,comm= -ax 2>/dev/null | awk '/\/MacOS\/WeChat$/ && !/Helper/ && !/GPU/ && !/Renderer/ {print $1; exit}')
    fi
fi

if [ -z "$WECHAT_PID" ]; then
    echo "[!] 未找到微信进程，请确保微信正在运行"
    exit 1
fi
echo "[*] 微信 PID: $WECHAT_PID"

"$BINARY" "$WECHAT_PID"

# ── 验证结果 ──
if [ -f "$KEYS_FILE" ]; then
    NEW_COUNT=$(python3 -c "
import json
with open('$KEYS_FILE') as f:
    d = json.load(f)
print(sum(1 for k in d if not k.startswith('_')))
" 2>/dev/null || echo "?")
    echo ""
    echo "[+] 提取完成: $NEW_COUNT 个密钥"
    echo "[+] 密钥文件: $KEYS_FILE"
else
    echo ""
    echo "[!] 未能生成密钥文件"
    exit 1
fi
