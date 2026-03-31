# WeChat 4.0 数据库解密器 (独立版)

从 wechat-decrypt 项目中分离出的独立解密功能，专为 macOS 设计。

## 功能

1. **密钥提取** — 从微信进程内存中扫描 SQLCipher 加密密钥
2. **数据库解密** — 批量解密整个 db_storage 目录，生成标准 SQLite 数据库

- 加密参数: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
- 自动验证 HMAC 完整性和解密结果

## 前提条件

- **macOS** (Apple Silicon / Intel 均可)
- **Xcode Command Line Tools**: `xcode-select --install` (用于编译 C 扫描器)
- **pycryptodome**: 已包含在 `.venv` 中，无需额外安装
- **微信已 ad-hoc 签名** (密钥提取需要读取进程内存)

## 快速使用

### 第一步：提取密钥

确保微信正在运行且已登录，然后：

```bash
sudo ./extract_keys.sh
```

脚本会自动：
- 编译 C 密钥扫描器（首次运行或源码更新时）
- 归档已有的 `all_keys.json` 到 `all_keys_archive/` 目录（不会覆盖）
- 扫描微信进程内存，生成新的 `all_keys.json`

也可指定微信 PID：

```bash
sudo ./extract_keys.sh 12345
```

### 第二步：运行解密

```bash
./run.sh
```

也支持命令行参数覆盖配置：

```bash
./run.sh --db-dir ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/db_storage \
         --out-dir ./decrypted
```

## 文件说明

```
decrypt_standalone/
├── extract_keys.sh         # 密钥提取入口（编译 + 运行 + 归档）
├── find_all_keys_macos.c   # 密钥扫描器 C 源码
├── find_all_keys_macos     # 编译后的二进制（自动生成）
├── run.sh                  # 解密入口（使用内置 venv）
├── decrypt_db.py           # 解密主程序
├── config.py               # 配置加载（macOS 自动检测）
├── key_utils.py            # 密钥匹配工具
├── config.example.json     # 配置文件模板
├── requirements.txt        # Python 依赖
├── .venv/                  # Python 虚拟环境（自带）
├── all_keys.json           # 当前密钥文件（提取后生成）
└── all_keys_archive/       # 密钥归档目录（自动创建）
```

## 配置

首次运行会自动检测微信数据目录，也可手动编辑 `config.json`：

```bash
cp config.example.json config.json
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `db_dir` | 微信数据库目录 (db_storage) | 自动检测 |
| `keys_file` | 密钥文件路径 | `all_keys.json` |
| `decrypted_dir` | 解密输出目录 | `decrypted` |

## 注意事项

- 密钥提取需要 `sudo` 权限且微信已 ad-hoc 签名
- 解密时微信不一定要在运行，但密钥文件必须存在
- 每个数据库有独立的密钥，切换微信账号后需重新提取
- 解密后的数据库可用任何 SQLite 工具打开查看
- 旧的密钥文件会自动归档到 `all_keys_archive/`，带时间戳命名
