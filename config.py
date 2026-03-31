"""
配置加载器 (独立解密版 - macOS)

仅保留解密功能所需的配置项，从 config.json 读取。
支持自动检测 macOS 微信数据目录。
"""
import glob
import json
import os
import sys

# 配置文件默认位于本脚本同目录
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_DEFAULT_TEMPLATE_DIR = os.path.expanduser("~/Documents/xwechat_files/your_wxid/db_storage")

_DEFAULT = {
    "db_dir": _DEFAULT_TEMPLATE_DIR,
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
}


def _choose_candidate(candidates):
    """在多个候选目录中选择一个。"""
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if not sys.stdin.isatty():
            return candidates[0]
        print("[!] 检测到多个微信数据目录（请选择当前正在运行的微信账号）:")
        for i, c in enumerate(candidates, 1):
            print(f"    {i}. {c}")
        print("    0. 跳过，稍后手动配置")
        try:
            while True:
                choice = input("请选择 [0-{}]: ".format(len(candidates))).strip()
                if choice == "0":
                    return None
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    return candidates[int(choice) - 1]
                print("    无效输入，请重新选择")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    return None


def auto_detect_db_dir():
    """自动检测 macOS 微信 db_storage 路径。"""
    seen = set()
    candidates = []
    search_root = os.path.expanduser("~/Documents/xwechat_files")

    if os.path.isdir(search_root):
        pattern = os.path.join(search_root, "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    # 优先使用最近活跃账号
    def _mtime(path):
        msg_dir = os.path.join(path, "message")
        target = msg_dir if os.path.isdir(msg_dir) else path
        try:
            return os.path.getmtime(target)
        except OSError:
            return 0

    candidates.sort(key=_mtime, reverse=True)
    return _choose_candidate(candidates)


def load_config(config_path=None):
    """加载配置，支持指定自定义配置文件路径。"""
    cfg = {}
    cfg_file = config_path or CONFIG_FILE

    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] {cfg_file} 格式损坏，将使用默认配置")
            cfg = {}

    # db_dir 缺失或仍为模板值时，尝试自动检测
    db_dir = cfg.get("db_dir", "")
    if not db_dir or db_dir == _DEFAULT_TEMPLATE_DIR or "your_wxid" in db_dir:
        detected = auto_detect_db_dir()
        if detected:
            print(f"[+] 自动检测到微信数据目录: {detected}")
            cfg = {**_DEFAULT, **cfg, "db_dir": detected}
            with open(cfg_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            print(f"[+] 已保存到: {cfg_file}")
        else:
            if not os.path.exists(cfg_file):
                with open(cfg_file, "w", encoding="utf-8") as f:
                    json.dump(_DEFAULT, f, indent=4, ensure_ascii=False)
            print(f"[!] 未能自动检测微信数据目录")
            print(f"    请手动编辑 {cfg_file} 中的 db_dir 字段")
            print(f"    路径可在 微信设置 → 文件管理 中找到")
            sys.exit(1)
    else:
        cfg = {**_DEFAULT, **cfg}

    # 将相对路径转为绝对路径（基于配置文件所在目录）
    base = os.path.dirname(os.path.abspath(cfg_file))
    for key in ("keys_file", "decrypted_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    return cfg
