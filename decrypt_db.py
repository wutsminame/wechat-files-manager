"""
WeChat 4.0 数据库解密器 (独立版)

使用从进程内存提取的 per-DB enc_key 解密 SQLCipher 4 加密的数据库。
参数: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
密钥来源: all_keys.json (由 find_all_keys_macos 从内存提取)

支持 WAL (Write-Ahead Log) 文件解密与合并，确保微信运行时也能获取完整数据。
"""
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import functools
import shutil

from Crypto.Cipher import AES

print = functools.partial(print, flush=True)

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b'SQLite format 3\x00'

# WAL 文件格式常量
WAL_MAGIC_BE = 0x377f0682   # big-endian (pre-2021 SQLite)
WAL_MAGIC_LE = 0x377f0683   # little-endian
WAL_FRAME_HDR_SZ = 24       # WAL 帧头大小 (bytes)


def derive_mac_key(enc_key, salt):
    """从 enc_key 派生 HMAC 密钥"""
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key, page_data, pgno):
    """解密单个页面，输出 4096 字节的标准 SQLite 页面"""
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]

    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        page = bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
        return bytes(page)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def decrypt_page_no_hmac(enc_key, page_data, pgno, salt=None):
    """解密单个页面（跳过 HMAC 验证）。

    用于解密 WAL 帧中的页面数据。WAL 帧的页面结构与主 DB 相同：
    - pgno == 1 时，前 SALT_SZ(16) 字节是 salt，加密区域跳过 salt
    - pgno > 1 时，整个页面（除 reserve 区域外）都是加密数据
    - WAL 文件尾部可能存在截断的帧（微信正在写入时）

    参数:
        enc_key: 32 字节加密密钥
        page_data: 加密的页面数据 (完整 PAGE_SZ 字节)
        pgno: 页面编号 (从帧头获取)
        salt: 主数据库的 salt (仅用于 pgno==1 时验证，不影响解密)
    """
    data_len = len(page_data)
    if data_len < PAGE_SZ:
        return b'\x00' * PAGE_SZ  # 不完整的页面，无法解密

    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]

    if pgno == 1:
        # page 1: 前 SALT_SZ 字节是 salt，跳过
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        # 重建完整 page 1: SQLite header + 解密内容 + reserve
        page = bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
        return bytes(page)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def decrypt_wal_file(wal_path, out_wal_path, enc_key, salt):
    """解密 SQLCipher 4 加密的 WAL 文件。

    WAL 文件格式 (SQLite):
        - 32 字节 WAL 文件头 (包含 magic, file format, page size, checkpoint seq 等)
        - 后续为连续的帧 (frame)，每帧结构:
            - 24 字节帧头 (page number, commit size, salt-1, salt-2, checksum-1, checksum-2)
            - page_size 字节的加密页面数据 (含 80 bytes reserve)

    由于 WAL 文件可能正在被微信写入（微信运行时），
    文件尾部可能存在不完整的帧，本函数会跳过这些截断帧。

    参数:
        wal_path: 加密的 WAL 文件路径
        out_wal_path: 解密后输出路径
        enc_key: 32 字节加密密钥
        salt: 主数据库的 salt (16 bytes)

    返回:
        (成功标志, 解密的帧数, 跳过的截断帧标志)
    """
    if not os.path.exists(wal_path):
        return False, 0, False

    wal_size = os.path.getsize(wal_path)
    if wal_size < 32 + WAL_FRAME_HDR_SZ + PAGE_SZ:
        return False, 0, False

    with open(wal_path, 'rb') as f:
        wal_header = f.read(32)
        magic = struct.unpack('>I', wal_header[0:4])[0]

        if magic not in (WAL_MAGIC_BE, WAL_MAGIC_LE):
            print(f"    [WARN] WAL magic 不匹配: 0x{magic:08x}")
            return False, 0, False

        is_le = (magic == WAL_MAGIC_LE)

        # 解析 WAL 文件头中的 page_size 验证
        if is_le:
            wal_page_sz = struct.unpack('<I', wal_header[8:12])[0]
        else:
            wal_page_sz = struct.unpack('>I', wal_header[8:12])[0]

        if wal_page_sz != PAGE_SZ:
            print(f"    [WARN] WAL page size ({wal_page_sz}) != 预期 ({PAGE_SZ})")
            # 仍然尝试处理

        # 读取帧数据
        frame_data = f.read()

    os.makedirs(os.path.dirname(out_wal_path) or '.', exist_ok=True)

    with open(out_wal_path, 'wb') as f:
        # 写入明文 WAL 文件头 (保持原样，只改 magic 为标准 SQLite)
        # 标准 SQLite WAL 头: magic(4) + file_format(4) + page_size(4) +
        #                    checkpoint_seq(4) + salt1(4) + salt2(4) +
        #                    checksum1(4) + checksum2(4)
        # magic 保持不变 (SQLite 用相同的 magic)
        f.write(wal_header)

        # 解析并解密每个帧
        offset = 0
        frame_count = 0
        had_truncated = False
        frame_size = WAL_FRAME_HDR_SZ + PAGE_SZ

        while offset + WAL_FRAME_HDR_SZ <= len(frame_data):
            frame_hdr = frame_data[offset:offset + WAL_FRAME_HDR_SZ]

            if is_le:
                pgno = struct.unpack('<I', frame_hdr[0:4])[0]
                commit_size = struct.unpack('<I', frame_hdr[4:8])[0]
            else:
                pgno = struct.unpack('>I', frame_hdr[0:4])[0]
                commit_size = struct.unpack('>I', frame_hdr[4:8])[0]

            # 检查帧数据是否完整
            if offset + frame_size > len(frame_data):
                # 不完整的帧 - 微信正在写入
                remaining = len(frame_data) - offset - WAL_FRAME_HDR_SZ
                if remaining > 0:
                    had_truncated = True
                break

            if pgno == 0 or pgno > 0x7FFFFFFF:
                # 无效的页号，可能已到帧数据末尾
                break

            encrypted_page = frame_data[offset + WAL_FRAME_HDR_SZ:offset + frame_size]

            # 解密页面 (WAL 中不含 page 1，都是 pgno > 1)
            try:
                decrypted_page = decrypt_page_no_hmac(enc_key, encrypted_page, pgno, salt)
            except Exception as e:
                print(f"    [WARN] 帧 {frame_count + 1} 解密失败 (pgno={pgno}): {e}")
                had_truncated = True
                break

            # 写入帧头 (保持原始帧头) + 解密后的页面
            f.write(frame_hdr)
            f.write(decrypted_page)

            frame_count += 1
            offset += frame_size

    return True, frame_count, had_truncated


def decrypt_database(db_path, out_path, enc_key):
    """解密整个数据库文件"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    if file_size % PAGE_SZ != 0:
        print(f"  [WARN] 文件大小 {file_size} 不是 {PAGE_SZ} 的倍数")
        total_pages += 1

    with open(db_path, 'rb') as fin:
        page1 = fin.read(PAGE_SZ)

    if len(page1) < PAGE_SZ:
        print(f"  [ERROR] 文件太小")
        return False

    # 提取 salt 并派生 mac_key，验证 page 1
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack('<I', 1))
    if hm.digest() != p1_stored_hmac:
        print(f"  [ERROR] Page 1 HMAC 验证失败! salt: {salt.hex()}")
        return False

    print(f"  HMAC OK, {total_pages} pages")

    # 解密所有页面
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break

            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)

            if pgno == 1:
                if decrypted[:16] != SQLITE_HDR:
                    print(f"  [WARN] 解密后 header 不匹配!")

            if pgno % 10000 == 0:
                print(f"  进度: {pgno}/{total_pages} ({100*pgno/total_pages:.1f}%)")

    return True


def try_merge_wal(decrypted_db_path, encrypted_db_path, enc_key, salt):
    """尝试解密 WAL 文件并合并到已解密的数据库。

    流程:
    1. 从加密源数据库路径找到对应的加密 .db-wal 文件
    2. 解密 WAL 文件，写入临时明文 WAL
    3. 将明文 WAL 临时放到已解密数据库旁边
    4. 使用 SQLite PRAGMA wal_checkpoint 将 WAL 数据合并到主文件
    5. 清理临时文件

    参数:
        decrypted_db_path: 已解密的主数据库路径 (输出目录中)
        encrypted_db_path: 加密的源数据库路径 (db_storage 目录中)
        enc_key: 32 字节加密密钥 (用于解密 WAL)
        salt: 主数据库的 salt (16 bytes, 从加密 .db 的 page 1 提取)

    返回:
        (成功标志, 合并的帧数, 状态描述)
    """
    import sqlite3

    # 加密源 WAL 路径 (与加密 .db 同目录)
    encrypted_wal_path = encrypted_db_path + '-wal'

    if not os.path.exists(encrypted_wal_path):
        return True, 0, "无 WAL 文件"

    wal_size = os.path.getsize(encrypted_wal_path)
    if wal_size <= 32:
        # WAL 文件只有头部，没有帧数据
        return True, 0, "WAL 文件为空"

    # 解密后的临时 WAL 放在已解密数据库同目录
    tmp_wal_path = decrypted_db_path + '.tmp.wal'

    try:
        # 解密 WAL 文件
        ok, frame_count, had_truncated = decrypt_wal_file(encrypted_wal_path, tmp_wal_path, enc_key, salt)

        if not ok:
            return False, 0, "WAL 解密失败"

        if frame_count == 0:
            return True, 0, "WAL 中无有效帧"

        # 不复制 SHM 文件！
        # SHM 是 SQLite 运行时的共享内存索引，直接复制会导致索引与
        # 解密后的 WAL 帧不匹配（因为 checksum 不同），SQLite 会认为
        # WAL 无效而跳过所有帧。让 SQLite 连接时自行重建 SHM。

        # 将解密后的 WAL 临时放到已解密数据库旁边
        final_wal_path = decrypted_db_path + '-wal'
        final_shm_path = decrypted_db_path + '-shm'

        # 备份已有的（如果有）
        backup_wal = None
        backup_shm = None
        if os.path.exists(final_wal_path):
            backup_wal = final_wal_path + '.bak'
            shutil.move(final_wal_path, backup_wal)
        if os.path.exists(final_shm_path):
            backup_shm = final_shm_path + '.bak'
            shutil.move(final_shm_path, backup_shm)

        try:
            shutil.move(tmp_wal_path, final_wal_path)

            # 打开数据库并执行 WAL checkpoint
            # 不需要显式设置 PRAGMA journal_mode=wal，解密后的 DB header
            # 中已声明使用 WAL 模式
            conn = sqlite3.connect(decrypted_db_path)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()

            return True, frame_count, f"合并 {frame_count} 帧" + (" (有截断帧被跳过)" if had_truncated else "")

        finally:
            # 清理临时 WAL（checkpoint 后 WAL 应已清空）
            if os.path.exists(final_wal_path):
                os.remove(final_wal_path)
            if os.path.exists(final_shm_path):
                os.remove(final_shm_path)
            if backup_wal and os.path.exists(backup_wal):
                shutil.move(backup_wal, final_wal_path)
            if backup_shm and os.path.exists(backup_shm):
                shutil.move(backup_shm, final_shm_path)

    finally:
        # 清理临时文件
        if os.path.exists(tmp_wal_path):
            try:
                os.remove(tmp_wal_path)
            except OSError:
                pass


def decrypt_database_with_wal(db_path, out_path, enc_key):
    """解密数据库（含 WAL 合并）。

    先解密主 .db 文件，再解密并合并 .db-wal 文件（如果存在）。

    参数:
        db_path: 加密的主数据库路径
        out_path: 解密输出路径
        enc_key: 32 字节加密密钥

    返回:
        (成功标志, 状态描述)
    """
    # 第一步：解密主数据库
    ok = decrypt_database(db_path, out_path, enc_key)
    if not ok:
        return False, "主数据库解密失败"

    # 提取 salt（从加密主数据库的 page 1）
    with open(db_path, 'rb') as f:
        salt = f.read(SALT_SZ)

    # 第二步：检查并合并 WAL
    wal_path = db_path + '-wal'
    if not os.path.exists(wal_path):
        return True, "OK"

    wal_size = os.path.getsize(wal_path)
    if wal_size <= 32:
        return True, "OK (WAL 为空)"

    print(f"  检测到 WAL 文件 ({wal_size/1024:.0f}KB)，尝试合并...", end=" ")
    ok, frame_count, status = try_merge_wal(out_path, db_path, enc_key, salt)
    if ok and frame_count > 0:
        print(f"  {status}")
    elif ok:
        print(f"  {status}")
    else:
        print(f"  WAL 合并失败: {status}")

    return ok, status


def main():
    from config import load_config
    from key_utils import get_key_info, strip_key_metadata

    print("=" * 60)
    print("  WeChat 4.0 数据库解密器 (独立版, 含 WAL 合并)")
    print("=" * 60)

    # 支持命令行参数指定配置项
    import argparse
    parser = argparse.ArgumentParser(description="WeChat 4.0 数据库解密器 (含 WAL 合并)")
    parser.add_argument("--db-dir", help="微信数据库目录路径 (db_storage)")
    parser.add_argument("--keys-file", help="密钥文件路径 (all_keys.json)")
    parser.add_argument("--out-dir", help="解密输出目录")
    parser.add_argument("--config", help="配置文件路径 (默认: 同目录下 config.json)")
    parser.add_argument("--no-wal", action="store_true",
                        help="跳过 WAL 文件处理 (仅解密主数据库)")
    args = parser.parse_args()

    cfg = load_config(args.config if hasattr(args, 'config') and args.config else None)

    # 命令行参数覆盖配置文件
    DB_DIR = args.db_dir or cfg["db_dir"]
    OUT_DIR = args.out_dir or cfg["decrypted_dir"]
    KEYS_FILE = args.keys_file or cfg["keys_file"]
    SKIP_WAL = args.no_wal

    # 加载密钥
    if not os.path.exists(KEYS_FILE):
        print(f"[ERROR] 密钥文件不存在: {KEYS_FILE}")
        print("请先使用 find_all_keys_macos 提取密钥，生成 all_keys.json")
        print("用法: ./find_all_keys_macos > all_keys.json")
        sys.exit(1)

    with open(KEYS_FILE, encoding="utf-8") as f:
        keys = json.load(f)

    keys = strip_key_metadata(keys)
    print(f"\n加载 {len(keys)} 个数据库密钥")
    print(f"数据库目录: {DB_DIR}")
    print(f"输出目录: {OUT_DIR}")
    if SKIP_WAL:
        print("WAL 合并: 已禁用")
    else:
        print("WAL 合并: 已启用")
    os.makedirs(OUT_DIR, exist_ok=True)

    # 收集所有 DB 文件
    db_files = []
    for root, dirs, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, DB_DIR)
                sz = os.path.getsize(path)
                db_files.append((rel, path, sz))

    db_files.sort(key=lambda x: x[2])  # 从小到大

    # 统计 WAL 信息
    wal_count = 0
    wal_total_size = 0
    if not SKIP_WAL:
        for rel, path, sz in db_files:
            wal_path = path + '-wal'
            if os.path.exists(wal_path):
                wal_size = os.path.getsize(wal_path)
                if wal_size > 32:
                    wal_count += 1
                    wal_total_size += wal_size

    print(f"找到 {len(db_files)} 个数据库文件")
    if not SKIP_WAL:
        print(f"其中 {wal_count} 个有 WAL 数据 ({wal_total_size/1024/1024:.1f}MB)")
    print()

    success = 0
    failed = 0
    total_bytes = 0
    wal_merged = 0

    for rel, path, sz in db_files:
        key_info = get_key_info(keys, rel)
        if not key_info:
            print(f"SKIP: {rel} (无密钥)")
            failed += 1
            continue

        enc_key = bytes.fromhex(key_info["enc_key"])
        out_path = os.path.join(OUT_DIR, rel)

        print(f"解密: {rel} ({sz/1024/1024:.1f}MB) ...", end=" ")

        if SKIP_WAL:
            ok = decrypt_database(path, out_path, enc_key)
            status = "OK" if ok else "FAIL"
        else:
            ok, status = decrypt_database_with_wal(path, out_path, enc_key)

        if ok:
            # SQLite 验证
            try:
                import sqlite3
                conn = sqlite3.connect(out_path)
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                conn.close()
                table_names = [t[0] for t in tables]
                print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
                if len(table_names) > 5:
                    print(f" ...共{len(table_names)}个", end="")
                if "合并" in status:
                    print(f" [{status}]", end="")
                    wal_merged += 1
                print()
                success += 1
                total_bytes += sz
            except Exception as e:
                print(f"  [WARN] SQLite 验证失败: {e}")
                failed += 1
        else:
            print(f"  [FAIL] {status}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"结果: {success} 成功, {failed} 失败, 共 {len(db_files)} 个")
    print(f"解密数据量: {total_bytes/1024/1024/1024:.1f}GB")
    if not SKIP_WAL:
        print(f"WAL 合并: {wal_merged} 个数据库合并了 WAL 数据")
    print(f"解密文件在: {OUT_DIR}")


if __name__ == '__main__':
    main()
