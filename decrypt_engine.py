import hmac
import hashlib
import os
import re
import sys
from Crypto.Cipher import AES

try:
    import pymem
    import psutil
    HAS_PYMEM = True
except ImportError:
    HAS_PYMEM = False

KEY_SZ = 32
PAGE_SZ = 4096
SQLITE_FILE_HEADER = bytes("SQLite format 3", encoding="ASCII") + bytes(1)
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = (IV_SZ + HMAC_SZ + 15) // 16 * 16


def find_weixin_pid():
    if not HAS_PYMEM:
        return None
    processes = [
        (p.pid, p.info['cmdline'])
        for p in psutil.process_iter(['pid', 'name', 'cmdline'])
        if p.info['name'] and p.info['name'].lower() == 'weixin.exe'
    ]
    if not processes:
        return None
    pid = min(processes, key=lambda _: len(_[1] or []))[0]
    return pid


def scan_keys_from_memory():
    if not HAS_PYMEM:
        print("[DecryptEngine] pymem/psutil not installed, cannot scan keys from memory")
        return []

    pid = find_weixin_pid()
    if pid is None:
        print("[DecryptEngine] Weixin.exe not running, cannot scan keys")
        return []

    print(f"[DecryptEngine] Scanning memory of Weixin.exe (PID: {pid})...")
    keys = []
    try:
        pm = pymem.Pymem()
        pm.open_process_from_id(pid)
    except Exception as e:
        print(f"[DecryptEngine] Failed to open process: {e}")
        return []

    try:
        addresses = pm.pattern_scan_all(b"x'", return_multiple=True)
    except Exception as e:
        print(f"[DecryptEngine] Memory scan failed: {e}")
        return []

    for a in addresses:
        try:
            b = pm.read_bytes(a, 3 + 64 + 32)
        except Exception:
            continue
        if len(b) < 67:
            continue
        if b[66] != ord("'") and (len(b) < 99 or b[98] != ord("'")):
            continue
        hex_part = b[2:66]
        try:
            hex_str = hex_part.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not re.match(r'^[0-9a-fA-F]{64}$', hex_str):
            continue
        found_key = b[0:66]
        for existed_key in keys:
            if existed_key[0] == found_key:
                existed_key[1] += 1
                break
        else:
            keys.append([found_key, 1])

    keys.sort(key=lambda _: _[1], reverse=True)
    hex_keys = [k[0][2:66].decode("ascii") for k in keys]
    print(f"[DecryptEngine] Found {len(hex_keys)} unique keys")
    return hex_keys


def decrypt_db(db_path, rawkey, output_path=None):
    if output_path is None:
        output_path = db_path
        if output_path.endswith(".db"):
            output_path = output_path[:-3] + ".decrypted.db"
        else:
            output_path += ".decrypted.db"

    with open(db_path, "rb") as f:
        blist = f.read()

    if len(blist) < PAGE_SZ:
        return None

    salt = blist[:SALT_SZ]
    key = rawkey
    page1 = blist[SALT_SZ:PAGE_SZ]

    mac_salt = bytes(x ^ 0x3a for x in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, KEY_SZ)
    hash_mac = hmac.new(mac_key, digestmod="sha512")
    hash_mac.update(page1[:-RESERVE_SZ + IV_SZ])
    hash_mac.update(bytes.fromhex("01 00 00 00"))

    if hash_mac.digest() != page1[-RESERVE_SZ + IV_SZ:][:HMAC_SZ]:
        return None

    pages = [page1]
    pages += [blist[i:i + PAGE_SZ] for i in range(PAGE_SZ, len(blist), PAGE_SZ)]

    with open(output_path, "wb") as f:
        f.write(SQLITE_FILE_HEADER)
        for i in pages:
            t = AES.new(key, AES.MODE_CBC, i[-RESERVE_SZ:][:IV_SZ])
            f.write(t.decrypt(i[:-RESERVE_SZ]))
            f.write(i[-RESERVE_SZ:])

    return output_path


def find_db_files(base_dir):
    db_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(".decrypted.db"):
                db_files.append(os.path.join(root, f))
    return db_files


def find_decrypted_path(db_path):
    if db_path.endswith(".db"):
        return db_path[:-3] + ".decrypted.db"
    return db_path + ".decrypted.db"


def auto_decrypt(base_dir, keys_hex=None):
    if keys_hex is None:
        keys_hex = scan_keys_from_memory()
        if not keys_hex:
            print("[DecryptEngine] No keys available, skipping decryption")
            return 0, 0

    db_files = find_db_files(base_dir)
    print(f"[DecryptEngine] Found {len(db_files)} encrypted database files")

    success = 0
    failed = 0
    skipped = 0

    for db_path in db_files:
        decrypted_path = find_decrypted_path(db_path)
        if os.path.exists(decrypted_path):
            skipped += 1
            continue

        rel_path = os.path.relpath(db_path, base_dir)
        decrypted = False
        for hex_key in keys_hex:
            try:
                rawkey = bytes.fromhex(hex_key)
            except ValueError:
                continue
            result = decrypt_db(db_path, rawkey, decrypted_path)
            if result:
                print(f"  [OK] {rel_path}")
                success += 1
                decrypted = True
                break

        if not decrypted:
            print(f"  [FAIL] {rel_path}")
            failed += 1

    print(f"[DecryptEngine] Done: {success} decrypted, {failed} failed, {skipped} already decrypted")
    return success, failed


def ensure_decrypted(base_dir, keys_hex=None):
    db_files = find_db_files(base_dir)
    need_decrypt = []
    for db_path in db_files:
        decrypted_path = find_decrypted_path(db_path)
        if not os.path.exists(decrypted_path):
            need_decrypt.append(db_path)

    if not need_decrypt:
        print(f"[DecryptEngine] All {len(db_files)} databases already decrypted")
        return True

    print(f"[DecryptEngine] {len(need_decrypt)} databases need decryption")

    if keys_hex is None:
        keys_hex = scan_keys_from_memory()

    if not keys_hex:
        print("[DecryptEngine] No keys available!")
        return False

    success, failed = auto_decrypt(base_dir, keys_hex)
    return failed == 0
