import hmac
import hashlib
import os
import sys
import glob
from Crypto.Cipher import AES


KEY_SZ = 32
PAGE_SZ = 4096
SQLITE_FILE_HEADER = bytes("SQLite format 3", encoding="ASCII") + bytes(1)

SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = (IV_SZ + HMAC_SZ + 15) // 16 * 16


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
        print(f"  File too small: {db_path}")
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


def try_decrypt_with_keys(db_path, keys_hex):
    for idx, hex_key in enumerate(keys_hex):
        try:
            rawkey = bytes.fromhex(hex_key)
        except ValueError:
            continue
        result = decrypt_db(db_path, rawkey)
        if result:
            return result, hex_key, idx
    return None, None, None


def find_db_files(base_dir):
    db_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(".decrypted.db"):
                db_files.append(os.path.join(root, f))
    return db_files


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python decrypt_db.py <db_path> <hex_key>")
        print("  python decrypt_db.py --auto <xwechat_files_dir> <keys_file>")
        print()
        print("Examples:")
        print("  python decrypt_db.py contact.db 09d67210196934ad620b9a9676f96ba16302d3a0cbd6af3fada41288ce08a47d")
        print("  python decrypt_db.py --auto <xwechat_files_dir> found_keys.txt")
        sys.exit(1)

    if sys.argv[1] == "--auto":
        if len(sys.argv) < 4:
            print("Usage: python decrypt_db.py --auto <xwechat_files_dir> <keys_file>")
            sys.exit(1)

        base_dir = sys.argv[2]
        keys_file = sys.argv[3]

        with open(keys_file, "r") as f:
            keys_hex = [line.strip().split("\t")[2] for line in f if line.strip()]

        print(f"Loaded {len(keys_hex)} keys from {keys_file}")

        db_files = find_db_files(base_dir)
        print(f"Found {len(db_files)} database files\n")

        success = 0
        failed = 0
        for db_path in db_files:
            rel_path = os.path.relpath(db_path, base_dir)
            result, matched_key, key_idx = try_decrypt_with_keys(db_path, keys_hex)
            if result:
                print(f"  [OK] {rel_path} (key #{key_idx})")
                success += 1
            else:
                print(f"  [FAIL] {rel_path}")
                failed += 1

        print(f"\nDone: {success} succeeded, {failed} failed")
    else:
        db_path = sys.argv[1]
        hex_key = sys.argv[2]

        if not os.path.exists(db_path):
            print(f"File not found: {db_path}")
            sys.exit(1)

        rawkey = bytes.fromhex(hex_key)
        print(f"Decrypting {db_path}...")
        result = decrypt_db(db_path, rawkey)
        if result:
            print(f"Success! Decrypted file: {result}")
        else:
            print("Failed: Wrong key or corrupted database")


if __name__ == "__main__":
    main()
