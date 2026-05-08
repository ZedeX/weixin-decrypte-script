import pymem
import psutil
import sys
import re


def find_weixin_pid():
    processes = [
        (p.pid, p.info['cmdline'])
        for p in psutil.process_iter(['pid', 'name', 'cmdline'])
        if p.info['name'] and p.info['name'].lower() == 'weixin.exe'
    ]
    if not processes:
        return None
    pid = min(processes, key=lambda _: len(_[1] or []))[0]
    return pid


def find_keys(pid):
    keys = []
    try:
        pm = pymem.Pymem()
        pm.open_process_from_id(pid)
    except Exception as e:
        print(f"Failed to open process {pid}: {e}")
        print("Please run as Administrator.")
        return keys

    print(f"Scanning memory of Weixin.exe (PID: {pid})...")
    try:
        addresses = pm.pattern_scan_all(b"x'", return_multiple=True)
    except Exception as e:
        print(f"Memory scan failed: {e}")
        return keys

    print(f"Found {len(addresses)} potential key prefixes, filtering...")

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
    return keys


def main():
    pid = find_weixin_pid()
    if pid is None:
        print("Weixin.exe is not running! Please start WeChat first.")
        sys.exit(1)

    print(f"Weixin.exe found, PID: {pid}")
    keys = find_keys(pid)

    if not keys:
        print("No keys found. Make sure WeChat is logged in.")
        sys.exit(1)

    print(f"\nFound {len(keys)} unique keys (sorted by frequency):\n")
    print(f"{'#':<4} {'Frequency':<12} {'Key (hex)'}")
    print("-" * 80)
    for i, (key_bytes, count) in enumerate(keys):
        hex_key = key_bytes[2:66].decode("ascii")
        print(f"{i:<4} {count:<12} {hex_key}")

    print("\nTip: Try the most frequent key first when decrypting databases.")
    print("Key format for SQLCipher PRAGMA: x'<hex_key>'")

    with open("found_keys.txt", "w") as f:
        for i, (key_bytes, count) in enumerate(keys):
            hex_key = key_bytes[2:66].decode("ascii")
            f.write(f"{i}\t{count}\t{hex_key}\n")
    print("\nKeys saved to found_keys.txt")


if __name__ == "__main__":
    main()
