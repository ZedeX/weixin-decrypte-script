import os
import sys
import re
import struct
import glob
import ctypes
from ctypes import wintypes
from Crypto.Cipher import AES

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.windll.kernel32

RE_KEY32 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{32}(?![a-zA-Z0-9])')
RE_KEY16 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{16}(?![a-zA-Z0-9])')


def get_wechat_pids():
    import subprocess
    result = subprocess.run(
        ['tasklist.exe', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        if 'Weixin.exe' in line:
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                pids.append(int(parts[1]))
    return pids


def find_v2_ciphertext(attach_dir):
    v2_magic = b'\x07\x08V2\x08\x07'
    for pattern in [
        os.path.join(attach_dir, "*", "*", "Img", "*_t.dat"),
        os.path.join(attach_dir, "*", "*", "Img", "*.dat"),
    ]:
        dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        for f in dat_files[:200]:
            try:
                with open(f, 'rb') as fp:
                    header = fp.read(31)
                if header[:6] == v2_magic and len(header) >= 31:
                    return header[15:31], os.path.basename(f)
            except Exception:
                continue
    return None, None


def find_xor_key(attach_dir):
    v2_magic = b'\x07\x08V2\x08\x07'
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    tail_counts = {}
    for f in dat_files[:32]:
        try:
            sz = os.path.getsize(f)
            with open(f, 'rb') as fp:
                head = fp.read(6)
                fp.seek(sz - 2)
                tail = fp.read(2)
            if head == v2_magic and len(tail) == 2:
                key = (tail[0], tail[1])
                tail_counts[key] = tail_counts.get(key, 0) + 1
        except Exception:
            continue
    if not tail_counts:
        return None
    most_common = max(tail_counts, key=tail_counts.get)
    x, y = most_common
    xor_key = x ^ 0xFF
    check = y ^ 0xD9
    if xor_key == check:
        return xor_key
    return xor_key


def try_key(key_bytes, ciphertext):
    try:
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        dec = cipher.decrypt(ciphertext)
        if dec[:3] == b'\xFF\xD8\xFF':
            return 'JPEG'
        if dec[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
            return 'PNG'
        if dec[:4] == b'RIFF':
            return 'WEBP'
        if dec[:4] == b'wxgf':
            return 'WXGF'
        if dec[:3] == b'GIF':
            return 'GIF'
    except Exception:
        pass
    return None


def is_rw_protect(protect):
    rw_flags = (PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return (protect & rw_flags) != 0


def scan_memory_for_aes_key(pid, ciphertext):
    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    h_process = kernel32.OpenProcess(access, False, pid)
    if not h_process:
        print(f"  Cannot open process {pid} (run as Administrator)")
        return None
    try:
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        rw_regions = []
        all_regions = []
        while address < 0x7FFFFFFFFFFF:
            result = kernel32.VirtualQueryEx(
                h_process, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if result == 0:
                break
            if (mbi.State == MEM_COMMIT and
                mbi.Protect != PAGE_NOACCESS and
                (mbi.Protect & PAGE_GUARD) == 0 and
                mbi.RegionSize <= 50 * 1024 * 1024):
                region = (mbi.BaseAddress, mbi.RegionSize, mbi.Protect)
                all_regions.append(region)
                if is_rw_protect(mbi.Protect):
                    rw_regions.append(region)
            next_addr = address + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr

        rw_mb = sum(r[1] for r in rw_regions) / 1024 / 1024
        all_mb = sum(r[1] for r in all_regions) / 1024 / 1024
        print(f"  RW regions: {len(rw_regions)} ({rw_mb:.0f} MB), Total: {len(all_regions)} ({all_mb:.0f} MB)")

        print("  === Phase 1: Scanning RW memory ===")
        result = _scan_regions(h_process, rw_regions, ciphertext)
        if result:
            return result

        print("  === Phase 2: Scanning all memory ===")
        rw_set = set((r[0], r[1]) for r in rw_regions)
        other_regions = [r for r in all_regions if (r[0], r[1]) not in rw_set]
        result = _scan_regions(h_process, other_regions, ciphertext)
        if result:
            return result
        return None
    finally:
        kernel32.CloseHandle(h_process)


def _scan_regions(h_process, regions, ciphertext):
    import time
    candidates_32 = 0
    candidates_16 = 0
    t0 = time.time()
    for idx, (base_addr, region_size, _protect) in enumerate(regions):
        if idx % 100 == 0:
            elapsed = time.time() - t0
            print(f"  Scanning {idx}/{len(regions)} ({elapsed:.1f}s)", end='\r', flush=True)
        buffer = ctypes.create_string_buffer(region_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(base_addr),
            buffer, region_size, ctypes.byref(bytes_read)
        )
        if not ok or bytes_read.value < 32:
            continue
        data = buffer.raw[:bytes_read.value]

        for m in RE_KEY32.finditer(data):
            key_bytes = m.group()
            candidates_32 += 1
            fmt = try_key(key_bytes[:16], ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                print(f"\n*** Found AES key (32-char)! -> {fmt} ***")
                print(f"  Full: {key_str}")
                print(f"  AES key: {key_str[:16]}")
                return key_str[:16]

        for m in RE_KEY16.finditer(data):
            key_bytes = m.group()
            candidates_16 += 1
            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                print(f"\n*** Found AES key (16-char)! -> {fmt} ***")
                print(f"  AES key: {key_str}")
                return key_str

    elapsed = time.time() - t0
    print(f"\n  Tested: {candidates_32} x 32-char + {candidates_16} x 16-char ({elapsed:.1f}s)")
    return None


def main():
    if len(sys.argv) < 2:
        print("WeChat V2 Image AES Key Finder")
        print()
        print("Usage:")
        print("  python find_image_key.py <xwechat_attach_dir>")
        print()
        print("Example:")
        print('  python find_image_key.py "C:\\Users\\<USER>\\Documents\\xwechat_files\\<wxid>\\msg\\attach"')
        print()
        print("IMPORTANT: View 2-3 images in WeChat before running this script!")
        sys.exit(1)

    attach_dir = sys.argv[1]
    if not os.path.exists(attach_dir):
        print(f"Directory not found: {attach_dir}")
        sys.exit(1)

    print("=== XOR Key ===")
    xor_key = find_xor_key(attach_dir)
    if xor_key is not None:
        print(f"XOR key: 0x{xor_key:02x}")
    else:
        print("XOR key: not found (using default 0x88)")
        xor_key = 0x88

    print("\n=== V2 Ciphertext ===")
    ciphertext, ct_file = find_v2_ciphertext(attach_dir)
    if ciphertext is None:
        print("No V2 .dat files found")
        sys.exit(1)
    print(f"File: {ct_file}")
    print(f"Cipher: {ciphertext.hex()}")

    print("\n=== Scanning WeChat process memory ===")
    pids = get_wechat_pids()
    if not pids:
        print("WeChat not running!")
        sys.exit(1)
    print(f"PIDs: {pids}")
    print("Tip: View 2-3 images in WeChat first, then run this script immediately\n")

    aes_key = None
    for pid in pids:
        print(f"Scanning PID {pid}...")
        aes_key = scan_memory_for_aes_key(pid, ciphertext)
        if aes_key:
            break

    if aes_key:
        print(f"\n=== Result ===")
        print(f"AES key: {aes_key}")
        print(f"XOR key: 0x{xor_key:02x}")

        with open("found_image_keys.txt", "w") as f:
            f.write(f"aes_key={aes_key}\n")
            f.write(f"xor_key=0x{xor_key:02x}\n")
        print("Saved to found_image_keys.txt")
    else:
        print("\nAES key not found!")
        print("Steps:")
        print("  1. Login WeChat and keep it running")
        print("  2. Open Moments or a chat, view 2-3 images (tap to open full size)")
        print("  3. Immediately re-run this script")


if __name__ == '__main__':
    main()
