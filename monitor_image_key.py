import os
import sys
import re
import struct
import glob
import time
import ctypes
from ctypes import wintypes
from Crypto.Cipher import AES
from Crypto.Util import Padding

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
                    return header[15:31], os.path.basename(f), f
            except Exception:
                continue
    return None, None, None


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

        result = _scan_regions(h_process, rw_regions, ciphertext)
        if result:
            return result

        rw_set = set((r[0], r[1]) for r in rw_regions)
        other_regions = [r for r in all_regions if (r[0], r[1]) not in rw_set]
        result = _scan_regions(h_process, other_regions, ciphertext)
        if result:
            return result
        return None
    finally:
        kernel32.CloseHandle(h_process)


def _scan_regions(h_process, regions, ciphertext):
    for idx, (base_addr, region_size, _protect) in enumerate(regions):
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
            fmt = try_key(key_bytes[:16], ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                return key_str[:16]

        for m in RE_KEY16.finditer(data):
            key_bytes = m.group()
            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                return key_str
    return None


def decrypt_v2_dat(dat_path, aes_key, xor_key):
    with open(dat_path, "rb") as f:
        data = f.read()
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    aligned_aes_size = aes_size - ~(~aes_size % 16)
    raw_size = len(data) - 15 - aligned_aes_size - xor_size
    aes_d = data[15:15 + aligned_aes_size]
    xor_d = data[15 + aligned_aes_size + raw_size:]
    raw_d = data[15 + aligned_aes_size:15 + aligned_aes_size + raw_size]

    cipher = AES.new(aes_key.encode()[:16], AES.MODE_ECB)
    dec_aes = Padding.unpad(cipher.decrypt(aes_d), AES.block_size)
    dec_xor = bytes(b ^ xor_key for b in xor_d)
    full = dec_aes + raw_d + dec_xor

    fmt = "bin"
    if full[:3] == b"\xFF\xD8\xFF":
        fmt = "jpg"
    elif full[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
        fmt = "png"
    elif full[:4] == b"RIFF":
        fmt = "webp"
    return full, fmt


def main():
    if len(sys.argv) < 2:
        print("WeChat V2 Image AES Key Monitor")
        print()
        print("Usage:")
        print("  python monitor_image_key.py <xwechat_attach_dir> [--xor-key 0xNN]")
        print()
        print("Example:")
        print('  python monitor_image_key.py "C:\\Users\\<USER>\\Documents\\xwechat_files\\<wxid>\\msg\\attach"')
        print()
        print("IMPORTANT: View 2-3 images in WeChat while this script is running!")
        sys.exit(1)

    attach_dir = sys.argv[1]
    if not os.path.exists(attach_dir):
        print(f"Directory not found: {attach_dir}")
        sys.exit(1)

    xor_key = 0x88
    for i, arg in enumerate(sys.argv):
        if arg == '--xor-key' and i + 1 < len(sys.argv):
            xor_key = int(sys.argv[i + 1], 0)

    ciphertext, ct_file, sample_dat = find_v2_ciphertext(attach_dir)
    if ciphertext is None:
        print("No V2 .dat files found")
        sys.exit(1)

    print(f"V2 ciphertext from: {ct_file}")
    print(f"Cipher: {ciphertext.hex()}")
    print()
    print("=" * 60)
    print("  V2 Image AES Key Monitor")
    print("=" * 60)
    print()
    print("Please do the following in WeChat:")
    print("  1. Open a chat or Moments")
    print("  2. Click to view 2-3 images in full size")
    print("  3. This script will automatically detect the key")
    print()
    print("Monitoring... (press Ctrl+C to stop)")
    print()

    pids = get_wechat_pids()
    if not pids:
        print("WeChat not running!")
        sys.exit(1)

    try:
        scan_count = 0
        while True:
            scan_count += 1
            for pid in pids:
                aes_key = scan_memory_for_aes_key(pid, ciphertext)
                if aes_key:
                    print(f"\n{'=' * 60}")
                    print(f"  FOUND AES KEY: {aes_key}")
                    print(f"{'=' * 60}")

                    with open("found_image_keys.txt", "w") as f:
                        f.write(f"aes_key={aes_key}\n")
                        f.write(f"xor_key=0x{xor_key:02x}\n")
                    print(f"Saved to found_image_keys.txt")

                    if sample_dat:
                        full, fmt = decrypt_v2_dat(sample_dat, aes_key, xor_key)
                        out_path = sample_dat.replace(".dat", f".{fmt}")
                        with open(out_path, "wb") as f:
                            f.write(full)
                        print(f"Decrypted test image: {out_path} ({len(full):,} bytes, {fmt})")
                    return

            print(f"  Scan #{scan_count} - key not found yet... (view images in WeChat!)", end="\r", flush=True)
            time.sleep(3)

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")


if __name__ == '__main__':
    main()
