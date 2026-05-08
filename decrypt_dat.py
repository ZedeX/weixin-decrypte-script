import os
import sys
import struct
from Crypto.Cipher import AES
from Crypto.Util import Padding

V2_MAGIC = b'\x07\x08\x56\x32'
V2_MAGIC_FULL = b'\x07\x08V2\x08\x07'
V1_MAGIC_FULL = b'\x07\x08V1\x08\x07'

IMAGE_MAGIC = {
    'png': [0x89, 0x50, 0x4E, 0x47],
    'gif': [0x47, 0x49, 0x46, 0x38],
    'tif': [0x49, 0x49, 0x2A, 0x00],
    'webp': [0x52, 0x49, 0x46, 0x46],
    'jpg': [0xFF, 0xD8, 0xFF],
}


def detect_xor_key(dat_path):
    with open(dat_path, 'rb') as f:
        header = f.read(16)
    if len(header) < 4:
        return None
    if header[:4] == V2_MAGIC:
        return None
    for fmt, magic in IMAGE_MAGIC.items():
        key = header[0] ^ magic[0]
        match = True
        for i in range(1, len(magic)):
            if i >= len(header):
                break
            if (header[i] ^ key) != magic[i]:
                match = False
                break
        if match:
            return key
    bmp_magic = [0x42, 0x4D]
    key = header[0] ^ bmp_magic[0]
    if len(header) >= 2 and (header[1] ^ key) == bmp_magic[1]:
        if len(header) >= 14:
            dec = bytes(b ^ key for b in header[:14])
            bmp_size = struct.unpack_from('<I', dec, 2)[0]
            bmp_offset = struct.unpack_from('<I', dec, 10)[0]
            file_size = os.path.getsize(dat_path)
            if abs(bmp_size - file_size) < 1024 and 14 <= bmp_offset <= 1078:
                return key
    return None


def detect_image_format(header_bytes):
    if header_bytes[:3] == bytes([0xFF, 0xD8, 0xFF]):
        return 'jpg'
    if header_bytes[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
        return 'png'
    if header_bytes[:3] == b'GIF':
        return 'gif'
    if header_bytes[:2] == b'BM':
        return 'bmp'
    if header_bytes[:4] == b'RIFF' and len(header_bytes) >= 12 and header_bytes[8:12] == b'WEBP':
        return 'webp'
    if header_bytes[:4] == bytes([0x49, 0x49, 0x2A, 0x00]):
        return 'tif'
    if header_bytes[:4] == b'wxgf':
        return 'hevc'
    return 'bin'


def xor_decrypt_file(dat_path, out_path=None, key=None):
    if key is None:
        key = detect_xor_key(dat_path)
    if key is None:
        return None, None
    with open(dat_path, 'rb') as f:
        data = f.read()
    decrypted = bytes(b ^ key for b in data)
    fmt = detect_image_format(decrypted[:16])
    if out_path is None:
        base = os.path.splitext(dat_path)[0]
        for suffix in ('_t', '_h'):
            if base.endswith(suffix):
                base = base[:-len(suffix)]
                break
        out_path = f"{base}.{fmt}"
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(decrypted)
    return out_path, fmt


def v2_decrypt_file(dat_path, out_path=None, aes_key=None, xor_key=0x88):
    if aes_key is None:
        return None, None
    if isinstance(aes_key, str):
        aes_key = aes_key.encode('ascii')[:16]
    if len(aes_key) < 16:
        return None, None
    if isinstance(xor_key, str):
        xor_key = int(xor_key, 0)
    with open(dat_path, 'rb') as f:
        data = f.read()
    if len(data) < 15:
        return None, None
    sig = data[:6]
    if sig not in (V2_MAGIC_FULL, V1_MAGIC_FULL):
        return None, None
    aes_size, xor_size = struct.unpack_from('<LL', data, 6)
    if sig == V1_MAGIC_FULL:
        aes_key = b'cfcd208495d565ef'
    aligned_aes_size = aes_size
    aligned_aes_size -= ~(~aligned_aes_size % 16)
    offset = 15
    if offset + aligned_aes_size > len(data):
        return None, None
    aes_data = data[offset:offset + aligned_aes_size]
    try:
        cipher = AES.new(aes_key[:16], AES.MODE_ECB)
        dec_aes = Padding.unpad(cipher.decrypt(aes_data), AES.block_size)
    except (ValueError, KeyError):
        return None, None
    offset += aligned_aes_size
    raw_end = len(data) - xor_size
    raw_data = data[offset:raw_end] if offset < raw_end else b''
    offset = raw_end
    xor_data = data[offset:]
    dec_xor = bytes(b ^ xor_key for b in xor_data)
    decrypted = dec_aes + raw_data + dec_xor
    fmt = detect_image_format(decrypted[:16])
    if decrypted[:4] == b'wxgf':
        fmt = 'hevc'
    if out_path is None:
        base = os.path.splitext(dat_path)[0]
        for suffix in ('_t', '_h'):
            if base.endswith(suffix):
                base = base[:-len(suffix)]
                break
        out_path = f"{base}.{fmt}"
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(decrypted)
    return out_path, fmt


def decrypt_dat_file(dat_path, out_path=None, aes_key=None, xor_key=0x88):
    with open(dat_path, 'rb') as f:
        head = f.read(6)
    if head == V2_MAGIC_FULL:
        return v2_decrypt_file(dat_path, out_path, aes_key, xor_key)
    if head == V1_MAGIC_FULL:
        return v2_decrypt_file(dat_path, out_path, b'cfcd208495d565ef', xor_key)
    return xor_decrypt_file(dat_path, out_path)


def find_image_aes_key():
    import pymem
    import psutil

    processes = [
        (p.pid, p.info['cmdline'])
        for p in psutil.process_iter(['pid', 'name', 'cmdline'])
        if p.info['name'] and p.info['name'].lower() == 'weixin.exe'
    ]
    if not processes:
        print("Weixin.exe is not running!")
        return None
    pid = min(processes, key=lambda _: len(_[1] or []))[0]
    print(f"Weixin.exe PID: {pid}")

    pm = pymem.Pymem()
    pm.open_process_from_id(pid)

    header_pattern = b'\x07\x08\x56\x32\x08\x07'
    print("Scanning memory for V2 header pattern...")
    addresses = pm.pattern_scan_all(header_pattern, return_multiple=True)
    print(f"Found {len(addresses)} matches")

    candidates = set()
    for addr in addresses:
        for offset in range(-256, 0, 1):
            try:
                candidate = pm.read_bytes(addr + offset, 16)
                if all(0x20 <= b < 0x7f for b in candidate):
                    candidates.add(candidate)
            except Exception:
                continue
        for offset in range(6, 256, 1):
            try:
                candidate = pm.read_bytes(addr + offset, 16)
                if all(0x20 <= b < 0x7f for b in candidate):
                    candidates.add(candidate)
            except Exception:
                continue

    print(f"Found {len(candidates)} ASCII key candidates near header pattern:")
    for c in sorted(candidates):
        print(f"  {c.decode('ascii', errors='replace')}")

    return candidates


def batch_decrypt(input_dir, output_dir=None, aes_key=None, xor_key=0x88):
    stats = {'xor': 0, 'v1': 0, 'v2': 0, 'failed': 0, 'total': 0}
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            if not f.endswith('.dat'):
                continue
            dat_path = os.path.join(root, f)
            stats['total'] += 1

            if output_dir:
                rel = os.path.relpath(dat_path, input_dir)
                out_path = os.path.join(output_dir, rel)
            else:
                out_path = None

            result_path, fmt = decrypt_dat_file(dat_path, out_path, aes_key, xor_key)
            if result_path:
                with open(dat_path, 'rb') as fh:
                    head = fh.read(6)
                if head == V2_MAGIC_FULL:
                    stats['v2'] += 1
                elif head == V1_MAGIC_FULL:
                    stats['v1'] += 1
                else:
                    stats['xor'] += 1
            else:
                stats['failed'] += 1

            if stats['total'] % 100 == 0:
                print(f"  Processed {stats['total']} files...")

    print(f"\nBatch decrypt complete:")
    print(f"  Total: {stats['total']}")
    print(f"  XOR (old format): {stats['xor']}")
    print(f"  V1 (fixed AES key): {stats['v1']}")
    print(f"  V2 (AES-ECB+XOR): {stats['v2']}")
    print(f"  Failed: {stats['failed']}")
    return stats


def main():
    if len(sys.argv) < 2:
        print("WeChat DAT Image File Decryptor")
        print("Supports: XOR (old), V1 (fixed AES), V2 (AES-128-ECB + XOR)")
        print()
        print("Usage:")
        print("  python decrypt_dat.py <dat_file> [output_file]")
        print("  python decrypt_dat.py --find-key")
        print("  python decrypt_dat.py --batch <input_dir> [output_dir] [--aes-key <key>] [--xor-key <key>]")
        sys.exit(1)

    if sys.argv[1] == "--find-key":
        find_image_aes_key()
        return

    if sys.argv[1] == "--batch":
        if len(sys.argv) < 3:
            print("Usage: python decrypt_dat.py --batch <input_dir> [output_dir]")
            sys.exit(1)
        input_dir = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('--') else None
        aes_key = None
        xor_key = 0x88
        for i, arg in enumerate(sys.argv):
            if arg == '--aes-key' and i + 1 < len(sys.argv):
                aes_key = sys.argv[i + 1]
            if arg == '--xor-key' and i + 1 < len(sys.argv):
                xor_key = int(sys.argv[i + 1], 0)
        batch_decrypt(input_dir, output_dir, aes_key, xor_key)
        return

    dat_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else None
    if not os.path.exists(dat_file):
        print(f"File not found: {dat_file}")
        sys.exit(1)

    result_path, fmt = decrypt_dat_file(dat_file, out_file)
    if result_path:
        size = os.path.getsize(result_path)
        print(f"Success! Output: {result_path}")
        print(f"Format: {fmt}, Size: {size:,} bytes")
    else:
        with open(dat_file, 'rb') as f:
            head = f.read(6)
        if head == V2_MAGIC_FULL:
            print("Failed: V2 format requires AES key. Use --find-key to extract from WeChat process.")
        else:
            print("Failed: Could not detect XOR key or decrypt file.")


if __name__ == "__main__":
    main()
