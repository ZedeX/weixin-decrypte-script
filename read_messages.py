import sqlite3
import zstandard
import struct
import os
import sys


def decompress_message_content(data):
    if not data or len(data) < 2:
        return data
    if data[:4] == b'\x28\xb5\x2f\xfd':
        try:
            dctx = zstandard.ZstdDecompressor()
            return dctx.decompress(data, max_output_size=100 * 1024 * 1024)
        except Exception:
            return data
    return data


def try_decode_text(data):
    try:
        return data.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        pass
    try:
        return data.decode("gbk")
    except (UnicodeDecodeError, AttributeError):
        pass
    return data.hex()


def read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_protobuf_simple(data):
    fields = []
    pos = 0
    while pos < len(data):
        try:
            tag, pos = read_varint(data, pos)
        except Exception:
            break
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, pos = read_varint(data, pos)
            fields.append((field_number, "varint", value))
        elif wire_type == 1:
            value = data[pos:pos + 8]
            pos += 8
            fields.append((field_number, "64bit", value))
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            value = data[pos:pos + length]
            pos += length
            fields.append((field_number, "length-delimited", value))
        elif wire_type == 5:
            value = data[pos:pos + 4]
            pos += 4
            fields.append((field_number, "32bit", value))
        else:
            break
    return fields


def extract_messages(db_path, output_dir=None, decompress=True):
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return []

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    msg_tables = [t for t in tables if t.startswith("Msg_")]
    name2id_tables = [t for t in tables if t == "Name2Id"]

    all_messages = []

    for table in msg_tables:
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]

            if "message_content" not in columns:
                continue

            select_cols = "local_id, server_id"
            if "message_content" in columns:
                select_cols += ", message_content"
            if "packed_info_data" in columns:
                select_cols += ", packed_info_data"
            if "createTime" in columns:
                select_cols += ", createTime"
            if "message_type" in columns:
                select_cols += ", message_type"

            cursor.execute(f"SELECT {select_cols} FROM {table}")
            rows = cursor.fetchall()

            for row in rows:
                msg = {
                    "table": table,
                    "local_id": row[0],
                    "server_id": row[1],
                }

                col_idx = 2
                if "message_content" in columns:
                    content = row[col_idx]
                    if content and decompress:
                        if isinstance(content, str):
                            content = content.encode("utf-8", errors="replace")
                        if isinstance(content, bytes):
                            decompressed = decompress_message_content(content)
                            if isinstance(decompressed, bytes):
                                try:
                                    msg["message_content"] = decompressed.decode("utf-8")
                                except UnicodeDecodeError:
                                    msg["message_content"] = decompressed.hex()
                            else:
                                msg["message_content"] = str(decompressed)
                        else:
                            msg["message_content"] = str(content)
                    else:
                        msg["message_content"] = str(content) if content else None
                    col_idx += 1

                if "packed_info_data" in columns and col_idx < len(row):
                    packed = row[col_idx]
                    if packed and isinstance(packed, bytes):
                        msg["packed_info"] = parse_protobuf_simple(packed)
                    col_idx += 1

                if "createTime" in columns and col_idx < len(row):
                    msg["createTime"] = row[col_idx]
                    col_idx += 1

                if "message_type" in columns and col_idx < len(row):
                    msg["message_type"] = row[col_idx]
                    col_idx += 1

                all_messages.append(msg)

        except Exception as e:
            print(f"  Error reading table {table}: {e}")

    conn.close()
    return all_messages


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python read_messages.py <decrypted_db_path>")
        print("  python read_messages.py <decrypted_db_path> --output <output_dir>")
        print("  python read_messages.py --batch <xwechat_files_dir>")
        sys.exit(1)

    db_path = sys.argv[1]
    output_dir = None

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]

    if db_path == "--batch":
        base_dir = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\<USER>\Documents\xwechat_files"
        for root, dirs, files in os.walk(base_dir):
            for f in files:
                if f.endswith(".decrypted.db") and "message" in f:
                    db_path = os.path.join(root, f)
                    print(f"\nReading {db_path}...")
                    messages = extract_messages(db_path)
                    print(f"  Found {len(messages)} messages")
                    for msg in messages[:5]:
                        content = msg.get("message_content", "")
                        if content and len(content) > 100:
                            content = content[:100] + "..."
                        print(f"  [{msg.get('message_type', '?')}] {content}")
                    if len(messages) > 5:
                        print(f"  ... and {len(messages) - 5} more")
        return

    print(f"Reading messages from {db_path}...")
    messages = extract_messages(db_path)
    print(f"Found {len(messages)} messages\n")

    for msg in messages[:20]:
        content = msg.get("message_content", "")
        if content and len(content) > 200:
            content = content[:200] + "..."
        msg_type = msg.get("message_type", "?")
        create_time = msg.get("createTime", "?")
        print(f"[type={msg_type}, time={create_time}] {content}")

    if len(messages) > 20:
        print(f"\n... and {len(messages) - 20} more messages")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out_file = os.path.join(output_dir, os.path.basename(db_path).replace(".decrypted.db", "_messages.txt"))
        with open(out_file, "w", encoding="utf-8") as f:
            for msg in messages:
                content = msg.get("message_content", "")
                msg_type = msg.get("message_type", "?")
                create_time = msg.get("createTime", "?")
                f.write(f"[type={msg_type}, time={create_time}] {content}\n")
        print(f"\nMessages saved to {out_file}")


if __name__ == "__main__":
    main()
