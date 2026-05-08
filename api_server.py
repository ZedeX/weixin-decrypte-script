import os
import sys
import csv
import io
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from db_service import DBService
from decrypt_engine import ensure_decrypted, scan_keys_from_memory

app = Flask(__name__)
CORS(app)

db_service = None


def get_db() -> DBService:
    global db_service
    if db_service is None:
        return None
    return db_service


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/v1/chatlog", methods=["GET"])
def handle_chatlog():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    talker = request.args.get("talker", "")
    sender = request.args.get("sender", "")
    keyword = request.args.get("keyword", "")
    start_time = request.args.get("time", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    fmt = request.args.get("format", "json").lower()

    if not talker:
        return jsonify({"error": "talker parameter is required"}), 400

    if limit < 0:
        limit = 50
    if offset < 0:
        offset = 0

    messages, total = db.get_messages(
        talker=talker,
        start_time=start_time if start_time else None,
        end_time=None,
        sender=sender,
        keyword=keyword,
        limit=limit,
        offset=offset,
    )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"])
        for m in messages:
            writer.writerow([
                m.time, m.sender_name, m.sender,
                m.talker_name, m.talker, m.content,
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=chatlog_{talker}.csv"},
        )

    if fmt == "text":
        lines = []
        for m in messages:
            lines.append(m.to_plain_text(show_chatroom="," in talker))
        return Response("\n".join(lines), mimetype="text/plain; charset=utf-8")

    result = {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [m.to_dict() for m in messages],
    }
    return jsonify(result)


@app.route("/api/v1/contact", methods=["GET"])
def handle_contacts():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    fmt = request.args.get("format", "json").lower()

    result = db.get_contacts(keyword=keyword, limit=limit, offset=offset)

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["UserName", "Alias", "Remark", "NickName"])
        for c in result.items:
            writer.writerow([c.username, c.alias, c.remark, c.nick_name])
        return Response(output.getvalue(), mimetype="text/csv; charset=utf-8")

    if fmt == "text":
        lines = []
        for c in result.items:
            lines.append(f"{c.username},{c.alias},{c.remark},{c.nick_name}")
        return Response("UserName,Alias,Remark,NickName\n" + "\n".join(lines),
                        mimetype="text/plain; charset=utf-8")

    return jsonify(result.to_dict())


@app.route("/api/v1/chatroom", methods=["GET"])
def handle_chatrooms():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    fmt = request.args.get("format", "json").lower()

    result = db.get_chatrooms(keyword=keyword, limit=limit, offset=offset)

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Remark", "NickName", "Owner", "UserCount"])
        for cr in result.items:
            writer.writerow([cr.name, cr.remark, cr.nick_name, cr.owner, len(cr.users)])
        return Response(output.getvalue(), mimetype="text/csv; charset=utf-8")

    return jsonify(result.to_dict())


@app.route("/api/v1/session", methods=["GET"])
def handle_sessions():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    fmt = request.args.get("format", "json").lower()

    result = db.get_sessions(keyword=keyword, limit=limit, offset=offset)

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["UserName", "NickName", "Content", "Time"])
        for s in result.items:
            writer.writerow([s.username, s.nick_name, s.content, s.time])
        return Response(output.getvalue(), mimetype="text/csv; charset=utf-8")

    return jsonify(result.to_dict())


@app.route("/api/v1/search", methods=["GET"])
def handle_search():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    if not keyword:
        return jsonify({"error": "keyword parameter is required"}), 400

    messages, total = db.search_messages(keyword=keyword, limit=limit, offset=offset)
    return jsonify({"total": total, "items": messages})


def find_db_storage_dir(data_dir):
    if os.path.exists(os.path.join(data_dir, "db_storage")):
        return os.path.join(data_dir, "db_storage")

    for root, dirs, files in os.walk(data_dir):
        for d in dirs:
            candidate = os.path.join(root, d, "db_storage")
            if os.path.exists(candidate):
                return candidate

    return data_dir


def main():
    global db_service

    import argparse
    parser = argparse.ArgumentParser(description="WeChat Chat Record JSON API Server")
    parser.add_argument("data_dir", nargs="?", default=None,
                        help="Path to xwechat_files directory or db_storage directory")
    parser.add_argument("--key", default=None,
                        help="Database decryption key (hex), auto-scan from memory if not provided")
    parser.add_argument("--key-file", default=None,
                        help="File containing decryption keys (one hex key per line)")
    parser.add_argument("--no-decrypt", action="store_true",
                        help="Skip auto-decryption, use existing .decrypted.db files only")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5050, help="Port to bind (default: 5050)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    if args.data_dir is None:
        default_paths = [
            os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "xwechat_files"),
        ]
        for p in default_paths:
            if os.path.exists(p):
                args.data_dir = p
                break

        if args.data_dir is None:
            print("Error: No data directory specified and default path not found.")
            print("Usage: python api_server.py <data_dir> [--key <hex_key>] [--key-file <keys_file>]")
            print("       python api_server.py  (auto-detect xwechat_files)")
            sys.exit(1)

    if not os.path.exists(args.data_dir):
        print(f"Error: Directory not found: {args.data_dir}")
        sys.exit(1)

    db_storage = find_db_storage_dir(args.data_dir)
    print(f"[API] Data directory: {db_storage}")

    if not args.no_decrypt:
        keys_hex = None
        if args.key:
            keys_hex = [args.key]
            print(f"[API] Using provided key: {args.key[:16]}...")
        elif args.key_file:
            with open(args.key_file, "r") as f:
                keys_hex = [line.strip().split("\t")[-1] for line in f if line.strip()]
            print(f"[API] Loaded {len(keys_hex)} keys from {args.key_file}")
        else:
            print("[API] No key provided, attempting auto-scan from WeChat memory...")
            keys_hex = scan_keys_from_memory()

        print("[API] Checking and decrypting databases...")
        ensure_decrypted(db_storage, keys_hex)
    else:
        print("[API] Skipping decryption (--no-decrypt)")

    print(f"[API] Initializing database service...")
    db_service = DBService(db_storage)
    db_service.init()

    print(f"\n[API] Starting server on http://{args.host}:{args.port}")
    print(f"\nAPI Endpoints:")
    print(f"  GET /health                              - Health check")
    print(f"  GET /api/v1/chatlog?talker=<id>          - Query chat messages")
    print(f"  GET /api/v1/contact?keyword=<name>       - Query contacts")
    print(f"  GET /api/v1/chatroom?keyword=<name>      - Query chat rooms")
    print(f"  GET /api/v1/session?keyword=<name>       - Query sessions")
    print(f"  GET /api/v1/search?keyword=<text>        - Full-text search messages")
    print(f"\nQuery Parameters for /api/v1/chatlog:")
    print(f"  talker   - WeChat ID or chatroom ID (required, comma-separated)")
    print(f"  time     - Time range (e.g. '2025-01-01' or '2025-01-01,2025-06-01')")
    print(f"  sender   - Filter by sender")
    print(f"  keyword  - Filter by keyword")
    print(f"  limit    - Number of results (default: 50)")
    print(f"  offset   - Offset for pagination (default: 0)")
    print(f"  format   - Output format: json, csv, text (default: json)")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
