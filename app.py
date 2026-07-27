import os
import re
import json
import sqlite3
import hashlib
import secrets
import threading
import time
import urllib.request
from functools import wraps
from flask import (
    Flask, request, jsonify, send_file,
    redirect, url_for, session, render_template, abort
)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "blossom.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "loaders")
OFFSETS_DIR = os.path.join(BASE_DIR, "data")
OFFSETS_FILE = os.path.join(OFFSETS_DIR, "offsets.h")
OFFSETS_HASH_FILE = os.path.join(OFFSETS_DIR, ".offsets_hash")

ADMIN_PASS = os.environ.get("BLOSSOM_ADMIN_PASS", "blossom2026")
KEY_SECRET = "BlossomKeys_2026_Seed"

CHEATOFFSETS_API = "https://www.cheatoffsets.com/api/games/roblox/current/offsets"
DUMPER_URL = "https://dumper.jonah.cool/offsets.h"
CHEATOFFSETS_MAP = {
    "FakeDataModelPointer": ("FakeDataModel", "Pointer"),
    "GameLoaded": ("DataModel", "GameLoaded"),
    "ScriptContextResume": ("ScriptContext", "Resume"),
    "ConnectionDisconnect": ("Instance", "ConnectionDisconnect"),
    "GetLuaStateForInstance": ("ScriptContext", "GetLuaState"),
    "PushInstance": ("ScriptContext", "PushInstance"),
    "FireLeftMouseClick": ("ProximityPrompt", "FireLeftMouseClick"),
    "FireMouseHoverEnter": ("ProximityPrompt", "FireMouseHoverEnter"),
    "FireMouseHoverLeave": ("ProximityPrompt", "FireMouseHoverLeave"),
    "FireTouchInterest": ("BasePart", "FireTouchInterest"),
    "HandleConnectionState": ("Instance", "HandleConnectionState"),
    "ProcessNetworkPacket": ("DataModel", "ProcessNetworkPacket"),
    "ReportNetworkError": ("DataModel", "ReportNetworkError"),
    "LuaVMLoad": ("LuaVM", "Load"),
    "luau_execute": ("LuaVM", "Execute"),
    "lua_namecallatom": ("LuaVM", "NamecallAtom"),
    "lua_newstate": ("LuaVM", "NewState"),
    "luaD_throw": ("LuaVM", "Throw"),
    "lua_yield": ("LuaVM", "Yield"),
    "spawn": ("TaskScheduler", "Spawn"),
    "defer": ("TaskScheduler", "Defer"),
    "delay": ("TaskScheduler", "Delay"),
    "wait": ("TaskScheduler", "Wait"),
}


def hash_key(key_text):
    return hashlib.sha256((key_text + KEY_SECRET).encode()).hexdigest()


def get_secret():
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_hex(32)
    open(path, "w").write(key)
    return key


app.secret_key = get_secret()
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OFFSETS_DIR, exist_ok=True)


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_text TEXT UNIQUE NOT NULL,
            key_hash TEXT NOT NULL,
            expiry_type TEXT NOT NULL DEFAULT 'day',
            status TEXT NOT NULL DEFAULT 'unused',
            redeemed_at TIMESTAMP DEFAULT NULL,
            loader_file TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            hwid TEXT NOT NULL DEFAULT '',
            key_hash TEXT NOT NULL,
            expiry_type TEXT NOT NULL,
            expiry_time INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    db.close()


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return redirect(url_for("redeem_page"))


@app.route("/redeem")
def redeem_page():
    return render_template("redeem.html")


@app.route("/api/validate", methods=["POST"])
def validate_key():
    data = request.get_json()
    if not data or "key" not in data:
        return jsonify({"valid": False, "message": "No key provided"}), 400

    key_text = data["key"].strip().upper()
    key_hash = hash_key(key_text)

    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key_hash = ?", (key_hash,)).fetchone()
    db.close()

    if not row:
        return jsonify({"valid": False, "message": "Invalid key"})
    if row["status"] == "redeemed":
        return jsonify({"valid": False, "message": "Key already used"})
    if not row["loader_file"] or not os.path.exists(os.path.join(UPLOAD_DIR, row["loader_file"])):
        return jsonify({"valid": False, "message": "Loader not available yet"})

    return jsonify({
        "valid": True,
        "message": "Key accepted",
        "expiry_type": row["expiry_type"],
        "download_url": url_for("download_loader", key_hash=key_hash)
    })


@app.route("/download/<key_hash>")
def download_loader(key_hash):
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key_hash = ?", (key_hash,)).fetchone()
    db.close()

    if not row:
        abort(404)
    if row["status"] == "redeemed":
        return "Key already used", 403
    if not row["loader_file"] or not os.path.exists(os.path.join(UPLOAD_DIR, row["loader_file"])):
        return "Loader not available", 404

    db = get_db()
    db.execute("UPDATE keys SET status = 'redeemed', redeemed_at = CURRENT_TIMESTAMP WHERE key_hash = ?", (key_hash,))
    db.commit()
    db.close()

    return send_file(
        os.path.join(UPLOAD_DIR, row["loader_file"]),
        as_attachment=True,
        download_name="BlossomLoader.exe"
    )


@app.route("/api/accounts", methods=["GET"])
def api_accounts():
    db = get_db()
    rows = db.execute("SELECT * FROM accounts ORDER BY created_at DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/accounts", methods=["DELETE"])
def api_delete_account():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "No username"}), 400
    db = get_db()
    db.execute("DELETE FROM accounts WHERE username = ?", (data["username"],))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/offsets", methods=["GET"])
def api_offsets_version():
    return jsonify({
        "version": _current_offsets_version,
        "last_check": int(_last_update_check),
        "download": "/api/offsets/download"
    })


@app.route("/api/offsets/download", methods=["GET"])
def api_offsets_download():
    if not os.path.exists(OFFSETS_FILE):
        return "Offsets not available yet", 404
    return send_file(OFFSETS_FILE, as_attachment=True, download_name="offsets.h")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASS:
            session["admin"] = True
            return redirect(url_for("admin_panel"))
        return render_template("admin_login.html", error="Wrong password")
    return render_template("admin_login.html", error=None)


@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    keys = db.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    accounts = db.execute("SELECT * FROM accounts ORDER BY created_at DESC").fetchall()
    db.close()
    stats = {
        "total_keys": len(keys),
        "unused": sum(1 for k in keys if k["status"] == "unused"),
        "redeemed": sum(1 for k in keys if k["status"] == "redeemed"),
        "total_accounts": len(accounts),
    }
    return render_template("admin.html", keys=keys, accounts=accounts, stats=stats)


@app.route("/admin/add-key", methods=["POST"])
@admin_required
def admin_add_key():
    key_text = request.form.get("key_text", "").strip().upper()
    expiry_type = request.form.get("type", "day")
    if not key_text:
        return redirect(url_for("admin_panel"))
    key_hash_val = hash_key(key_text)
    db = get_db()
    try:
        db.execute("INSERT INTO keys (key_text, key_hash, expiry_type) VALUES (?, ?, ?)",
                   (key_text, key_hash_val, expiry_type))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    db.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/upload-loader", methods=["POST"])
@admin_required
def admin_upload_loader():
    key_text = request.form.get("key_text", "").strip().upper()
    file = request.files.get("loader")
    if not key_text or not file:
        return "Missing key or file", 400

    key_hash_val = hash_key(key_text)
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key_hash = ?", (key_hash_val,)).fetchone()
    if not row:
        db.close()
        return "Key not found", 404

    filename = f"loader_{key_hash_val[:16]}.exe"
    file.save(os.path.join(UPLOAD_DIR, filename))
    db.execute("UPDATE keys SET loader_file = ? WHERE key_hash = ?", (filename, key_hash_val))
    db.commit()
    db.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete-key/<int:key_id>", methods=["POST"])
@admin_required
def admin_delete_key(key_id):
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE id = ?", (key_id,)).fetchone()
    if row and row["loader_file"]:
        path = os.path.join(UPLOAD_DIR, row["loader_file"])
        if os.path.exists(path):
            os.remove(path)
    db.execute("DELETE FROM keys WHERE id = ?", (key_id,))
    db.commit()
    db.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/reset-hwid/<username>", methods=["POST"])
@admin_required
def admin_reset_hwid(username):
    db = get_db()
    db.execute("UPDATE accounts SET hwid = '' WHERE username = ?", (username,))
    db.commit()
    db.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


_last_update_check = 0
_current_offsets_version = "unknown"


def _fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def _convert_dumper(raw):
    lines = raw.splitlines()
    out = []
    header_done = False
    version = "unknown"
    for line in lines:
        s = line.strip()
        if not header_done:
            if s.startswith("/*") or s.startswith("*") or s.startswith("*/") or s.startswith("#pragma") or s.startswith("#include") or s.startswith("//"):
                if s.startswith("namespace"):
                    header_done = True
                continue
            header_done = True
        if "namespace offsets" in line and "{" in line:
            line = line.replace("namespace offsets", "namespace Offsets")
        if "inline constexpr const char*" in line and "roblox_version" in line:
            idx = line.find('"')
            if idx != -1:
                end = line.rfind('"')
                version = line[idx + 1:end]
                line = f'    inline std::string ClientVersion = "{version}";'
            else:
                line = line.replace("inline constexpr const char* roblox_version", "inline std::string ClientVersion")
            out.append(line)
            continue
        out.append(line)
    return "\n".join(out), version


def _parse_offsets(content):
    result = {}
    current_ns = None
    for line in content.splitlines():
        s = line.strip()
        ns_match = re.match(r'namespace\s+(\w+)\s*\{', s)
        if ns_match:
            current_ns = ns_match.group(1)
            if current_ns not in result:
                result[current_ns] = {}
            continue
        if s.startswith("}") and current_ns:
            current_ns = None
            continue
        val_match = re.match(r'inline\s+(?:constexpr\s+)?(?:uintptr_t|std::string)\s+(\w+)\s*=\s*(.+?);', s)
        if val_match and current_ns:
            result[current_ns][val_match.group(1)] = val_match.group(2).strip()
    return result


def _build_offsets():
    try:
        dumper_raw = _fetch_text(DUMPER_URL)
        dumper_content, dumper_version = _convert_dumper(dumper_raw)
    except Exception:
        dumper_content, dumper_version = "", "unknown"
    try:
        cheat_data = _fetch_json(CHEATOFFSETS_API)
        cheat_version = cheat_data.get("version", "unknown")
        offsets_flat = cheat_data.get("offsets_flat", {})
        cheat_ns = {}
        for flat_name, (ns, name) in CHEATOFFSETS_MAP.items():
            if flat_name in offsets_flat:
                if ns not in cheat_ns:
                    cheat_ns[ns] = {}
                cheat_ns[ns][name] = offsets_flat[flat_name]
    except Exception:
        cheat_ns, cheat_version = {}, "unknown"
    existing = _parse_offsets(dumper_content)
    for ns, vals in cheat_ns.items():
        if ns not in existing:
            existing[ns] = {}
        for name, val in vals.items():
            if name not in existing[ns]:
                existing[ns][name] = val
    lines = [
        "#pragma once",
        "/* ===========================================================",
        "/*                    Auto-Dumped Offsets",
        "/*  Sources: cheatoffsets.com + dumper.jonah.cool",
        f"/*  Dumper Version: {dumper_version}",
        f"/*  Cheat Version:  {cheat_version}",
        "/* ===========================================================",
        "",
        "#include <cstdint>",
        "",
        "// clang-format off",
        "namespace Offsets {",
        f'    inline std::string ClientVersion = "{dumper_version}";',
    ]
    for ns in sorted(existing.keys()):
        if ns in ("offsets", "Offsets"):
            continue
        lines.append("")
        lines.append(f"    namespace {ns} {{")
        for name in sorted(existing[ns].keys()):
            val = existing[ns][name]
            if val.startswith('"'):
                lines.append(f'        inline std::string {name} = {val};')
            else:
                lines.append(f"        inline constexpr uintptr_t {name} = {val};")
        lines.append("    }")
    lines.append("")
    lines.append("} // namespace Offsets")
    lines.append("")
    return "\n".join(lines), dumper_version


def _check_and_update_offsets():
    global _last_update_check, _current_offsets_version
    try:
        content, version = _build_offsets()
        new_hash = hashlib.sha256(content.encode()).hexdigest()
        old_hash = ""
        if os.path.exists(OFFSETS_HASH_FILE):
            old_hash = open(OFFSETS_HASH_FILE).read().strip()
        if new_hash != old_hash:
            with open(OFFSETS_FILE, "w", encoding="utf-8") as f:
                f.write(content)
            with open(OFFSETS_HASH_FILE, "w") as f:
                f.write(new_hash)
            print(f"[offsets] Updated to {version}")
        _current_offsets_version = version
    except Exception as e:
        print(f"[offsets] Error: {e}")
        _current_offsets_version = "error"
    _last_update_check = time.time()


def _offset_loop():
    while True:
        time.sleep(1800)
        _check_and_update_offsets()


init_db()
_check_and_update_offsets()

if not os.environ.get("PORT"):
    threading.Thread(target=_offset_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
