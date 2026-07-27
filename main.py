import os
import io
import uuid
import sqlite3
import hashlib
import secrets
import subprocess
import time
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_file, redirect, url_for, session, render_template, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), "blossom.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "loaders")
ADMIN_PASS_HASH = os.environ.get("BLOSSOM_ADMIN_PASS", "blossom2026")

os.makedirs(UPLOAD_DIR, exist_ok=True)

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
            redeemed_by TEXT DEFAULT NULL,
            redeemed_hwid TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            redeemed_at TIMESTAMP DEFAULT NULL,
            loader_file TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            hwid TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            expiry_type TEXT NOT NULL,
            expiry_time INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    db.close()

def hash_key(key_text):
    secret = "BlossomKeys_2026_Seed"
    return hashlib.sha256((key_text + secret).encode()).hexdigest()

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

@app.route("/admin/reset-hwid/<username>", methods=["POST"])
@admin_required
def admin_reset_hwid(username):
    db = get_db()
    db.execute("UPDATE accounts SET hwid = '' WHERE username = ?", (username,))
    db.commit()
    db.close()
    return redirect(url_for("admin_panel"))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASS_HASH:
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
    generated_keys = session.pop("generated_keys", None)
    return render_template("admin.html", keys=keys, accounts=accounts, stats=stats)

@app.route("/admin/generate-key", methods=["POST"])
@admin_required
def admin_generate_key():
    expiry_type = request.form.get("type", "day")
    count = int(request.form.get("count", 1))
    count = max(1, min(count, 100))

    chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    db = get_db()
    generated = []

    for _ in range(count):
        for attempt in range(100):
            key_text = ""
            for i in range(25):
                if i > 0 and i % 5 == 0:
                    key_text += "-"
                key_text += secrets.choice(chars)
            key_hash_val = hash_key(key_text)
            try:
                db.execute("INSERT INTO keys (key_text, key_hash, expiry_type) VALUES (?, ?, ?)",
                           (key_text, key_hash_val, expiry_type))
                generated.append(key_text)
                break
            except sqlite3.IntegrityError:
                continue

    db.commit()
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

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
