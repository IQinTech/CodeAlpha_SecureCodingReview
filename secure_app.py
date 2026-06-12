#!/usr/bin/env python3
"""
secure_app.py — CodeAlpha Task 3: Secure Coding Review
=======================================================
REMEDIATED version of vulnerable_app.py.
All identified vulnerabilities have been fixed following
OWASP best practices and secure coding standards.
"""

import sqlite3
import os
import subprocess
import secrets
import re
from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from functools import wraps

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────
# FIX 1: Cryptographically random secret key (fixes CWE-798)
# Generated once at startup; in production, load from env variable
# ─────────────────────────────────────────────────────────────────
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot access cookie
    SESSION_COOKIE_SECURE=True,     # HTTPS only
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF mitigation
    PERMANENT_SESSION_LIFETIME=1800  # 30-minute session timeout
)

DB_PATH = "secure_users.db"

# Allowlist for ping hostnames
VALID_HOST = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')


# ─────────────────────────────────────────────────────────────────
# Database bootstrap
# ─────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)""")
    # FIX 2: Passwords hashed with bcrypt via Werkzeug (fixes CWE-916)
    admin_pw = generate_password_hash(os.environ.get("ADMIN_PW", "ChangeMe!2024"))
    alice_pw = generate_password_hash(os.environ.get("ALICE_PW", "AliceStr0ng!"))
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin',?,'admin')", (admin_pw,))
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice',?,'user')",  (alice_pw,))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────
# FIX 3: Parameterised query prevents SQL Injection (fixes CWE-89)
# ─────────────────────────────────────────────────────────────────

def get_user(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Parameterised — user input never touches the SQL string
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row[2], password):
        return row
    return None


# ─────────────────────────────────────────────────────────────────
# Access-control decorator (fixes CWE-284)
# ─────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        # FIX 5: Role verified server-side from DB, not from session
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session["user_id"],))
        row = c.fetchone()
        conn.close()
        if not row or row[0] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────
# FIX 4: Output escaped — no XSS possible (fixes CWE-79)
# ─────────────────────────────────────────────────────────────────

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Secure Login</h2>
  <!-- Error is HTML-escaped via Jinja2 autoescape -->
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
  <form method="POST">
    Username: <input name="username" autocomplete="username"><br>
    Password: <input name="password" type="password" autocomplete="current-password"><br>
    <input type="submit" value="Login">
  </form>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username, password)
        if user:
            session.clear()                    # prevent session fixation
            session["user_id"] = user[0]       # store only the DB id
            session["username"] = user[1]
            return redirect("/dashboard")
        else:
            # Generic error — don't reveal whether username exists
            error = "Invalid username or password."
    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    username = escape(session.get("username", ""))
    return (f"<h1>Welcome {username}!</h1>"
            f"<a href='/admin'>Admin Panel</a> | "
            f"<a href='/ping'>Ping Tool</a> | "
            f"<a href='/logout'>Logout</a>")


@app.route("/admin")
@admin_required
def admin():
    return "<h1>Admin Panel</h1><p>Accessible only to verified admins.</p>"


# ─────────────────────────────────────────────────────────────────
# FIX 6: Command injection eliminated (fixes CWE-78)
# Allowlist validation + list-form subprocess call (no shell=True)
# ─────────────────────────────────────────────────────────────────

@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "")
    if not host:
        return "<form>Host: <input name='host'><input type='submit' value='Ping'></form>"
    if not VALID_HOST.match(host):
        return "Invalid host", 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],   # list form — no shell expansion
            capture_output=True, text=True, timeout=5
        )
        return f"<pre>{escape(result.stdout)}</pre>"
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504


# ─────────────────────────────────────────────────────────────────
# FIX 7: Insecure deserialization removed (fixes CWE-502)
# Accept only JSON; pickle upload endpoint removed entirely
# ─────────────────────────────────────────────────────────────────

import json

@app.route("/load", methods=["GET", "POST"])
@login_required
def load_data():
    if request.method == "POST":
        raw = request.files.get("data")
        if raw:
            try:
                obj = json.loads(raw.read().decode("utf-8"))   # safe — JSON only
                return f"Loaded keys: {list(obj.keys()) if isinstance(obj, dict) else type(obj).__name__}"
            except (json.JSONDecodeError, UnicodeDecodeError):
                return "Invalid JSON file", 400
    return """<form method=POST enctype=multipart/form-data>
              Upload JSON: <input type=file name=data>
              <input type=submit value=Load></form>"""


# ─────────────────────────────────────────────────────────────────
# FIX 8: Sensitive data moved to POST body, not URL (fixes CWE-598)
# ─────────────────────────────────────────────────────────────────

@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    data = request.get_json(force=True, silent=True) or {}
    token  = data.get("token", "")
    amount = data.get("amount", 0)
    if not token or not isinstance(amount, (int, float)):
        return {"error": "Invalid request"}, 400
    return {"status": "ok", "amount": amount}


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─────────────────────────────────────────────────────────────────
# FIX 9: Debug mode off; host restricted (fixes CWE-215)
# In production, use gunicorn/uWSGI — never app.run()
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
