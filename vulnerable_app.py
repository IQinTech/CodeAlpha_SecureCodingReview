#!/usr/bin/env python3
"""
vulnerable_app.py — CodeAlpha Task 3: Secure Coding Review
=============================================================
This is a DELIBERATELY INSECURE Flask application created for
educational purposes as part of a secure code review exercise.

⚠️  DO NOT deploy this application in any real environment.
     It contains intentional vulnerabilities for audit purposes.
"""

import sqlite3
import os
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 1: Hardcoded secret key (CWE-798)
# A static, weak secret key exposes session integrity
# ─────────────────────────────────────────────────────────────────
app.secret_key = "supersecret123"

DB_PATH = "users.db"

# ─────────────────────────────────────────────────────────────────
# Database bootstrap
# ─────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    # VULNERABILITY 2: Passwords stored as plain MD5 (CWE-916)
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','" +
              hashlib.md5(b"admin123").hexdigest() + "','admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','" +
              hashlib.md5(b"alice456").hexdigest() + "','user')")
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 3: SQL Injection (CWE-89)
# User input directly concatenated into SQL query
# ─────────────────────────────────────────────────────────────────

def get_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    # ⚠️ VULNERABLE: string concatenation — attacker can bypass auth
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + pwd_hash + "'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    return user


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 4: Reflected XSS (CWE-79)
# Unsanitised user input rendered directly into HTML
# ─────────────────────────────────────────────────────────────────

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  <!-- ⚠️ VULNERABLE: 'error' reflected without escaping -->
  <p style="color:red">{{ error }}</p>
  <form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
  </form>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_user(username, password)
        if user:
            session["user"] = user[1]
            session["role"] = user[3]
            return redirect("/dashboard")
        else:
            # ⚠️ VULNERABLE: username echoed back without sanitisation
            error = f"Invalid login for user: {username}"
    return render_template_string(LOGIN_TEMPLATE, error=error)


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 5: Broken Access Control (CWE-284)
# No server-side role check — client can manipulate session
# ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    # ⚠️ VULNERABLE: role read directly from session without verification
    role = session.get("role", "user")
    return f"<h1>Welcome {session['user']}!</h1><p>Role: {role}</p>" \
           f"<a href='/admin'>Admin Panel</a> | <a href='/ping'>Ping Tool</a> | " \
           f"<a href='/load'>Load Data</a> | <a href='/logout'>Logout</a>"


@app.route("/admin")
def admin():
    # ⚠️ VULNERABLE: only checks session role — attacker can set session['role']='admin'
    if session.get("role") != "admin":
        return "Access Denied", 403
    return "<h1>Admin Panel</h1><p>All user data exposed here.</p>"


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 6: OS Command Injection (CWE-78)
# User input passed directly to shell command
# ─────────────────────────────────────────────────────────────────

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return "<form>Host: <input name='host'><input type='submit' value='Ping'></form>"
    # ⚠️ VULNERABLE: attacker can append ; rm -rf / or similar
    result = subprocess.check_output("ping -c 1 " + host, shell=True,
                                     stderr=subprocess.STDOUT, timeout=5)
    return f"<pre>{result.decode()}</pre>"


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 7: Insecure Deserialization (CWE-502)
# Arbitrary pickle data accepted from user
# ─────────────────────────────────────────────────────────────────

@app.route("/load", methods=["GET", "POST"])
def load_data():
    if request.method == "POST":
        raw = request.files.get("data")
        if raw:
            # ⚠️ VULNERABLE: pickle.loads on untrusted data = RCE
            obj = pickle.loads(raw.read())
            return f"Loaded: {obj}"
    return """<form method=POST enctype=multipart/form-data>
              Upload pickle: <input type=file name=data>
              <input type=submit value=Load></form>"""


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 8: Sensitive data in URL / no HTTPS enforcement
# (CWE-319, CWE-598)
# ─────────────────────────────────────────────────────────────────

@app.route("/transfer")
def transfer():
    # ⚠️ VULNERABLE: token in GET param appears in server logs & browser history
    token = request.args.get("token", "")
    amount = request.args.get("amount", "0")
    return f"Transfer of ${amount} authorised with token {token}"


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─────────────────────────────────────────────────────────────────
# VULNERABILITY 9: Debug mode enabled in production (CWE-215)
# Exposes interactive debugger — full RCE possible
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # ⚠️ VULNERABLE: debug=True must NEVER be used in production
    app.run(debug=True, host="0.0.0.0", port=5000)
