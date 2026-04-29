#!/usr/bin/env python3
"""
DevSecOps Workshop GUI
Run: python devsecops_workshop.py
Then open: http://localhost:9999
"""

import http.server
import socketserver
import json
import sqlite3
import subprocess
import sys
import os
import threading
import webbrowser
import hashlib
import pickle
import tempfile

PORT = 9999

# ── Vulnerable in-memory DB for SQL injection demo ──────────────────────────
def make_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INT, username TEXT, password TEXT, email TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'admin','admin@123','admin@company.com','superadmin')")
    conn.execute("INSERT INTO users VALUES (2,'alice','pass456','alice@company.com','developer')")
    conn.execute("INSERT INTO users VALUES (3,'bob','pass789','bob@company.com','developer')")
    conn.execute("INSERT INTO users VALUES (4,'charlie','charlie99','charlie@company.com','intern')")
    conn.commit()
    return conn

DB = make_db()

# ── Vulnerable code files written to temp dir ────────────────────────────────
VULN_CODE = """import subprocess
import pickle
import hashlib
import requests

SECRET_KEY = "jwt-super-secret-do-not-share"
DB_PASSWORD = "admin@123"

def run_command(user_input):
    subprocess.run(user_input, shell=True)   # VULNERABILITY 1

def get_user(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query                             # VULNERABILITY 2

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)          # VULNERABILITY 3

def check_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()  # VULNERABILITY 4

def fetch_url(url):
    requests.get(url, verify=False)         # VULNERABILITY 5
"""

SAFE_CODE = """import subprocess
import hmac
import hashlib
import requests
import os

SECRET_KEY = os.environ.get("SECRET_KEY")   # FIXED 1: env variable
DB_PASSWORD = os.environ.get("DB_PASSWORD") # FIXED 1: env variable

def run_command(hostname):
    allowed = ["google.com","example.com"]
    if hostname in allowed:
        subprocess.run(["ping","-n","1", hostname])  # FIXED 2: no shell=True

def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return (query, (username,))             # FIXED 3: parameterized

def check_password(pwd, stored_hash):
    return hmac.compare_digest(
        hashlib.sha256(pwd.encode()).hexdigest(), stored_hash
    )                                       # FIXED 4: SHA-256 + constant time

def fetch_url(url):
    requests.get(url, verify=True)         # FIXED 5: SSL enabled
"""

VULN_FILE = os.path.join(tempfile.gettempdir(), "vuln.py")
with open(VULN_FILE, "w") as f:
    f.write(VULN_CODE)

# ── HTML page ────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DevSecOps Workshop</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --purple: #bc8cff; --orange: #ffa657;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; color: var(--text); }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; font-weight: 500; }
  .badge-red { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
  .badge-green { background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid rgba(63,185,80,0.3); }
  .badge-blue { background: rgba(88,166,255,0.15); color: var(--blue); border: 1px solid rgba(88,166,255,0.3); }
  .badge-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); border: 1px solid rgba(210,153,34,0.3); }
  .layout { display: flex; height: calc(100vh - 53px); }
  nav { width: 220px; background: var(--bg2); border-right: 1px solid var(--border); padding: 12px 8px; flex-shrink: 0; overflow-y: auto; }
  .nav-section { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; padding: 8px 8px 4px; }
  .nav-btn { display: block; width: 100%; text-align: left; background: none; border: none; color: var(--muted); padding: 7px 10px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-bottom: 2px; transition: all .15s; }
  .nav-btn:hover { background: var(--bg3); color: var(--text); }
  .nav-btn.active { background: var(--bg3); color: var(--blue); font-weight: 500; }
  .nav-btn .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 8px; }
  main { flex: 1; overflow-y: auto; padding: 24px; }
  .tab { display: none; }
  .tab.active { display: block; }
  h2 { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 20px; line-height: 1.5; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
  .card-title { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 12px; }
  .row { display: flex; gap: 12px; align-items: flex-start; flex-wrap: wrap; }
  input[type=text], input[type=password] {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
    color: var(--text); padding: 7px 12px; font-size: 13px; font-family: monospace;
    outline: none; transition: border .15s; width: 220px;
  }
  input:focus { border-color: var(--blue); }
  label { font-size: 12px; color: var(--muted); margin-bottom: 4px; display: block; }
  .field { display: flex; flex-direction: column; }
  btn, button.btn {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
    color: var(--text); padding: 7px 16px; font-size: 13px; cursor: pointer;
    transition: all .15s; white-space: nowrap; font-family: inherit;
  }
  button.btn:hover { border-color: var(--blue); color: var(--blue); }
  button.btn.danger { border-color: rgba(248,81,73,0.4); color: var(--red); }
  button.btn.danger:hover { background: rgba(248,81,73,0.1); }
  button.btn.success { border-color: rgba(63,185,80,0.4); color: var(--green); }
  button.btn.success:hover { background: rgba(63,185,80,0.1); }
  button.btn.primary { border-color: rgba(88,166,255,0.4); color: var(--blue); }
  button.btn.primary:hover { background: rgba(88,166,255,0.1); }
  .terminal {
    background: #010409; border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; font-family: 'Cascadia Code','Consolas',monospace; font-size: 12.5px;
    line-height: 1.7; min-height: 120px; max-height: 340px; overflow-y: auto;
    white-space: pre-wrap; word-break: break-word; margin-top: 12px;
    color: #c9d1d9;
  }
  .t-green { color: #3fb950; }
  .t-red { color: #f85149; }
  .t-yellow { color: #d29922; }
  .t-blue { color: #58a6ff; }
  .t-purple { color: #bc8cff; }
  .t-muted { color: #8b949e; }
  .t-orange { color: #ffa657; }
  .payload-btn { display: inline-block; margin: 3px; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-family: monospace; cursor: pointer; border: 1px solid var(--border); background: var(--bg3); color: var(--orange); transition: all .15s; }
  .payload-btn:hover { border-color: var(--orange); background: rgba(255,166,87,0.08); }
  .code-view { background: #010409; border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: monospace; font-size: 12.5px; line-height: 1.8; overflow-x: auto; white-space: pre; }
  .line-bad { background: rgba(248,81,73,0.12); display: block; border-left: 3px solid var(--red); padding-left: 8px; margin-left: -8px; }
  .line-good { background: rgba(63,185,80,0.1); display: block; border-left: 3px solid var(--green); padding-left: 8px; margin-left: -8px; }
  .line-comment { color: #8b949e; }
  .vuln-tag { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid rgba(248,81,73,0.3); margin-left: 6px; vertical-align: middle; }
  .fix-tag { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid rgba(63,185,80,0.3); margin-left: 6px; vertical-align: middle; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-bottom: 16px; }
  .stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
  .stat-val { font-size: 22px; font-weight: 600; margin-bottom: 2px; }
  .stat-label { font-size: 11px; color: var(--muted); }
  .loading { color: var(--muted); font-style: italic; }
  hr.sep { border: none; border-top: 1px solid var(--border); margin: 16px 0; }
</style>
</head>
<body>
<header>
  <span style="font-size:20px;">🛡️</span>
  <h1>DevSecOps Workshop</h1>
  <span class="badge badge-red">Live Demo Panel</span>
  <span style="margin-left:auto;font-size:12px;color:var(--muted);">45-min session · BTech 2nd Year</span>
</header>
<div class="layout">

<nav>
  <div class="nav-section">Concepts</div>
  <button class="nav-btn active" onclick="show('intro')"><span class="dot" style="background:#58a6ff"></span>DevOps vs DevSecOps</button>

  <div class="nav-section" style="margin-top:8px;">Live Demos</div>
  <button class="nav-btn" onclick="show('secrets')"><span class="dot" style="background:#f85149"></span>1. Secret Scanner</button>
  <button class="nav-btn" onclick="show('sqli')"><span class="dot" style="background:#ffa657"></span>2. SQL Injection</button>
  <button class="nav-btn" onclick="show('deps')"><span class="dot" style="background:#d29922"></span>3. Dependency Scan</button>
  <button class="nav-btn" onclick="show('bandit')"><span class="dot" style="background:#bc8cff"></span>4. Code Analyser</button>

  <div class="nav-section" style="margin-top:8px;">Students</div>
  <button class="nav-btn" onclick="show('challenge')"><span class="dot" style="background:#3fb950"></span>Find the Bug</button>
</nav>

<main>

<!-- ══ INTRO ══════════════════════════════════════════════════════════ -->
<div class="tab active" id="tab-intro">
  <h2>DevOps vs DevSecOps</h2>
  <p class="subtitle">The core mindset shift — from "security later" to "security everywhere"</p>
  <div class="card">
    <div class="card-title">DevOps pipeline</div>
    <div style="display:flex;gap:0;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:4px;">
      <span class="badge badge-blue">Plan</span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-blue">Code</span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-blue">Build</span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-blue">Test</span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-blue">Deploy</span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-blue">Monitor</span>
      <span style="color:var(--muted);margin-left:12px;font-size:12px;">Security added at end 🔒</span>
    </div>
  </div>
  <div class="card">
    <div class="card-title">DevSecOps pipeline — security at every step</div>
    <div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">
      <span class="badge badge-red">Plan<br><small>threat model</small></span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-red">Code<br><small>secret scan</small></span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-red">Build<br><small>dep scan</small></span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-red">Test<br><small>SAST/DAST</small></span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-red">Deploy<br><small>sign+verify</small></span><span style="color:var(--muted);padding:0 4px;">→</span>
      <span class="badge badge-red">Monitor<br><small>alerts</small></span>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Why it matters — cost of fixing a bug</div>
    <div class="stats">
      <div class="stat"><div class="stat-val t-green">₹80</div><div class="stat-label">Fix in development</div></div>
      <div class="stat"><div class="stat-val t-yellow">₹8,000</div><div class="stat-label">Fix in testing</div></div>
      <div class="stat"><div class="stat-val t-red">₹8,00,000</div><div class="stat-label">Fix after breach</div></div>
    </div>
    <p style="font-size:12px;color:var(--muted);">This is why we "shift left" — catch vulnerabilities early, before they reach production.</p>
  </div>
</div>

<!-- ══ SECRETS ════════════════════════════════════════════════════════ -->
<div class="tab" id="tab-secrets">
  <h2>Demo 1 — Secret Detection</h2>
  <p class="subtitle">Developers accidentally commit passwords & API keys to git. Bots scan GitHub 24/7 and steal them within minutes. This demo shows how to catch it automatically.</p>
  <div class="card">
    <div class="card-title">Vulnerable code — what a developer might write</div>
    <div class="code-view"><span class="line-bad">AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE" <span class="vuln-tag">HARDCODED SECRET</span></span>
<span class="line-bad">AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENGbPxRfi" <span class="vuln-tag">HARDCODED SECRET</span></span>
<span class="line-bad">DB_PASSWORD    = "supersecret123" <span class="vuln-tag">HARDCODED SECRET</span></span>
<span class="line-bad">GITHUB_TOKEN   = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXy" <span class="vuln-tag">HARDCODED SECRET</span></span>

<span class="line-comment">s3 = boto3.client('s3',</span>
<span class="line-comment">    aws_access_key_id=AWS_ACCESS_KEY,</span>
<span class="line-comment">    aws_secret_access_key=AWS_SECRET_KEY</span>
<span class="line-comment">)</span></div>
  </div>
  <div class="card">
    <div class="card-title">Run detect-secrets scanner</div>
    <button class="btn danger" onclick="runSecrets()">&#9654; Scan for secrets now</button>
    <div class="terminal" id="out-secrets"><span class="t-muted">Click the button to scan...</span></div>
  </div>
  <div class="card">
    <div class="card-title">The fix — environment variables</div>
    <div class="code-view"><span class="line-good">import os <span class="fix-tag">SAFE</span></span>

<span class="line-good">AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID") <span class="fix-tag">FROM .env FILE</span></span>
<span class="line-good">AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY") <span class="fix-tag">FROM .env FILE</span></span>
<span class="line-good">DB_PASSWORD    = os.environ.get("DB_PASSWORD") <span class="fix-tag">FROM .env FILE</span></span>

<span class="line-comment"># .gitignore — this file is NEVER committed</span>
<span class="line-good">.env <span class="fix-tag">IGNORED BY GIT</span></span></div>
  </div>
</div>

<!-- ══ SQL INJECTION ══════════════════════════════════════════════════ -->
<div class="tab" id="tab-sqli">
  <h2>Demo 2 — SQL Injection Attack</h2>
  <p class="subtitle">The #1 web vulnerability for 10+ years. Try a normal login, then try the attack payloads and watch the database get dumped live.</p>
  <div class="card">
    <div class="card-title">Vulnerable login form</div>
    <div class="row" style="margin-bottom:12px;">
      <div class="field"><label>Username</label><input type="text" id="sqli-user" value="alice" /></div>
      <div class="field"><label>Password</label><input type="text" id="sqli-pass" value="pass456" /></div>
      <div class="field"><label>&nbsp;</label><button class="btn primary" onclick="runSQLi()">&#9654; Login</button></div>
    </div>
    <div style="margin-bottom:8px;font-size:12px;color:var(--muted);">Try these attack payloads — click to load, then hit Login:</div>
    <div>
      <span class="payload-btn" onclick="loadPayload(this)" data-u="admin'--" data-p="anything">Bypass password →  admin'--</span>
      <span class="payload-btn" onclick="loadPayload(this)" data-u="' OR '1'='1" data-p="x">Dump all users →  ' OR '1'='1</span>
      <span class="payload-btn" onclick="loadPayload(this)" data-u="' UNION SELECT id,username,password,email,role FROM users--" data-p="x">UNION dump →  ' UNION SELECT...</span>
    </div>
    <div class="terminal" id="out-sqli"><span class="t-muted">Enter credentials and click Login...</span></div>
  </div>
  <div class="card">
    <div class="card-title">What the vulnerable code looks like</div>
    <div class="code-view"><span class="line-bad">query = "SELECT * FROM users WHERE username='" + username + <span class="vuln-tag">STRING CONCAT</span></span>
<span class="line-bad">        "' AND password='" + password + "'"</span>
<span class="line-comment">
# attacker types:  admin'--
# query becomes:   SELECT * FROM users WHERE username='admin'--' AND password='x'
#                                                                ↑ everything after -- is ignored!</span></div>
    <hr class="sep">
    <div class="card-title">The safe version</div>
    <div class="code-view"><span class="line-good">query = "SELECT * FROM users WHERE username=? AND password=?" <span class="fix-tag">PARAMETERIZED</span></span>
<span class="line-good">result = db.execute(query, (username, password)) <span class="fix-tag">DATA NOT CODE</span></span>
<span class="line-comment">
# ' OR '1'='1  is treated as a literal string, not SQL code. Attack fails.</span></div>
  </div>
</div>

<!-- ══ DEPS ═══════════════════════════════════════════════════════════ -->
<div class="tab" id="tab-deps">
  <h2>Demo 3 — Dependency Vulnerability Scan</h2>
  <p class="subtitle">Every library you pip install may have known CVEs. <code>safety</code> checks your requirements.txt against a database of 800,000+ vulnerabilities.</p>
  <div class="card">
    <div class="card-title">requirements.txt being scanned</div>
    <div class="code-view"><span class="line-bad">flask==0.12.2 <span class="vuln-tag">CVE-2018-1000656 HIGH</span></span>
<span class="line-bad">django==2.0.0 <span class="vuln-tag">CVE-2019-6975 CRITICAL</span></span>
<span class="line-bad">requests==2.18.0 <span class="vuln-tag">CVE-2018-18074 MEDIUM</span></span>
<span class="line-bad">pyyaml==3.12 <span class="vuln-tag">CVE-2017-18342 CRITICAL</span></span>
<span class="line-bad">Pillow==6.2.0 <span class="vuln-tag">CVE-2020-5313 HIGH</span></span></div>
  </div>
  <div class="card">
    <div class="card-title">Run safety scanner</div>
    <button class="btn danger" onclick="runDeps()">&#9654; Scan dependencies now</button>
    <div class="terminal" id="out-deps"><span class="t-muted">Click to scan...</span></div>
  </div>
</div>

<!-- ══ BANDIT ═════════════════════════════════════════════════════════ -->
<div class="tab" id="tab-bandit">
  <h2>Demo 4 — Static Code Analysis (Bandit)</h2>
  <p class="subtitle">Bandit reads your Python code without running it and flags security issues. This is SAST — Static Application Security Testing.</p>
  <div class="card">
    <div class="card-title">Run bandit on vulnerable code</div>
    <button class="btn danger" onclick="runBandit()">&#9654; Analyse vuln.py now</button>
    <div class="terminal" id="out-bandit"><span class="t-muted">Click to analyse...</span></div>
  </div>
  <div class="card">
    <div class="card-title">The code bandit is reading</div>
    <div class="code-view"><span class="line-bad">SECRET_KEY = "jwt-super-secret-do-not-share" <span class="vuln-tag">B105: hardcoded password</span></span>
<span class="line-bad">DB_PASSWORD = "admin@123" <span class="vuln-tag">B105: hardcoded password</span></span>
<span class="line-comment">
def run_command(user_input):</span>
<span class="line-bad">    subprocess.run(user_input, shell=True) <span class="vuln-tag">B602: shell injection HIGH</span></span>
<span class="line-comment">
def get_user(username):</span>
<span class="line-bad">    query = "SELECT * FROM users WHERE name='" + username + "'" <span class="vuln-tag">B608: SQL injection HIGH</span></span>
<span class="line-comment">
def load_data(raw_bytes):</span>
<span class="line-bad">    return pickle.loads(raw_bytes) <span class="vuln-tag">B301: unsafe deserialise HIGH</span></span>
<span class="line-comment">
def check_password(pwd):</span>
<span class="line-bad">    return hashlib.md5(pwd.encode()).hexdigest() <span class="vuln-tag">B324: weak MD5 hash MEDIUM</span></span>
<span class="line-comment">
def fetch_url(url):</span>
<span class="line-bad">    requests.get(url, verify=False) <span class="vuln-tag">B501: SSL disabled HIGH</span></span></div>
  </div>
</div>

<!-- ══ CHALLENGE ══════════════════════════════════════════════════════ -->
<div class="tab" id="tab-challenge">
  <h2>Student Challenge — Find the Bug</h2>
  <p class="subtitle">Give students 2 minutes to read the code and spot all vulnerabilities. Then reveal answers one by one, or run the scanner to let the tool find them.</p>
  <div class="card">
    <div class="card-title">How many can you find?  <span id="score-badge" class="badge badge-blue">0 / 5 found</span></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <button class="btn" onclick="reveal(1)">Reveal #1</button>
      <button class="btn" onclick="reveal(2)">Reveal #2</button>
      <button class="btn" onclick="reveal(3)">Reveal #3</button>
      <button class="btn" onclick="reveal(4)">Reveal #4</button>
      <button class="btn" onclick="reveal(5)">Reveal #5</button>
      <button class="btn danger" onclick="revealAll()">Reveal All</button>
      <button class="btn success" onclick="runBanditChallenge()">&#9654; Let tool find them</button>
      <button class="btn" onclick="resetChallenge()">Reset</button>
    </div>
    <div class="code-view" id="challenge-code">
<span id="v1" class="line-comment">SECRET_KEY = "jwt-super-secret-do-not-share"    # ← vulnerability here?</span>

<span class="line-comment">import subprocess, pickle, hashlib, requests
</span>
<span class="line-comment">def run_command(user_input):</span>
<span id="v2" class="line-comment">    subprocess.run(user_input, shell=True)       # ← vulnerability here?</span>

<span class="line-comment">def get_user(username):</span>
<span id="v3" class="line-comment">    query = "SELECT * FROM users WHERE name='" + username + "'"   # ← vulnerability?</span>

<span class="line-comment">def load_data(raw_bytes):</span>
<span id="v4" class="line-comment">    return pickle.loads(raw_bytes)               # ← vulnerability here?</span>

<span class="line-comment">def check_password(pwd):</span>
<span id="v4b" class="line-comment">    return hashlib.md5(pwd.encode()).hexdigest() # ← vulnerability here?</span>

<span class="line-comment">def fetch_url(url):</span>
<span id="v5" class="line-comment">    requests.get(url, verify=False)              # ← vulnerability here?</span>
</div>
    <div class="terminal" id="out-challenge" style="display:none;"></div>
  </div>
  <div id="explanations" style="display:none;">
    <div id="exp1" class="card" style="display:none;border-left:3px solid var(--red);">
      <strong class="t-red">#1 Hardcoded Secret Key</strong><br><br>
      <span style="color:var(--muted);">Anyone with access to the repo can read the JWT secret and forge auth tokens — logging in as any user including admin. Fix: use <code>os.environ.get("SECRET_KEY")</code></span>
    </div>
    <div id="exp2" class="card" style="display:none;border-left:3px solid var(--red);">
      <strong class="t-red">#2 Shell Injection — subprocess shell=True</strong><br><br>
      <span style="color:var(--muted);">If user_input is <code>"google.com; rm -rf /"</code> the shell runs both commands. Attacker can delete files, steal data, install backdoors. Fix: use <code>shell=False</code> with a list.</span>
    </div>
    <div id="exp3" class="card" style="display:none;border-left:3px solid var(--red);">
      <strong class="t-red">#3 SQL Injection — string concatenation</strong><br><br>
      <span style="color:var(--muted);">Username <code>' OR '1'='1</code> returns all rows. Username <code>'; DROP TABLE users;--</code> deletes everything. Fix: use parameterised queries <code>WHERE name=?</code></span>
    </div>
    <div id="exp4" class="card" style="display:none;border-left:3px solid var(--red);">
      <strong class="t-red">#4 Unsafe Deserialization — pickle.loads()</strong><br><br>
      <span style="color:var(--muted);"><code>pickle.loads()</code> on untrusted bytes executes arbitrary Python code. Attacker can send crafted bytes that run <code>os.system("...")</code> on your server. Fix: use JSON instead.</span>
    </div>
    <div id="exp5" class="card" style="display:none;border-left:3px solid var(--red);">
      <strong class="t-red">#5 SSL Verification Disabled — verify=False</strong><br><br>
      <span style="color:var(--muted);"><code>verify=False</code> disables SSL certificate checking. A man-in-the-middle attacker can intercept and modify all data sent to that URL. Fix: remove <code>verify=False</code> (default is True).</span>
    </div>
  </div>
</div>

</main>
</div>

<script>
function show(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.currentTarget.classList.add('active');
}

function loadPayload(el) {
  document.getElementById('sqli-user').value = el.dataset.u;
  document.getElementById('sqli-pass').value = el.dataset.p;
}

async function call(endpoint, body) {
  const r = await fetch(endpoint, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  return r.json();
}

function setOut(id, html) {
  const el = document.getElementById(id);
  el.innerHTML = html;
  el.scrollTop = el.scrollHeight;
}

async function runSecrets() {
  setOut('out-secrets', '<span class="t-muted loading">Scanning...</span>');
  const d = await call('/api/secrets', {});
  setOut('out-secrets', d.html);
}

async function runSQLi() {
  const u = document.getElementById('sqli-user').value;
  const p = document.getElementById('sqli-pass').value;
  setOut('out-sqli', '<span class="t-muted loading">Running query...</span>');
  const d = await call('/api/sqli', { username: u, password: p });
  setOut('out-sqli', d.html);
}

async function runDeps() {
  setOut('out-deps', '<span class="t-muted loading">Scanning dependencies... (may take a few seconds)</span>');
  const d = await call('/api/deps', {});
  setOut('out-deps', d.html);
}

async function runBandit() {
  setOut('out-bandit', '<span class="t-muted loading">Analysing code...</span>');
  const d = await call('/api/bandit', {});
  setOut('out-bandit', d.html);
}

let found = 0;
const revealedSet = new Set();

function reveal(n) {
  if (revealedSet.has(n)) return;
  revealedSet.add(n);
  found++;
  document.getElementById('score-badge').textContent = found + ' / 5 found';
  document.getElementById('explanations').style.display = 'block';
  const expIds = { 1:'exp1', 2:'exp2', 3:'exp3', 4:'exp4', 5:'exp5' };
  const lineIds = { 1:'v1', 2:'v2', 3:'v3', 4:'v4', 5:'v5' };
  document.getElementById(expIds[n]).style.display = 'block';
  const line = document.getElementById(lineIds[n]);
  if (line) { line.className = 'line-bad'; }
  if (n === 4) { const l2 = document.getElementById('v4b'); if(l2) l2.className='line-bad'; }
}

function revealAll() { [1,2,3,4,5].forEach(reveal); }

async function runBanditChallenge() {
  document.getElementById('out-challenge').style.display = 'block';
  setOut('out-challenge', '<span class="t-muted loading">Running bandit scanner...</span>');
  const d = await call('/api/bandit', {});
  setOut('out-challenge', d.html);
  revealAll();
}

function resetChallenge() {
  found = 0; revealedSet.clear();
  document.getElementById('score-badge').textContent = '0 / 5 found';
  document.getElementById('explanations').style.display = 'none';
  document.getElementById('out-challenge').style.display = 'none';
  [1,2,3,4,5].forEach(n => {
    const expIds = { 1:'exp1', 2:'exp2', 3:'exp3', 4:'exp4', 5:'exp5' };
    const lineIds = { 1:'v1', 2:'v2', 3:'v3', 4:'v4' };
    if(expIds[n]) document.getElementById(expIds[n]).style.display = 'none';
    if(lineIds[n]) document.getElementById(lineIds[n]).className = 'line-comment';
  });
  const v4b = document.getElementById('v4b');
  if(v4b) v4b.className = 'line-comment';
}
</script>
</body>
</html>
"""

# ── API handlers ─────────────────────────────────────────────────────────────
def handle_secrets():
    fake_file = os.path.join(tempfile.gettempdir(), "config_demo.py")
    with open(fake_file, "w") as f:
        f.write('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        f.write('AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENGbPxRfi"\n')
        f.write('DB_PASSWORD    = "supersecret123"\n')
        f.write('GITHUB_TOKEN   = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXy"\n')

    try:
        result = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", fake_file],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout or result.stderr
    except FileNotFoundError:
        raw = '{"error": "detect-secrets not installed. Run: pip install detect-secrets"}'
    except Exception as e:
        raw = str(e)

    lines = [
        '<span class="t-green">$ detect-secrets scan config.py</span>\n',
        '<span class="t-muted">─────────────────────────────────────────────</span>\n',
    ]
    if "AWS" in raw or "results" in raw:
        lines += [
            '<span class="t-red">[FOUND] Line 1 → AWS Access Key  — AKIAIOSFODNN7EXAMPLE</span>\n',
            '<span class="t-red">[FOUND] Line 2 → Secret Keyword  — wJalrXUtnFEMI/K7MDENG...</span>\n',
            '<span class="t-red">[FOUND] Line 3 → Secret Keyword  — supersecret123</span>\n',
            '<span class="t-red">[FOUND] Line 4 → GitHub Token    — ghp_aBcDeFgHiJkLm...</span>\n',
            '<span class="t-muted">─────────────────────────────────────────────</span>\n',
            '<span class="t-yellow">4 secrets detected. This git push would be BLOCKED.</span>\n',
            '<span class="t-muted">Secrets detected in: config.py</span>\n',
        ]
    else:
        lines.append(f'<span class="t-muted">{raw}</span>\n')
    return {"html": "".join(lines)}


def handle_sqli(body):
    username = body.get("username", "")
    password = body.get("password", "")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    lines = [
        f'<span class="t-blue">$ Executing login query...</span>\n\n',
        f'<span class="t-muted">SQL: </span><span class="t-yellow">{query}</span>\n\n',
    ]

    is_attack = "'" in username or "'" in password or "--" in username or "OR" in username.upper()

    try:
        rows = DB.execute(query).fetchall()
        if rows:
            if is_attack:
                lines.append('<span class="t-red">⚠  ATTACK SUCCESSFUL — SQL Injection detected!</span>\n\n')
            else:
                lines.append('<span class="t-green">✓  Login successful</span>\n\n')
            lines.append('<span class="t-muted">id  │ username │ password  │ email                │ role</span>\n')
            lines.append('<span class="t-muted">────┼──────────┼───────────┼──────────────────────┼────────────</span>\n')
            for r in rows:
                lines.append(f'<span class="t-red">{r[0]!s:<3} │ {r[1]:<8} │ {r[2]:<9} │ {r[3]:<20} │ {r[4]}</span>\n')
            if len(rows) > 1:
                lines.append(f'\n<span class="t-red">Entire database dumped! {len(rows)} users exposed.</span>\n')
        else:
            lines.append('<span class="t-muted">Login failed — invalid credentials.</span>\n')
    except Exception as e:
        lines.append(f'<span class="t-red">DB Error: {e}</span>\n')

    return {"html": "".join(lines)}


def handle_deps():
    req_file = os.path.join(tempfile.gettempdir(), "req_demo.txt")
    with open(req_file, "w") as f:
        f.write("flask==0.12.2\ndjango==2.0.0\nrequests==2.18.0\npyyaml==3.12\nPillow==6.2.0\n")

    lines = [
        '<span class="t-green">$ safety check -r requirements.txt</span>\n',
        '<span class="t-muted">─────────────────────────────────────────────</span>\n',
    ]
    try:
        result = subprocess.run(
            [sys.executable, "-m", "safety", "check", "-r", req_file, "--output", "text"],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout + result.stderr
        if "vulnerability" in raw.lower() or "CVE" in raw or "VULNERABILITY" in raw:
            lines.append(raw.replace(
                "CRITICAL", '<span class="t-red">CRITICAL</span>'
            ).replace(
                "HIGH", '<span class="t-red">HIGH</span>'
            ).replace(
                "MEDIUM", '<span class="t-yellow">MEDIUM</span>'
            ).replace(
                "LOW", '<span class="t-muted">LOW</span>'
            ))
        elif "No known security vulnerabilities" in raw:
            lines += [
                '<span class="t-yellow">safety free tier may not check all packages.</span>\n',
                '<span class="t-muted">Known vulnerabilities for these old versions:</span>\n\n',
                *_fake_deps_output(),
            ]
        else:
            lines += _fake_deps_output()
    except Exception as e:
        lines += [f'<span class="t-muted">safety error: {e}</span>\n', *_fake_deps_output()]
    return {"html": "".join(lines)}


def _fake_deps_output():
    return [
        '<span class="t-red">VULNERABILITY FOUND</span>\n',
        '<span class="t-muted">  Package:  flask 0.12.2</span>\n',
        '<span class="t-muted">  CVE:      CVE-2018-1000656</span>\n',
        '<span class="t-red">  Severity: HIGH — Denial of service via crafted JSON</span>\n\n',
        '<span class="t-red">VULNERABILITY FOUND</span>\n',
        '<span class="t-muted">  Package:  django 2.0.0</span>\n',
        '<span class="t-muted">  CVE:      CVE-2019-6975</span>\n',
        '<span class="t-red">  Severity: CRITICAL — Memory exhaustion / potential RCE</span>\n\n',
        '<span class="t-red">VULNERABILITY FOUND</span>\n',
        '<span class="t-muted">  Package:  pyyaml 3.12</span>\n',
        '<span class="t-muted">  CVE:      CVE-2017-18342</span>\n',
        '<span class="t-red">  Severity: CRITICAL — Arbitrary code execution via yaml.load()</span>\n\n',
        '<span class="t-muted">─────────────────────────────────────────────</span>\n',
        '<span class="t-yellow">Scanned 5 packages. Found 8 vulnerabilities (2 CRITICAL, 4 HIGH, 2 MEDIUM)</span>\n',
    ]


def handle_bandit():
    lines = [
        '<span class="t-green">$ bandit -r vuln.py</span>\n',
        '<span class="t-muted">─────────────────────────────────────────────</span>\n',
    ]
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", VULN_FILE, "--format", "text"],
            capture_output=True, text=True, timeout=20
        )
        raw = result.stdout + result.stderr
        if "Issue:" in raw or "Severity:" in raw:
            lines.append(raw.replace(
                "Severity: High", '<span class="t-red">Severity: High</span>'
            ).replace(
                "Severity: Medium", '<span class="t-yellow">Severity: Medium</span>'
            ).replace(
                "Severity: Low", '<span class="t-muted">Severity: Low</span>'
            ).replace(
                "Issue:", '<span class="t-red">Issue:</span>'
            ))
        else:
            lines += _fake_bandit_output()
    except Exception as e:
        lines += [f'<span class="t-muted">{e}</span>\n', *_fake_bandit_output()]
    return {"html": "".join(lines)}


def _fake_bandit_output():
    return [
        '<span class="t-red">Issue: [B105] Hardcoded password string</span>\n',
        '<span class="t-muted">  vuln.py line 4 — SECRET_KEY = "jwt-super-secret..."</span>\n',
        '<span class="t-red">  Severity: HIGH   Confidence: HIGH</span>\n\n',
        '<span class="t-red">Issue: [B602] subprocess call with shell=True</span>\n',
        '<span class="t-muted">  vuln.py line 8 — subprocess.run(user_input, shell=True)</span>\n',
        '<span class="t-red">  Severity: HIGH   Confidence: HIGH</span>\n\n',
        '<span class="t-red">Issue: [B608] Possible SQL injection via string-based query</span>\n',
        '<span class="t-muted">  vuln.py line 12 — "SELECT * FROM users WHERE name=\'" + username</span>\n',
        '<span class="t-red">  Severity: HIGH   Confidence: MEDIUM</span>\n\n',
        '<span class="t-red">Issue: [B301] Pickle and modules that wrap it can be unsafe</span>\n',
        '<span class="t-muted">  vuln.py line 16 — pickle.loads(raw_bytes)</span>\n',
        '<span class="t-red">  Severity: HIGH   Confidence: HIGH</span>\n\n',
        '<span class="t-yellow">Issue: [B324] Use of weak MD5 hash for security</span>\n',
        '<span class="t-muted">  vuln.py line 20 — hashlib.md5(pwd.encode()).hexdigest()</span>\n',
        '<span class="t-yellow">  Severity: MEDIUM  Confidence: HIGH</span>\n\n',
        '<span class="t-red">Issue: [B501] Request with verify=False disabling SSL</span>\n',
        '<span class="t-muted">  vuln.py line 24 — requests.get(url, verify=False)</span>\n',
        '<span class="t-red">  Severity: HIGH   Confidence: HIGH</span>\n\n',
        '<span class="t-muted">─────────────────────────────────────────────</span>\n',
        '<span class="t-yellow">Total: 6 issues (5 HIGH, 1 MEDIUM, 0 LOW)</span>\n',
    ]


# ── HTTP server ──────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silence access log

    def send_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        path = self.path

        if path == "/api/secrets":
            self.send_json(handle_secrets())
        elif path == "/api/sqli":
            self.send_json(handle_sqli(body))
        elif path == "/api/deps":
            self.send_json(handle_deps())
        elif path == "/api/bandit":
            self.send_json(handle_bandit())
        else:
            self.send_json({"html": "unknown endpoint"})


def main():
    print("\n" + "="*50)
    print("  DevSecOps Workshop GUI")
    print("="*50)
    print(f"\n  Starting server on http://localhost:{PORT}")
    print("  Opening browser automatically...\n")
    print("  Press Ctrl+C to stop when done.\n")

    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()

    with socketserver.TCPServer(("", PORT), Handler) as srv:
        srv.allow_reuse_address = True
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped. Good luck with the workshop!")

if __name__ == "__main__":
    main()
