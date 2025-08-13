# waf_app.py — updated and cleaned
import re
import sqlite3
import os
import requests as py_requests
from flask import Flask, request, Response, render_template, redirect, url_for, send_from_directory
from datetime import datetime
from urllib.parse import unquote_plus
from flask import abort
import uuid
import json
import time

app = Flask(__name__)

DB_PATH = '/home/kali/WAF-Project/sqli_logs.db'
LOG_PATH = '/var/log/apache2/modsec_audit.log'

def get_client_ip(request):
    forwarded = (
        request.headers.get('X-Forwarded-For')
        or request.headers.get('X-Real-IP')
        or request.headers.get('CF-Connecting-IP')
    )
    return forwarded.split(',')[0].strip() if forwarded else request.remote_addr

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            attempted TEXT,
            timestamp TEXT,
            country TEXT,
            isp TEXT
        )
    ''')
    # Keep schema aligned with dashboard_app.py (include log_type & attack_command)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS modsec_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            uri TEXT,
            method TEXT,
            status TEXT,
            disrupted BOOLEAN,
            matched_rules TEXT,
            log_type TEXT DEFAULT 'Unknown',
            attack_command TEXT DEFAULT 'Unknown'
        )
    ''')
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

def log_attempt(ip, attempted):
    try:
        geo = py_requests.get(f"https://ipapi.co/{ip}/json/", timeout=2).json()
        country = geo.get('country_name', 'Unknown')
        isp = geo.get('org', 'Unknown')
    except Exception:
        country = 'Unknown'
        isp = 'Unknown'
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            'INSERT INTO attempts (ip, attempted, timestamp, country, isp) VALUES (?, ?, ?, ?, ?)',
            (ip, attempted, timestamp, country, isp)
        )
        conn.commit()
    except Exception as e:
        print("Failed to write attempt:", e)
    finally:
        try:
            conn.close()
        except:
            pass

def _audit_says_block(trace_id, timeout=0.8, max_lines=400):
    """
    Look for the just-processed request in the ModSecurity audit log by the
    custom header X-CyberSentinel-Trace, and decide if it should be blocked.
    Returns (blocked: bool, reason: str)
    """
    log_path = LOG_PATH
    deadline = time.time() + timeout
    want = trace_id.lower()

    while time.time() < deadline:
        try:
            with open(log_path, "rb") as f:
                lines = f.readlines()[-max_lines:]
        except FileNotFoundError:
            return (False, "")

        # Scan newest-to-oldest for speed
        for raw in reversed(lines):
            try:
                entry = json.loads(raw)
            except Exception:
                continue

            req = entry.get("request", {})
            headers = req.get("headers", {}) or {}

            # Case-insensitive header lookup
            trace_val = None
            # headers in audit may be dict or array; handle both
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if k.lower() == "x-cybersentinel-trace":
                        trace_val = str(v).lower()
                        break
            else:
                # If headers are array-like, try scanning
                try:
                    for item in headers:
                        # item could be "Name: value" or ["Name","value"]
                        if isinstance(item, str) and ":" in item:
                            k, v = item.split(":", 1)
                            if k.strip().lower() == "x-cybersentinel-trace":
                                trace_val = v.strip().lower()
                                break
                        elif isinstance(item, (list, tuple)) and len(item) == 2:
                            if item[0].strip().lower() == "x-cybersentinel-trace":
                                trace_val = str(item[1]).lower()
                                break
                except Exception:
                    pass

            if trace_val != want:
                continue  # not our request

            aud = entry.get("audit_data", {}) or {}
            msgs = aud.get("messages", []) or []
            tags_text = " ".join(msgs).lower()
            intercepted = bool(aud.get("action", {}).get("intercepted", False))

            if intercepted:
                return (True, "ModSecurity intercepted=true")

            # Tag-based block (covers cases like XSS seen in headers)
            for tag in ("attack-xss", "attack-sqli", "attack-rfi", "attack-lfi", "attack-rce"):
                if tag in tags_text:
                    return (True, f"Detected via CRS tag: {tag}")

            # Found our request but not blocked → stop searching
            return (False, "")

        # brief wait to let Apache flush the JSON line
        time.sleep(0.05)

    return (False, "")

@app.route('/caught-attack')
def caught_attack():
    attempted = request.args.get('attempted', 'Unknown Attack')
    ip = request.args.get('ip', get_client_ip(request))
    return render_template('caught_attack.html', attempted=attempted, ip=ip)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def waf_proxy(path):
    query_string = request.query_string.decode('utf-8')
    backend_url = f"http://127.0.0.1:8090/{path}"
    if query_string:
        backend_url += f"?{query_string}"

    trace_id = str(uuid.uuid4())

    try:
        # Forward request to Apache/ModSecurity
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        fwd_headers["X-CyberSentinel-Trace"] = trace_id

        resp = py_requests.request(
            method=request.method,
            url=backend_url,
            headers=fwd_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=False,
            timeout=6
        )

        client_ip = get_client_ip(request)

        # Primary quick decision: ModSecurity explicit 403
        if resp.status_code == 403:
            attempted = "Blocked by ModSecurity (HTTP 403)"
            log_attempt(client_ip, attempted)
            return redirect(url_for('caught_attack', attempted=attempted))

        # Secondary robust decision: check audit log for our trace id
        blocked, reason = _audit_says_block(trace_id)
        if blocked:
            attempted = f"Attack Detected by CyberSentinel — {reason}"
            log_attempt(client_ip, attempted)
            return redirect(url_for('caught_attack', attempted=attempted))

        # Safe: serve homepage for clean "/" responses
        if path == '' and resp.status_code == 200:
            return send_from_directory(os.path.join(app.root_path, 'static_home'), 'index.html')

        # Proxy other responses back
        excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
        return Response(resp.content, resp.status_code, headers)

    except py_requests.RequestException as e:
        # Optional: log exception here
        print("Proxy request error:", e)
        return f"Error: {str(e)}", 502

@app.errorhandler(500)
def internal_error(error):
    ip = get_client_ip(request)
    print(f"Internal error: {error}")
    return render_template('internal_error.html', ip=ip), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
