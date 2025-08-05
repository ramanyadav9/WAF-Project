import re
import sqlite3
import requests as py_requests
from flask import Flask, request, Response, render_template, redirect, url_for, jsonify, stream_with_context
from datetime import datetime
from urllib.parse import unquote_plus

app = Flask(__name__)

# === SQL Injection patterns ===
SQLI_PATTERNS = [
    r"'", r"--", r";", r"/\*", r"\*/",
    r"\b(OR|AND|SELECT|DELETE|INSERT|UPDATE|DROP|UNION|EXEC|SLEEP|WAITFOR|CAST|CONVERT|DECLARE|XP_CMDSHELL|XP_DIRTREE|LOAD_FILE|BENCHMARK|CHAR|CONCAT|IF)\b",
    r"\b(0x[0-9a-fA-F]+)\b",
    r"\b(ASCII|CHR|SUBSTR|SUBSTRING)\b",
    r"\b(EXECUTE|FETCH|OPEN)\b",
    r"\b(ALTER|CREATE|REPLACE|GRANT|REVOKE|TRUNCATE)\b",
    r"\b(INFORMATION_SCHEMA|PG_SLEEP)\b",
    r"\b(ARRAY)\b"
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

def is_sqli_attempt(value):
    return bool(SQLI_REGEX.search(value)) if value else False

def get_client_ip(request):
    forwarded = (
        request.headers.get('X-Forwarded-For')
        or request.headers.get('X-Real-IP')
        or request.headers.get('CF-Connecting-IP')
    )
    if forwarded:
        ip = forwarded.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def init_db():
    conn = sqlite3.connect('sqli_logs.db')
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
    try:
        cursor.execute("ALTER TABLE attempts ADD COLUMN country TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE attempts ADD COLUMN isp TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

def log_attempt(ip, attempted):
    try:
        geo = py_requests.get(f"https://ipapi.co/{ip}/json/").json()
        country = geo.get('country_name', 'Unknown')
        isp = geo.get('org', 'Unknown')
    except Exception:
        country = 'Unknown'
        isp = 'Unknown'
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        'INSERT INTO attempts (ip, attempted, timestamp, country, isp) VALUES (?, ?, ?, ?, ?)',
        (ip, attempted, timestamp, country, isp)
    )
    conn.commit()
    conn.close()

def get_attempts_count():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM attempts')
    count = cursor.fetchone()[0]
    conn.close()
    return count

def waf_detect():
    # Check all decoded GET parameter values
    for k, v in request.args.items():
        decoded_v = unquote_plus(v)
        if decoded_v and is_sqli_attempt(decoded_v):
            return True, f"Param: {k}={decoded_v}"
    # Check raw query string as fallback
    url_query = request.query_string.decode('utf-8')
    decoded_qs = unquote_plus(url_query)
    if decoded_qs and is_sqli_attempt(decoded_qs):
        return True, f"QueryString: {decoded_qs}"
    return False, ""

# Safe (non-proxied) endpoints
SAFE_PATHS = {
    'caught-sqli': 'caught_sqli',
    'api/attempts': 'api_attempts'
}

@app.route('/caught-sqli')
def caught_sqli():
    attempted = request.args.get('attempted', '')
    ip = request.args.get('ip', '')
    return render_template('caught_sqli.html', attempted=attempted, ip=ip)

@app.route('/api/attempts')
def api_attempts():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    conn.close()
    attempts_list = [
        {"ip": a[0], "attempted": a[1], "timestamp": a[2], "country": a[3], "isp": a[4]} for a in attempts
    ]
    return jsonify(attempts_list)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def waf_gate_proxy(path):
    # (1) Serve safe paths (API, block page) directly
    if path in SAFE_PATHS:
        return app.view_functions[SAFE_PATHS[path]]()

    # (2) Run WAF detection for all other traffic, including the dashboard (/)
    detected, payload = waf_detect()
    if detected:
        client_ip = get_client_ip(request)
        log_attempt(client_ip, payload)
        return redirect(url_for('caught_sqli', attempted=payload, ip=client_ip))

    # (3) Serve dashboard directly if root path
    if path == '':
        conn = sqlite3.connect('sqli_logs.db')
        cursor = conn.cursor()
        cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
        attempts = cursor.fetchall()
        conn.close()
        attempt_count = get_attempts_count()
        return render_template('index.html', attempts=attempts, attempt_count=attempt_count)

    # (4) All other requests proxy to Apache backend
    backend_url = f"http://127.0.0.1:8080/{path}"
    resp = py_requests.request(
        method=request.method,
        url=backend_url,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True
    )
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
    response = Response(stream_with_context(resp.iter_content(chunk_size=1024)), resp.status_code, headers)
    return response

if __name__ == '__main__':
    # In production, run with Gunicorn: sudo /path/to/venv/bin/gunicorn --bind 0.0.0.0:80 app:app
    app.run(host='0.0.0.0', port=80, debug=False)
