import re
import sqlite3
import requests
from flask import Flask, request, redirect, url_for, render_template, jsonify
from datetime import datetime

app = Flask(__name__)
app.static_folder = 'static'

# Enhanced SQL injection patterns with proper word boundaries
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
    # Add missing columns for upgrades
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
        geo = requests.get(f"https://ipapi.co/{ip}/json/").json()
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

@app.before_request
def check_for_sqli():
    # List of routes that should never be blocked
    safe_paths = ['/', '/caught-sqli', '/attempts', '/api/attempts', '/favicon.ico']
    if request.path.startswith('/static') or request.path in safe_paths:
        return

    client_ip = get_client_ip(request)
    detected = False
    payload = ""

    # 1. Check all GET parameter values (user input)
    for k, v in request.args.items():
        if v and is_sqli_attempt(v):
            payload = f"Param: {k}={v}"
            detected = True
            break  # Only block & log first match

    # 2. If nothing detected yet, check the full query string as sometimes INJECTS happen here directly
    if not detected:
        url_query = request.query_string.decode('utf-8')
        if url_query and is_sqli_attempt(url_query):
            payload = f"QueryString: {url_query}"
            detected = True

    if detected:
        log_attempt(client_ip, payload)
        if request.path not in safe_paths:  # don't redirect user if already on dashboard/caught-sqli
            return redirect(url_for('caught_sqli', attempted=payload, ip=client_ip))
    # Normal browsing? Just proceed, don't log, don't block


# On the dashboard ('/') side, always show ALL logs (normal and suspicious)
@app.route('/')
def index():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    conn.close()
    attempt_count = get_attempts_count()
    return render_template('index.html', attempts=attempts, attempt_count=attempt_count)

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

@app.route('/caught-sqli')
def caught_sqli():
    attempted = request.args.get('attempted', '')
    ip = request.args.get('ip', '')
    return render_template('caught_sqli.html', attempted=attempted, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)
