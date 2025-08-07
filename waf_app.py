# waf_app.py
import re, sqlite3, os
import requests as py_requests
from flask import Flask, request, Response, render_template, redirect, url_for, stream_with_context, send_from_directory
import os
from datetime import datetime
from urllib.parse import unquote_plus

app = Flask(__name__)

# --- SQLi detection logic (unchanged) ---
SQLI_PATTERNS = [
    r"'", r"--", r";", r"/\*", r"\*/",
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"\b(OR|AND|SELECT|DELETE|INSERT|UPDATE|DROP|UNION|EXEC|SLEEP|WAITFOR|CAST|CONVERT|DECLARE|XP_CMDSHELL|XP_DIRTREE|LOAD_FILE|BENCHMARK|CHAR|CONCAT|ASCII|CHR|SUBSTR|SUBSTRING|PG_SLEEP|INFORMATION_SCHEMA|XP_|EXECUTE|FETCH|OPEN|ALTER|CREATE|REPLACE|GRANT|REVOKE|TRUNCATE|ARRAY)\b",
    r"\b(waitfor\s+delay|benchmark\s*\(|sleep\s*\(|pg_sleep\s*\()",
    r"\b(?:0x[0-9a-fA-F]+)\b",
    r"[\s\(\)]*=\s*\d+",
    r"[\w]*\s+like\s+\w*['\"]",
    r"/\*.*?\*/",
    r"--.*$",
    r"#.*$",
    r";.*?(drop|truncate|delete|insert|exec|update|union)\b",
    r"union(\s|/\*.*?\*/|%[0-9a-fA-F]{2}){0,10}select",
    r"\bselect.+from.+where\b",
    r"%20|%09|%0a|%0d|\t|\n|\r",
    r"[\s\(\)]*[+|&^][\s\(\)]*\d+",
    r";.*?\b(select|drop|insert|delete|update)\b",
    r"(sleep\s*\(\d+\)|benchmark\s*\([^)]+\)|pg_sleep\s*\(\d+\))",
    r"\(\s*select.+\)",
    r"%2527|%252D%252D",
    r"\|\|\s*\d{1,3}\s*=\s*\d{1,3}\|\|",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)



SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

def is_sqli_attempt(value):
    return bool(SQLI_REGEX.search(value)) if value else False

def get_client_ip(request):
    forwarded = (
        request.headers.get('X-Forwarded-For')
        or request.headers.get('X-Real-IP')
        or request.headers.get('CF-Connecting-IP')
    )
    return forwarded.split(',')[0].strip() if forwarded else request.remote_addr

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
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

def log_attempt(ip, attempted):
    # Geolocation (simplified, ignore if offline)
    try:
        geo = py_requests.get(f"https://ipapi.co/{ip}/json/").json()
        country = geo.get('country_name', 'Unknown')
        isp = geo.get('org', 'Unknown')
    except:
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

def waf_detect():
    for k, v in request.args.items():
        decoded_v = unquote_plus(v)
        if decoded_v and is_sqli_attempt(decoded_v):
            return True, f"Param: {k}={decoded_v}"
    url_query = request.query_string.decode('utf-8')
    decoded_qs = unquote_plus(url_query)
    if decoded_qs and is_sqli_attempt(decoded_qs):
        return True, f"QueryString: {decoded_qs}"
    return False, ""





@app.route('/caught-sqli')
def caught_sqli():
    attempted = request.args.get('attempted', '')
    ip = request.args.get('ip', '')
    return render_template('caught_sqli.html', attempted=attempted, ip=ip)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def waf_proxy(path):
    detected, payload = waf_detect()
    if detected:
        client_ip = get_client_ip(request)
        log_attempt(client_ip, payload)
        return redirect(url_for('caught_sqli', attempted=payload, ip=client_ip))
    if path == '':
        # Serve static homepage at root
        return send_from_directory(os.path.join(app.root_path, 'static_home'), 'index.html')
    # Proxy to backend (Apache on 8090)
    backend_url = f"http://127.0.0.1:8090/{path}"
    resp = py_requests.request(
        method=request.method,
        url=backend_url,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True)
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
    return Response(stream_with_context(resp.iter_content(chunk_size=1024)), resp.status_code, headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)