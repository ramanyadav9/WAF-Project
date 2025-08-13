import re, sqlite3, os
import requests as py_requests
from flask import Flask, request, Response, render_template, redirect, url_for, stream_with_context, send_from_directory
from datetime import datetime
from urllib.parse import unquote_plus
from flask import abort

app = Flask(__name__)

# --- SQLi detection logic (unchanged) ---
SQLI_PATTERNS = [
    r"'", r"--", r";", r"/\*", r"\*/",
    r"(%27)|(')|(--)|(%23)|(#)",
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
    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS modsec_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            uri TEXT,
            method TEXT,
            status TEXT,
            disrupted BOOLEAN,
            matched_rules TEXT
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
    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
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

# Updated route for generalized custom denied page
@app.route('/caught-attack')
def caught_attack():
    attempted = request.args.get('attempted', 'Unknown Attack')  # Generalized for any attack
    ip = request.args.get('ip', get_client_ip(request))
    return render_template('caught_attack.html', attempted=attempted, ip=ip)

# Updated proxy route: Proxy all requests to Cyber Sentinel for detection, catch blocks
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def waf_proxy(path):
    # Optional: Your basic SQLi check as fallback (comment out if you want Cyber Sentinel to handle all)
    detected, payload = waf_detect()
    if detected:
        client_ip = get_client_ip(request)
        log_attempt(client_ip, payload)
        return redirect(url_for('caught_attack', attempted=payload))

    # Serve static homepage at root if no path
    if path == '':
        return send_from_directory(os.path.join(app.root_path, 'static_home'), 'index.html')

    # Proxy to Apache/Cyber Sentinel for advanced detection
    backend_url = f"http://127.0.0.1:8090/{path}?{request.query_string.decode('utf-8')}"
    try:
        resp = py_requests.request(
            method=request.method,
            url=backend_url,
            headers={k: v for k, v in request.headers if k.lower() != 'host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True
        )
        # If Cyber Sentinel blocks (403), redirect to custom page
        if resp.status_code == 403:
            client_ip = get_client_ip(request)
            attempted = "Advanced Attack Detected by Cyber Sentinel"  # Can enhance with log details if needed
            log_attempt(client_ip, attempted)  # Log the block
            return redirect(url_for('caught_attack', attempted=attempted))

        # Safe response: stream back
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(stream_with_context(resp.iter_content(chunk_size=1024)), resp.status_code, headers)
    except py_requests.RequestException as e:
        return f"Error proxying to Cyber Sentinel backend: {str(e)}", 502

# Custom 404 handler
@app.errorhandler(404)
def not_found(error):
    ip = get_client_ip(request)  # Use your existing function
    return render_template('not_found.html', ip=ip), 404

# Custom 500 handler
@app.errorhandler(500)
def internal_error(error):
    ip = get_client_ip(request)  # Use your existing function
    # Optional: Log the error for debugging
    print(f"Internal error: {error}")  # Or use logging module
    return render_template('internal_error.html', ip=ip), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
