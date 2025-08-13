import re, sqlite3, os
import requests as py_requests
from flask import Flask, request, Response, render_template, redirect, url_for, stream_with_context, send_from_directory
from datetime import datetime
from urllib.parse import unquote_plus
from flask import abort

app = Flask(__name__)

# --- SQLi detection logic (commented out as per request; ModSecurity handles all) ---
# SQLI_PATTERNS = [ ... ]  # Omitted for brevity
# SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

# def is_sqli_attempt(value):
#     return bool(SQLI_REGEX.search(value)) if value else False

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

# Commented out waf_detect as per request
# def waf_detect():
#     ...

# Updated route for generalized custom denied page
@app.route('/caught-attack')
def caught_attack():
    attempted = request.args.get('attempted', 'Unknown Attack')  # Generalized for any attack
    ip = request.args.get('ip', get_client_ip(request))
    return render_template('caught_attack.html', attempted=attempted, ip=ip)

# Updated proxy route: Proxy all requests to Cyber Sentinel for full detection/handling
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def waf_proxy(path):
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
