import re
import sqlite3
import requests

from flask import jsonify  # Add this import if not already present

from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template

app = Flask(__name__)

app.static_folder = 'static'  


# SQLi detection patterns (expand as needed)
import re

# Enhanced patterns to detect advanced payloads
SQLI_PATTERNS = [
    r"'",                      # Single quote
    r"--",                     # Comment
    r";",                      # Statement terminator
    r"/\*",                    # Block comment start
    r"\*/",                    # Block comment end
    r"\\b(OR|AND|SELECT|DELETE|INSERT|UPDATE|DROP|UNION|EXEC|SLEEP|WAITFOR|CAST|CONVERT|DECLARE|XP_CMDSHELL|XP_DIRTREE|LOAD_FILE|BENCHMARK|CHAR|CONCAT|IF)\\b",  # Core keywords/functions
    r"\\b(0x[0-9a-fA-F]+)\\b", # Hex values (e.g., 0x414243)
    r"\\b(ASCII|CHR|SUBSTR|SUBSTRING)\\b",  # String manipulation
    r"\\b(EXECUTE|FETCH|OPEN)\\b",  # Execution commands
    r"\\b(ALTER|CREATE|REPLACE|GRANT|REVOKE|TRUNCATE)\\b",  # DDL commands
    r"\\b(INFORMATION_SCHEMA|PG_SLEEP)\\b",  # Schema and Postgres-specific
    r"\\b(DECLARE|WAITFOR)\\b",  # MSSQL-specific
    r"\\b(ARRAY)\\b",          # Array-based injections
]

def is_sqli_attempt(url_query):
    pattern = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)  # Case-insensitive
    return bool(pattern.search(url_query))


def get_client_ip(request):
    forwarded = request.headers.get('X-Forwarded-For') or request.headers.get('X-Real-IP') or request.headers.get('CF-Connecting-IP')
    if forwarded:
        ip = forwarded.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip


# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    
    # Create table with all columns if it doesn't exist
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
    
    # Safely add columns if missing (skips if they exist)
    try:
        cursor.execute("ALTER TABLE attempts ADD COLUMN country TEXT")
    except sqlite3.OperationalError:
        pass  # Already exists
    
    try:
        cursor.execute("ALTER TABLE attempts ADD COLUMN isp TEXT")
    except sqlite3.OperationalError:
        pass  # Already exists
    
    conn.commit()
    conn.close()

def log_attempt(ip, attempted):
    # Fetch geo-location data
    try:
        geo = requests.get(f"https://ipapi.co/{ip}/json/").json()
        country = geo.get('country_name', 'Unknown')
        isp = geo.get('org', 'Unknown')
    except Exception as e:
        country = 'Unknown'
        isp = 'Unknown'
    
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('INSERT INTO attempts (ip, attempted, timestamp, country, isp) VALUES (?, ?, ?, ?, ?)',
                   (ip, attempted, timestamp, country, isp))
    conn.commit()
    conn.close()
    
    
    
def get_attempts_count():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM attempts')
    count = cursor.fetchone()[0]
    conn.close()
    return count



# Detection middleware
@app.before_request
def check_for_sqli():
    if request.path == '/caught-sqli' or request.path == '/attempts':  # Skip for these pages
        return
    url_query = request.query_string.decode('utf-8')
    if is_sqli_attempt(url_query):
        client_ip = get_client_ip(request)
        log_attempt(client_ip, url_query)  # Log to DB
        return redirect(url_for('caught_sqli', attempted=url_query, ip=client_ip))

# Main page with company info and attempts section
@app.route('/')
def index():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    conn.close()
    
    attempt_count = get_attempts_count()  # Get the total count
    
    return render_template('index.html', attempts=attempts, attempt_count=attempt_count)





@app.route('/api/attempts')
def api_attempts():
    conn = sqlite3.connect('sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts for JSON
    attempts_list = [
        {"ip": a[0], "attempted": a[1], "timestamp": a[2], "country": a[3], "isp": a[4]} for a in attempts
    ]
    return jsonify(attempts_list)




# Custom error page
@app.route('/caught-sqli')
def caught_sqli():
    attempted = request.args.get('attempted', '')
    ip = request.args.get('ip', '')
    return render_template('caught_sqli.html', attempted=attempted, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)
