from flask import Flask, render_template, jsonify, request
import sqlite3
import threading
import time
import json
import os
from datetime import datetime

app = Flask(__name__)

# Initialize DB with both tables (added log_type and attack_command to modsec_logs)
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
            matched_rules TEXT,
            log_type TEXT DEFAULT 'Unknown',       -- Classified type (e.g., SQL Injection, XSS)
            attack_command TEXT DEFAULT 'Unknown'  -- Extracted attack details (e.g., URI/query)
        )
    ''')
    conn.commit()
    conn.close()

# Call it once on startup
with app.app_context():
    init_db()

# Updated parser: Classifies type, extracts attack command, and parses rules
def parse_modsec_json(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    tx = data.get("transaction", {})
    req = data.get("request", {})
    aud = data.get("audit_data", {})
    msgs = aud.get("messages", [])

    # --- Determine attack type from tags ---
    attack_type = "Unknown"
    all_text = " ".join(msgs).lower()
    if "attack-xss" in all_text:
        attack_type = "XSS"
    elif "attack-sqli" in all_text or "sql injection" in all_text:
        attack_type = "SQL Injection"
    elif "attack-rfi" in all_text:
        attack_type = "Remote File Inclusion"
    elif "attack-lfi" in all_text:
        attack_type = "Local File Inclusion"
    elif "attack-rce" in all_text:
        attack_type = "Remote Code Execution"

    # --- Extract attack command ---
    attack_command = req.get("request_line", "")
    if not attack_command and "uri" in tx:
        attack_command = tx.get("uri")

    # --- Extract matched rules ---
    matched_rules = []
    for msg in msgs:
        # Extract rule id and message from the raw CRS message string
        rid = None
        if "[id \"" in msg:
            try:
                rid = msg.split("[id \"")[1].split("\"]")[0]
            except IndexError:
                rid = None
        rule_msg = None
        if "[msg \"" in msg:
            try:
                rule_msg = msg.split("[msg \"")[1].split("\"]")[0]
            except IndexError:
                rule_msg = None
        matched_rules.append({
            "id": rid or "unknown",
            "message": rule_msg or msg
        })

    # Build DB insert payload
    return {
        "timestamp": tx.get("time"),
        "client_ip": tx.get("remote_address"),
        "uri": tx.get("uri") or req.get("request_line"),
        "method": req.get("method", ""),
        "status": str(data.get("response", {}).get("status", "")),
        "disrupted": bool(aud.get("action", {}).get("intercepted", False)),
        "matched_rules": json.dumps(matched_rules),
        "log_type": attack_type,
        "attack_command": attack_command
    }

# Background tailer to read and insert logs (updated for new fields)
def tail_log():
    log_path = '/var/log/apache2/modsec_audit.log'
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return
    with open(log_path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            rec = parse_modsec_json(line)
            if rec:
                conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO modsec_logs (timestamp, client_ip, uri, method, status, disrupted, matched_rules, log_type, attack_command)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (rec['timestamp'], rec['client_ip'], rec['uri'], rec['method'], rec['status'], rec['disrupted'], rec['matched_rules'], rec['log_type'], rec['attack_command']))
                conn.commit()
                conn.close()

# Start the tailer thread
threading.Thread(target=tail_log, daemon=True).start()

# Updated route: Fetch both attempts and modsec_logs (including new fields)
@app.route('/')
def admin_logs():
    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    cursor.execute('SELECT timestamp, client_ip, uri, method, status, disrupted, matched_rules, log_type, attack_command FROM modsec_logs ORDER BY id DESC')
    modsec_logs = cursor.fetchall()  # Fetch Cyber Sentinel logs with new fields
    conn.close()
    return render_template('dashboard.html', attempts=attempts, modsec_logs=modsec_logs)  # Pass both to template

@app.route('/api/attempts')
def api_attempts():
    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attempted, timestamp, country, isp FROM attempts ORDER BY id DESC')
    attempts = cursor.fetchall()
    conn.close()
    return jsonify([
        {"ip": a[0], "attempted": a[1], "timestamp": a[2], "country": a[3], "isp": a[4]}
        for a in attempts
    ])

# Updated endpoint for live refresh of modsec_logs (includes pagination)
@app.route('/api/all_logs')
def api_all_logs():
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 10))  # default 10 per page
    offset = (page - 1) * size

    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
    cursor = conn.cursor()

    # Fetch attempts (SQLi custom detection logs)
    cursor.execute('SELECT id, ip, attempted, timestamp, country, isp FROM attempts')
    attempts = [
        {
            "id": row[0],
            "timestamp": row[3],
            "type": "SQL Injection",
            "ip": row[1],
            "attack_command": row[2],
            "rules": "N/A",
            "country": row[4],
            "isp": row[5],
            "disrupted": True
        }
        for row in cursor.fetchall()
    ]

    # Fetch ModSecurity logs
    cursor.execute('''
        SELECT id, timestamp, client_ip, uri, method, status, disrupted, matched_rules, log_type, attack_command
        FROM modsec_logs
    ''')
    modsec_logs = [
        {
            "id": row[0],
            "timestamp": row[1],
            "type": row[8] or "CyberSentinel WAF",
            "ip": row[2],
            "attack_command": row[9] or row[3],
            "rules": row[7],
            "country": "N/A",
            "isp": "N/A",
            "disrupted": bool(row[6])
        }
        for row in cursor.fetchall()
    ]

    conn.close()

    # Merge and sort all logs newest → oldest
    all_logs = attempts + modsec_logs
    all_logs.sort(key=lambda x: datetime.strptime(x["timestamp"], "%d/%b/%Y:%H:%M:%S.%f %z"), reverse=True)

    # Pagination
    total = len(all_logs)
    paginated_logs = all_logs[offset:offset + size]
    total_pages = (total + size - 1) // size

    return jsonify({
        "logs": paginated_logs,
        "total": total,
        "page": page,
        "size": size,
        "pages": total_pages
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
