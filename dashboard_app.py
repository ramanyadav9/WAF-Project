from flask import Flask, render_template, jsonify, request
import sqlite3
import threading
import time
import json
import os
from datetime import datetime

app = Flask(__name__)

DB_PATH = '/home/kali/WAF-Project/sqli_logs.db'
LOG_PATH = '/var/log/apache2/modsec_audit.log'

# -------------------- DB Initialization --------------------
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

# -------------------- Log Parser --------------------
def parse_modsec_json(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    tx = data.get("transaction", {}) or {}
    req = data.get("request", {}) or {}
    aud = data.get("audit_data", {}) or {}
    msgs = aud.get("messages", []) or []

    # --- Determine attack type ---
    attack_type = "Unknown"
    all_text = " ".join(msgs).lower()
    if "attack-xss" in all_text or " xss " in all_text:
        attack_type = "XSS"
    elif "attack-sqli" in all_text or "sql injection" in all_text or " sqli " in all_text:
        attack_type = "SQL Injection"
    elif "attack-rfi" in all_text:
        attack_type = "Remote File Inclusion"
    elif "attack-lfi" in all_text:
        attack_type = "Local File Inclusion"
    elif "attack-rce" in all_text:
        attack_type = "Remote Code Execution"

    # --- Extract attack command ---
    attack_command = req.get("request_line") or tx.get("uri") or ""
    headers = req.get("headers", {}) or {}
    ref = headers.get("Referer") or headers.get("referer") or ""
    if (not attack_command or attack_command == "") and any(tok in ref.lower() for tok in ("<script", "javascript:", "onerror=", "onload=", "%3cscript", "alert(")):
        attack_command = ref

    # --- Extract matched rules ---
    matched_rules = []
    for msg in msgs:
        rid = None
        if "[id \"" in msg:
            try:
                rid = msg.split("[id \"")[1].split("\"]")[0]
            except IndexError:
                pass
        rule_msg = None
        if "[msg \"" in msg:
            try:
                rule_msg = msg.split("[msg \"")[1].split("\"]")[0]
            except IndexError:
                pass
        matched_rules.append({
            "id": rid or "unknown",
            "message": rule_msg or msg
        })

    return {
        "timestamp": tx.get("time"),
        "client_ip": tx.get("remote_address"),
        "uri": tx.get("uri") or req.get("request_line"),
        "method": req.get("method", ""),
        "status": str(data.get("response", {}).get("status", "")),
        "disrupted": bool(aud.get("action", {}).get("intercepted", False)),
        "matched_rules": json.dumps(matched_rules),
        "log_type": attack_type,
        "attack_command": attack_command or "Unknown"
    }

# -------------------- Background Tailer --------------------
def tail_log():
    if not os.path.exists(LOG_PATH):
        print(f"Log file not found: {LOG_PATH}")
        return
    with open(LOG_PATH, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            rec = parse_modsec_json(line)
            if rec:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO modsec_logs (timestamp, client_ip, uri, method, status, disrupted, matched_rules, log_type, attack_command)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (rec['timestamp'], rec['client_ip'], rec['uri'], rec['method'], rec['status'], rec['disrupted'], rec['matched_rules'], rec['log_type'], rec['attack_command']))
                conn.commit()
                conn.close()

threading.Thread(target=tail_log, daemon=True).start()

# -------------------- Timestamp Parser --------------------
def parse_ts(ts: str):
    if not ts:
        return datetime.fromtimestamp(0)
    for fmt in ("%d/%b/%Y:%H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            continue
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            continue
    return datetime.fromtimestamp(0)

# -------------------- Routes --------------------
@app.route('/')
def admin_logs():
    return render_template('dashboard.html')

@app.route('/api/all_logs')
def api_all_logs():
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 10))
    offset = (page - 1) * size

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Attempts logs
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
            "disrupted": True,
            "_sort_ts": parse_ts(row[3]).timestamp()
        }
        for row in cursor.fetchall()
    ]

    # ModSecurity logs
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
            "disrupted": bool(row[6]),
            "_sort_ts": parse_ts(row[1]).timestamp()
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    # Merge & sort
    all_logs = attempts + modsec_logs
    all_logs.sort(key=lambda x: x["_sort_ts"], reverse=True)

    total = len(all_logs)
    paginated_logs = all_logs[offset:offset + size]
    total_pages = (total + size - 1) // size
    for row in paginated_logs:
        row.pop("_sort_ts", None)

    return jsonify({
        "logs": paginated_logs,
        "total": total,
        "page": page,
        "size": size,
        "pages": total_pages
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
