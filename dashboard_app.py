from flask import Flask, render_template, jsonify
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
            log_type TEXT,       -- Classified type (e.g., SQL Injection, XSS)
            attack_command TEXT  -- Extracted attack details (e.g., URI/query)
        )
    ''')
    conn.commit()
    conn.close()

# Call it once on startup
with app.app_context():
    init_db()

# Updated parser: Classifies type and extracts attack command
def parse_modsec_json(line):
    try:
        obj = json.loads(line)
        tx = obj.get('transaction', {})
        audit_data = obj.get('audit_data', {})
        messages = audit_data.get('messages', [])
        matched = json.dumps([{
            'rule_id': m.get('rule_id', ''),
            'message': m.get('message', ''),
            'severity': m.get('severity', '')
        } for m in messages])

        # Classify type from messages (e.g., look for keywords)
        log_type = "Unknown"
        lower_msgs = json.dumps(messages).lower()
        if "sqli" in lower_msgs or "sql" in lower_msgs:
            log_type = "SQL Injection"
        elif "xss" in lower_msgs:
            log_type = "XSS"
        # Add more classifications as needed (e.g., "rfi" for Remote File Inclusion)

        # Extract attack command (full URI with query)
        attack_command = tx.get('uri', 'Unknown')

        disrupted = audit_data.get('action', '') == 'intercepted'
        return {
            'timestamp': tx.get('time_stamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'client_ip': tx.get('client_ip', ''),
            'uri': tx.get('uri', ''),
            'method': tx.get('request_method', ''),
            'status': audit_data.get('status', ''),
            'disrupted': disrupted,
            'matched_rules': matched,
            'log_type': log_type,
            'attack_command': attack_command
        }
    except Exception:
        return None

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

# New endpoint for live refresh of modsec_logs (includes new fields)
@app.route('/api/modsec_logs')
def api_modsec_logs():
    conn = sqlite3.connect('/home/kali/WAF-Project/sqli_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, client_ip, uri, method, status, disrupted, matched_rules, log_type, attack_command FROM modsec_logs ORDER BY id DESC')
    modsec_logs = cursor.fetchall()
    conn.close()
    return jsonify([
        {"timestamp": l[0], "client_ip": l[1], "uri": l[2], "method": l[3], "status": l[4], "disrupted": l[5], "matched_rules": l[6], "log_type": l[7], "attack_command": l[8]}
        for l in modsec_logs
    ])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
