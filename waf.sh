#!/bin/bash
# WAF Management Script

WAF_DIR="/home/kali/WAF-Project"
WAF_PROXY_CMD="sudo $WAF_DIR/venv/bin/gunicorn --bind 0.0.0.0:80 waf_app:app"
DASH_CMD="$WAF_DIR/venv/bin/gunicorn --bind 0.0.0.0:5000 dashboard_app:app"

start() {
    echo "[*] Starting WAF proxy..."
    cd "$WAF_DIR"
    $WAF_PROXY_CMD > wafproxy.log 2>&1 &
    echo $! > wafproxy.pid

    echo "[*] Starting Dashboard..."
    cd "$WAF_DIR"
    $DASH_CMD > dashboard.log 2>&1 &
    echo $! > dashboard.pid

    echo "[+] Both WAF and dashboard started."
}
stop() {
    echo "[*] Stopping WAF proxy..."
    if [[ -f wafproxy.pid ]]; then
        if ps -p $(cat wafproxy.pid) > /dev/null 2>&1; then
            sudo kill -9 $(cat wafproxy.pid)
            echo "    → Stopped by PID file."
        else
            echo "    → PID file exists but process not found."
        fi
        rm -f wafproxy.pid
    else
        echo "    → PID file missing, killing by name..."
        sudo pkill -f "gunicorn.*waf_app:app"
    fi

    echo "[*] Stopping Dashboard..."
    if [[ -f dashboard.pid ]]; then
        if ps -p $(cat dashboard.pid) > /dev/null 2>&1; then
            kill -9 $(cat dashboard.pid)
            echo "    → Stopped by PID file."
        else
            echo "    → PID file exists but process not found."
        fi
        rm -f dashboard.pid
    else
        echo "    → PID file missing, killing by name..."
        pkill -f "gunicorn.*dashboard_app:app"
    fi

    echo "[+] Both services stopped."
}
