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
    [[ -f wafproxy.pid ]] && sudo kill -9 $(cat wafproxy.pid) && rm -f wafproxy.pid

    echo "[*] Stopping Dashboard..."
    [[ -f dashboard.pid ]] && kill -9 $(cat dashboard.pid) && rm -f dashboard.pid

    echo "[+] Both services stopped."
}

status() {
    proxy_running=0
    dash_running=0
    [[ -f wafproxy.pid ]] && ps -p $(cat wafproxy.pid) > /dev/null 2>&1 && proxy_running=1
    [[ -f dashboard.pid ]] && ps -p $(cat dashboard.pid) > /dev/null 2>&1 && dash_running=1
    echo "WAF proxy running:    $([[ $proxy_running -eq 1 ]] && echo YES || echo NO)"
    echo "Dashboard running:    $([[ $dash_running -eq 1 ]] && echo YES || echo NO)"
}

case "$1" in
    start)  start ;;
    stop)   stop  ;;
    status) status ;;
    *)
        echo "Usage: waf {start|stop|status}"
        ;;
esac
