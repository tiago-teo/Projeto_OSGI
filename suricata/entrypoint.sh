#!/bin/bash

echo "[INIT] A iniciar HTTP server..."
python3 -m http.server 80 &

echo "[INIT] A iniciar Suricata..."
suricata -i eth0 -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules &

echo "[INIT] A iniciar Monitor (Flask)..."
python3 /app/monitor.py &

echo "[INIT] A iniciar Watchdog..."
python3 /app/log_watch.py