FROM python:3.11-slim

# Instalar Suricata, iptables e bibliotecas Python
RUN apt-get update && \
    apt-get install -y suricata iptables tcpdump iproute2 procps && \
    pip install watchdog pandas scikit-learn flask && \
    apt-get clean

# Copiar configurações do Suricata
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

# Copiar scripts para o container
COPY log_watch.py /app/log_watch.py
COPY alg_dosDetect.py /app/alg_dosDetect.py
COPY entrypoint.sh /entrypoint.sh
COPY monitor.py /app/monitor.py
COPY templates /app/templates
COPY static /app/static

# Usar 'sh' para correr o script (não é preciso chmod +x)
CMD ["sh", "/entrypoint.sh"]
