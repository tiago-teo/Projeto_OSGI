FROM python:3.11-slim

# Instalar Suricata
RUN apt-get update && \
    apt-get install -y suricata && \
    apt-get clean

# Copiar configs se quiseres
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

CMD sh -c "python3 -m http.server 80 & suricata -i eth0 -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules"

