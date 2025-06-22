from flask import Flask, jsonify, render_template
from collections import defaultdict
import subprocess
import threading
import time
import re
from alg_dosDetect import detect_anomalous_ips, block_anomalous_ips  # Importa a função de detecção de IPs anômalos

from datetime import datetime

timestamps = defaultdict(list)

import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')
data = defaultdict(list)  # {ip: [count1, count2, ...]} 
total_counts = defaultdict(int)     # Contagem acumulada total
#ip_regex = re.compile(r'IP (\d+\.\d+\.\d+\.\d+)\.\d+ >')
ip_regex = re.compile(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):')

# Captura pacotes em tempo real 
def capture_packets(interface='eth0'):
    p = subprocess.Popen(
        ['tcpdump', '-i', interface, '-nn', '-l', 'ip'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    counters = defaultdict(int)

    def reset_loop():
        while True:
            time.sleep(1)
            for ip, count in counters.items():
                data[ip].append(count)
                if len(data[ip]) > 30:
                    data[ip] = data[ip][-30:]
            counters.clear()

    threading.Thread(target=reset_loop, daemon=True).start()

    for line in p.stdout:
        match = ip_regex.search(line)
        if match:
            ip = match.group(1)
            # Variavel counter agrupa os pacotes capturados por cada IP
            counters[ip] += 1
            total_counts[ip] += 1

@app.route('/')
def index():
    log.info("Index page accessed")
    anomalous_ips = detect_anomalous_ips()
    num_anomalous_ips = len(anomalous_ips)
    num_blocked_ips = block_anomalous_ips(anomalous_ips)
    # Conta o número total de pedidos (soma de todos os pacotes capturados)
    #total_requests = sum(sum(counts) for counts in data.values())
    total_requests = sum(total_counts.values())   

    # Conta o número de IPs diferentes que enviaram pacotes
    num_unique_ips = len(data)


    IPdata = []
    for ip, counts in data.items():
        total = total_counts[ip]
        total_30s = sum(counts)  # Total de pacotes para este IP nos últimos 30 segundos
        maligno = "Sim" if ip in anomalous_ips else "Não" if ip == '172.28.0.1' else "Não"
        IPdata.append({
            "ip": ip,
            "num_packets": total,
            "num_packets_30s": total_30s,
            "maligno": maligno
        })

    # Seleciona os dois IPs com mais tráfego
    top_ips = sorted(data.items(), key=lambda x: sum(x[1]), reverse=True)[:2]

    if top_ips:
        if len(top_ips) < 2:
            top_ips.append(("0.0.0.0", [0]*len(top_ips[0][1])))
    else:
        top_ips.append(("0.0.0.0", [0] * 30))

    ip1, ip2 = top_ips[0][0], top_ips[1][0]
    values = top_ips[0][1]
    values2 = top_ips[1][1]
    labels = [f"{i} seg" for i in range(len(values))]

    ip1_label = f"{ip1} "
    ip2_label = f"{ip2} "
    return render_template(
        'dashboard.html',
        labels=labels,
        values=values,
        values2=values2,
        ip1_label=ip1_label,
        ip2_label=ip2_label,
        num_anomalous_ips=num_anomalous_ips,
        num_blocked_ips=num_blocked_ips,
        total_requests=total_requests,
        num_unique_ips=num_unique_ips,  # Passa o número de IPs únicos para o template
        IPdata=IPdata
    )


@app.route('/test')
def index2():
    return render_template('index.html')

@app.route('/data')
def get_data():
    return jsonify(data)

@app.route('/stats')
def get_stats():
    try:
        anomalous_ips = detect_anomalous_ips()
        num_anomalous_ips = len(anomalous_ips)
        num_blocked_ips = block_anomalous_ips(anomalous_ips)
        total_requests = sum(total_counts.values())
        num_unique_ips = len(data)

        IPdata = []
        for ip, counts in data.items():
            total = total_counts[ip]
            total_30s = sum(counts)
            maligno = "Sim" if ip in anomalous_ips else "Não"
            IPdata.append({
                "ip": ip,
                "num_packets": total,
                "num_packets_30s": total_30s,
                "maligno": maligno
            })

        response = ({
            "total_requests": total_requests,
            "num_unique_ips": num_unique_ips,
            "num_anomalous_ips": num_anomalous_ips,
            "num_blocked_ips": num_blocked_ips,
            "IPdata": IPdata
        })
        

        return jsonify(response)
    except Exception as e:
        log.exception("Erro ao gerar /stats")
        return jsonify({"error": str(e)}), 500
    
if __name__ == '__main__':
    threading.Thread(target=capture_packets, daemon=True).start()
    app.run(debug=True, host='0.0.0.0')
