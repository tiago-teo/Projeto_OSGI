from flask import Flask, jsonify, render_template
from collections import defaultdict
import subprocess
import threading
import time
import re

app = Flask(__name__)
data = defaultdict(list)  # {ip: [count1, count2, ...]}
ip_regex = re.compile(r'IP (\d+\.\d+\.\d+\.\d+)\.\d+ >')

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def get_data():
    return jsonify(data)

if __name__ == '__main__':
    threading.Thread(target=capture_packets, daemon=True).start()
    app.run(debug=True, host='0.0.0.0')
