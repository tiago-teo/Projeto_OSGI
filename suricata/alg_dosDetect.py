import json
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
import subprocess

def detect_anomalous_ips(log_file='/var/log/suricata/eve.json', contamination=0.03, min_packets=100):
    data = []

    # Leitura do arquivo de logs
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alert = event.get('alert', {})
                    data.append({
                        'timestamp': event.get('timestamp'),
                        'src_ip': event.get('src_ip'),
                        'dest_ip': event.get('dest_ip'),
                        'proto': event.get('proto'),
                        'signature': alert.get('signature'),
                        'sid': alert.get('signature_id'),
                    })
            except json.JSONDecodeError:
                continue

    df = pd.DataFrame(data)
    if df.empty:
        return []

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by=['src_ip', 'timestamp'])
    df['delta'] = df.groupby('src_ip')['timestamp'].diff().dt.total_seconds()
    df = df.dropna()

    # Tempo por minuto e segundo
    df['time_interval'] = df['timestamp'].dt.floor('min')
    df['time_bucket'] = df['timestamp'].dt.floor('s')

    packets_per_interval = df['time_interval'].value_counts().sort_index()
    df['count_interval'] = df['time_interval'].map(packets_per_interval)

    packets_per_second = df.groupby(['src_ip', 'time_bucket']).size().reset_index(name='pps')
    df = df.merge(packets_per_second, on=['src_ip', 'time_bucket'], how='left')

    le_sid = LabelEncoder()
    df['sid'] = le_sid.fit_transform(df['sid'])

    le_time = LabelEncoder()
    df['time_interval'] = le_time.fit_transform(df['time_interval'])

    # Agregações nomeadas com nomes fixos
    agg_df = df.groupby('src_ip').agg(
        sid_count=('sid', 'count'),
        count_interval_mean=('count_interval', 'mean'),
        count_interval_max=('count_interval', 'max'),
        delta_mean=('delta', 'mean'),
        delta_std=('delta', 'std'),
        pps_max=('pps', 'max')
    ).reset_index()

    # Proporções por sid
    for sid_code in df['sid'].unique():
        df[f'sid_{sid_code}'] = (df['sid'] == sid_code).astype(int)
    sid_props = df.groupby('src_ip')[[f'sid_{sid}' for sid in df['sid'].unique()]].mean().reset_index()
    agg_df = agg_df.merge(sid_props, on='src_ip')

    # Normalização e modelo
    X = agg_df.drop(columns=['src_ip'])
    if len(X) < 5 or agg_df['src_ip'].nunique() < 3:
        print("[DETECÇÃO] Dados insuficientes para deteção.")
        return []

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(contamination=contamination, random_state=42)
    clf.fit(X_scaled)
    agg_df['anomaly_score'] = clf.decision_function(X_scaled)
    agg_df['is_anomaly'] = clf.predict(X_scaled)

    # Filtrar IPs anômalos com pacotes suficientes
    anomalous_ips = agg_df[
        (agg_df['is_anomaly'] == -1) &
        (agg_df['sid_count'] > min_packets)
    ]['src_ip'].tolist()

    return anomalous_ips

def block_anomalous_ips(anomalous_ips):
    num_blocked_ips = 0
    for ip in anomalous_ips:
        #Verificar se já está bloqueado
        num_blocked_ips += 1
        result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            print(f"[FIREWALL] IP {ip} já está bloqueado.")
            continue

        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"[FIREWALL] IP {ip} bloqueado com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"[ERRO] Ao tentar bloquear o IP {ip}: {e}")
        
    return num_blocked_ips

if __name__ == "__main__":
    anomalous_ips = detect_anomalous_ips()
    if anomalous_ips:
        print(f"[DETECÇÃO] IPs anômalos detectados: {anomalous_ips}")
        block_anomalous_ips(anomalous_ips)
    else:
        print("[DETECÇÃO] Nenhum IP anômalo detetado.")
