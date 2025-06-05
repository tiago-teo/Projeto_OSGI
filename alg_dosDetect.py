import json
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest

def detect_anomalous_ips(log_file='logs/eve.json', contamination=0.1):
    data = []

    # Leitura do arquivo
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

    # Conversão em DataFrame
    df = pd.DataFrame(data)
    if df.empty:
        return []

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by=['src_ip', 'timestamp'])

    # Cálculo do delta de tempo
    df['delta'] = df.groupby('src_ip')['timestamp'].diff().dt.total_seconds()
    df = df.dropna()

    # Agrupamentos por intervalos de tempo
    df['time_interval'] = df['timestamp'].dt.floor('min')
    packets_per_interval = df['time_interval'].value_counts().sort_index()
    df['count_interval'] = df['time_interval'].map(packets_per_interval)

    # Agrupamento por segundo para cálculo de pps
    df['time_bucket'] = df['timestamp'].dt.floor('S')
    packets_per_second = df.groupby(['src_ip', 'time_bucket']).size().reset_index(name='pps')
    df = df.merge(packets_per_second, on=['src_ip', 'time_bucket'], how='left')

    # Encoding de variáveis categóricas
    le_sid = LabelEncoder()
    df['sid'] = le_sid.fit_transform(df['sid'])

    le_time = LabelEncoder()
    df['time_interval'] = le_time.fit_transform(df['time_interval'])

    # Agregações por src_ip
    agg_df = df.groupby('src_ip').agg({
        'sid': 'count',
        'count_interval': ['mean', 'max'],
        'delta': ['mean', 'std'],
        'pps': 'max',
    })
    agg_df.columns = ['_'.join(col) for col in agg_df.columns]
    agg_df.reset_index(inplace=True)

    # Proporções por sid
    for sid_code in df['sid'].unique():
        df[f'sid_{sid_code}'] = (df['sid'] == sid_code).astype(int)
    sid_props = df.groupby('src_ip')[[f'sid_{sid}' for sid in df['sid'].unique()]].mean().reset_index()
    agg_df = agg_df.merge(sid_props, on='src_ip')

    # Feature matrix
    X = agg_df.drop(columns=['src_ip'])

    # Normalização
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Detecção de anomalias
    clf = IsolationForest(contamination=contamination, random_state=42)
    clf.fit(X_scaled)
    agg_df['anomaly_score'] = clf.decision_function(X_scaled)
    agg_df['is_anomaly'] = clf.predict(X_scaled)

    # Retorna IPs anômalos
    anomalous_ips = agg_df[agg_df['is_anomaly'] == -1]['src_ip'].tolist()
    return anomalous_ips

