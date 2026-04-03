import os
import io
import csv
import json
import datetime
import ipaddress
import random
import shutil
import threading
import time
import socket
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
import pandas as pd
import numpy as np
import joblib
import psutil

# ── Scapy (optional — needs Npcap on Windows) ───────────────────────────────
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    conf.verb = 0       # Suppress scapy warnings
    SCAPY_AVAILABLE = True
    print("[OK] Scapy loaded - packet-level capture available")
except ImportError:
    print("[WARN] Scapy not installed - using psutil fallback")

app = Flask(__name__)
app.secret_key = 'ids_ml_secret_key_2026'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
ACTIVE_MODEL_FILE = os.path.join(MODELS_DIR, 'active_model.json')
LATEST_UPLOAD_EXPORT_FILE = os.path.join(BASE_DIR, 'latest_upload_full_results.csv')

# ── Model ─────────────────────────────────────────────────────────────────────
MODEL = None
FEATURE_NAMES = None
MODEL_METRICS = {}
MODEL_DATASET_NAME = ''
MODEL_DATASET_KEY = ''

# ── Storage ───────────────────────────────────────────────────────────────────
analysis_results = []
latest_upload_export_rows = 0
live_monitoring_active = False
live_monitor_thread = None
training_status = {'running': False, 'progress': 0, 'message': '', 'metrics': None}
live_log_buffer = []        # Terminal log lines
live_flow_results = {}
live_session_results = []
live_result_counter = 0
live_stats = {'total_packets': 0, 'total_flows': 0, 'threats': 0, 'normal': 0,
              'start_time': None, 'last_event': '', 'capture_mode': ''}

# ── Algorithm Info ────────────────────────────────────────────────────────────
ALGORITHMS = {
    'random_forest': {
        'name': 'Random Forest', 'icon': 'bi-tree', 'color': 'danger',
        'badge': 'Ensemble',
        'description': 'Builds many decision trees on random subsets, combines votes. Reduces overfitting.',
        'use': 'Trained and evaluated for comparison.',
    },
    'decision_tree': {
        'name': 'Decision Tree', 'icon': 'bi-diagram-3', 'color': 'warning',
        'badge': 'Interpretable',
        'description': 'Single tree of yes/no questions. Easy to trace why a packet was flagged.',
        'use': 'Trained and evaluated for comparison.',
    },
    'xgboost': {
        'name': 'XGBoost', 'icon': 'bi-stars', 'color': 'success',
        'badge': 'Primary Model',
        'description': 'Gradient-boosted trees — each tree corrects previous errors. Best accuracy.',
        'use': 'Saved as the primary model for all predictions.',
    },
}

# ── Datasets ──────────────────────────────────────────────────────────────────
DATASETS = {
    'ciciot23': {
        'name': 'CIC-IoT23 Dataset',
        'files': ['Merged01.csv', 'Merged02.csv'],
        'description': 'CIC-IoT23 is the only in-scope dataset for this prototype. It is used to build a balanced Benign-vs-Attack model.',
        'label_col': 'Label',
        'benign_labels': ['benigntraffic', 'normal', 'benign'],
        'drop_cols': [],
        'feature_count': 39,
        'feature_selection': '39 selected CIC-IoT23 numeric flow features are retained, then SMOTE creates a balanced training set before model fitting.',
    }
}


CICIOT23_FEATURES = [
    'Header_Length', 'Protocol Type', 'Time_To_Live', 'Rate', 'fin_flag_number',
    'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count',
    'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
    'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max',
    'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance'
]

def ensure_models_dir():
    os.makedirs(MODELS_DIR, exist_ok=True)


def model_artifact_paths(dataset_key):
    return {
        'model': os.path.join(MODELS_DIR, f'xgb_model_{dataset_key}.pkl'),
        'features': os.path.join(MODELS_DIR, f'feature_names_{dataset_key}.pkl'),
        'metrics': os.path.join(MODELS_DIR, f'model_metrics_{dataset_key}.json'),
    }


def save_active_model_key(dataset_key):
    ensure_models_dir()
    with open(ACTIVE_MODEL_FILE, 'w') as f:
        json.dump({'dataset_key': dataset_key}, f)


def load_active_model_key():
    try:
        with open(ACTIVE_MODEL_FILE, 'r') as f:
            data = json.load(f)
            return data.get('dataset_key')
    except Exception:
        return None


def migrate_legacy_model_files():
    ensure_models_dir()
    legacy_model = os.path.join(BASE_DIR, 'xgb_model.pkl')
    legacy_features = os.path.join(BASE_DIR, 'feature_names.pkl')
    legacy_metrics = os.path.join(BASE_DIR, 'model_metrics.json')
    if not (os.path.exists(legacy_model) and os.path.exists(legacy_features)):
        return

    dataset_key = 'ciciot23'
    if os.path.exists(legacy_metrics):
        try:
            with open(legacy_metrics, 'r') as f:
                metrics = json.load(f)
            dataset_key = metrics.get('meta', {}).get('dataset_key', dataset_key)
        except Exception:
            pass

    paths = model_artifact_paths(dataset_key)
    if not os.path.exists(paths['model']):
        shutil.copyfile(legacy_model, paths['model'])
    if not os.path.exists(paths['features']):
        shutil.copyfile(legacy_features, paths['features'])
    if os.path.exists(legacy_metrics) and not os.path.exists(paths['metrics']):
        shutil.copyfile(legacy_metrics, paths['metrics'])
    if not load_active_model_key():
        save_active_model_key(dataset_key)


def get_trained_models_info():
    ensure_models_dir()
    trained = {}
    for key, ds in DATASETS.items():
        paths = model_artifact_paths(key)
        is_trained = all(os.path.exists(paths[name]) for name in ('model', 'features', 'metrics'))
        entry = {
            'trained': is_trained,
            'name': ds['name'],
            'dataset_key': key,
            'feature_count': ds['feature_count'],
            'metrics': None,
        }
        if is_trained:
            try:
                with open(paths['metrics'], 'r') as f:
                    entry['metrics'] = json.load(f)
            except Exception:
                entry['metrics'] = None
        trained[key] = entry
    return trained


def get_active_dataset_info():
    if MODEL_DATASET_KEY and MODEL_DATASET_KEY in DATASETS:
        return MODEL_DATASET_KEY, DATASETS[MODEL_DATASET_KEY]
    return None, None


def load_model(dataset_key=None):
    global MODEL, FEATURE_NAMES, MODEL_METRICS, MODEL_DATASET_NAME, MODEL_DATASET_KEY
    ensure_models_dir()
    migrate_legacy_model_files()

    if dataset_key is None:
        dataset_key = load_active_model_key()

    if not dataset_key or dataset_key not in DATASETS:
        trained_models = get_trained_models_info()
        dataset_key = next((key for key, info in trained_models.items() if info['trained']), None)

    MODEL = None
    FEATURE_NAMES = None
    MODEL_METRICS = {}
    MODEL_DATASET_NAME = ''
    MODEL_DATASET_KEY = ''

    if not dataset_key:
        print("[WARN] No trained dataset models found. Train a dataset first.")
        return False

    paths = model_artifact_paths(dataset_key)
    try:
        MODEL = joblib.load(paths['model'])
        FEATURE_NAMES = joblib.load(paths['features'])
        with open(paths['metrics'], 'r') as f:
            MODEL_METRICS = json.load(f)
        MODEL_DATASET_KEY = dataset_key
        MODEL_DATASET_NAME = MODEL_METRICS.get('meta', {}).get('dataset', DATASETS[dataset_key]['name'])
        save_active_model_key(dataset_key)
        print(f"[OK] Model loaded for {MODEL_DATASET_NAME}. Features: {len(FEATURE_NAMES)}")
        return True
    except FileNotFoundError as e:
        print(f"[WARN] {e}. Train the {DATASETS[dataset_key]['name']} model first.")
    except Exception as e:
        print(f"[WARN] Could not load model for {dataset_key}: {e}")
    return False


load_model()


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def get_network_info():
    """Detect network interfaces, IPs, and identify WSL."""
    info = {'interfaces': [], 'primary_ip': '', 'wsl_ip': '', 'wsl_iface': ''}
    primary_candidates = []

    def primary_rank(iface_name, ip_address):
        lname = iface_name.lower()
        rank = 0
        if ip_address.startswith('169.254.'):
            rank += 60
        if 'wsl' in lname or 'vethernet' in lname:
            rank += 50
        if 'local area connection' in lname:
            rank += 25
        if 'virtual' in lname or 'vmware' in lname or 'hyper-v' in lname:
            rank += 20
        if 'wi-fi' in lname or 'wifi' in lname:
            rank -= 20
        elif lname == 'ethernet':
            rank -= 10
        return rank

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                entry = {'name': iface, 'ip': addr.address}
                info['interfaces'].append(entry)
                if 'wsl' in iface.lower() or 'vethernet' in iface.lower():
                    info['wsl_ip'] = addr.address
                    info['wsl_iface'] = iface
                else:
                    primary_candidates.append((primary_rank(iface, addr.address), addr.address))
    for _, ip in sorted(primary_candidates, key=lambda item: item[0]):
        if not ip.startswith('169.254.'):
            info['primary_ip'] = ip
            break
    if not info['primary_ip'] and primary_candidates:
        info['primary_ip'] = sorted(primary_candidates, key=lambda item: item[0])[0][1]
    if not info['primary_ip'] and info['interfaces']:
        info['primary_ip'] = info['interfaces'][0]['ip']
    return info


def get_attack_commands(target_ip='<YOUR_TARGET_IP>'):
    """Generate display-only command examples with a replaceable target placeholder."""
    return [
        {'name': 'Port Scan',       'cmd': f'sudo nmap -sS -T4 -p 1-100 {target_ip}', 'win_cmd': f'nmap -sS -T4 -p 1-100 {target_ip}'},
        {'name': 'Fast Port Scan',  'cmd': f'sudo hping3 -S -p ++1-50 {target_ip}', 'win_cmd': f'nping --tcp -p 1-50 {target_ip}'},
        {'name': 'Service Exploit', 'cmd': f'sudo hping3 -S -c 20 -p 445 {target_ip}', 'win_cmd': f'nping --tcp -c 20 -p 445 {target_ip}'},
        {'name': 'Botnet C&C',      'cmd': f'for i in {{1..10}}; do nc {target_ip} 6667 & done', 'win_cmd': f'for /L %i in (1,1,10) do start ncat {target_ip} 6667'},
        {'name': 'Brute Force',     'cmd': f'sudo hping3 -S -c 50 -i u10000 -p 22 {target_ip}', 'win_cmd': f'nping --tcp -c 50 --delay 10ms -p 22 {target_ip}'},
        {'name': 'DDoS Attack',     'cmd': f'sudo hping3 -S --flood -p 80 {target_ip}', 'win_cmd': f'nping --tcp -p 80 --rate 1000 {target_ip}'},
    ]


def get_windows_test_commands(target_ip):
    """Generate Windows-safe traffic commands for validating host-side capture."""
    return [
        {'name': 'Ping Burst',      'cmd': f'ping -n 20 {target_ip}'},
        {'name': 'Port Check 80',   'cmd': f'powershell -Command "Test-NetConnection {target_ip} -Port 80"'},
        {'name': 'Port Check 445',  'cmd': f'powershell -Command "Test-NetConnection {target_ip} -Port 445"'},
        {'name': 'HTTP Request',    'cmd': f'powershell -Command "try {{ Invoke-WebRequest http://{target_ip} -UseBasicParsing }} catch {{ $_.Exception.Message }}"'},
        {'name': 'Repeated Checks', 'cmd': f'for /L %i in (1,1,10) do powershell -Command "Test-NetConnection {target_ip} -Port 80 | Out-Null"'},
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET CAPTURE & FLOW ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PORTS = {23, 2323, 5555, 7547, 37215, 8291, 6379, 11211, 6667, 445, 139}
EPHEMERAL_PORT_START = 32768
KNOWN_SAFE_PORTS = {80, 443, 8080, 53, 993, 587, 465, 143, 110, 995}
FLOW_WINDOW_SECONDS = 12
packet_buffer = []                 # Raw captured packets
packet_buffer_lock = threading.Lock()


def is_ignored_remote_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_multicast or addr.is_unspecified
    except ValueError:
        return False


def get_capture_interfaces(net_info):
    """Pick the interfaces Scapy should listen on for host + WSL traffic."""
    if not SCAPY_AVAILABLE:
        return []

    available = []
    for iface in conf.ifaces.values():
        name = getattr(iface, 'name', '')
        if name and name not in available:
            available.append(name)

    selected = []
    for entry in net_info['interfaces']:
        if entry['name'] in available and entry['name'] not in selected:
            selected.append(entry['name'])

    for name in available:
        lname = name.lower()
        if ('loopback' in lname or 'wsl' in lname or 'vethernet' in lname) and name not in selected:
            selected.append(name)

    return selected or available


def packet_flow_key(pkt, my_ips):
    src_is_local = pkt['src_ip'] in my_ips
    dst_is_local = pkt['dst_ip'] in my_ips

    if src_is_local and not dst_is_local:
        remote_ip = pkt['dst_ip']
        direction = 'outgoing'
    elif dst_is_local and not src_is_local:
        remote_ip = pkt['src_ip']
        direction = 'incoming'
    elif src_is_local and dst_is_local:
        remote_ip = pkt['dst_ip']
        direction = 'internal'
    else:
        return None

    if is_ignored_remote_ip(remote_ip):
        return None

    return direction, remote_ip


def next_live_result_id():
    global live_result_counter
    live_result_counter += 1
    return live_result_counter


def describe_live_result(direction, attack_type, remote_ip):
    if direction == 'outgoing':
        connector = 'to'
    elif direction == 'incoming':
        connector = 'from'
    else:
        connector = 'on'
    return f'{attack_type} {connector} {remote_ip}'


def infer_live_attack_type(flow):
    target_ports = flow.get('target_ports', set())
    local_ports = flow.get('local_ports', set())
    remote_ports = flow.get('remote_ports', set())
    service_ports = {p for p in (target_ports | local_ports | remote_ports) if p and p < EPHEMERAL_PORT_START}
    n = len(flow['times'])
    duration = max(flow['times']) - min(flow['times']) if n > 1 else 0.0
    rate = n / max(duration, 0.001)

    if len(service_ports) > 10:
        return 'Port Scanning'
    if 22 in service_ports and flow['syn'] > 10 and flow['ack'] < 2:
        return 'Brute Force'
    if service_ports & SUSPICIOUS_PORTS:
        return 'Service Exploit'
    if flow.get('direction') in {'outgoing', 'internal'} and flow['syn'] > 10 and flow['ack'] > 10 and service_ports:
        return 'Service Exploit'
    if flow['icmp_count'] > 20 or (flow['syn'] > 10 and rate > 50):
        return 'DDoS Attack'
    return 'Suspicious Activity'


def combine_live_verdict(flow, heur, ml):
    ports = flow.get('target_ports', set())
    low_target_ports = {p for p in ports if p and p < EPHEMERAL_PORT_START}
    ephemeral_target_ports = {p for p in ports if p >= EPHEMERAL_PORT_START}
    reasons = list(heur['reasons'])
    prediction = 'Attack' if heur['is_attack'] else 'Normal'
    attack_type = heur['attack_type']
    confidence = heur['confidence']

    # Incoming reply traffic to many ephemeral local ports is common client behavior
    # and should not be promoted to "Port Scanning" by the ML fallback alone.
    if flow.get('direction') == 'incoming' and len(ephemeral_target_ports) >= 8 and not low_target_ports and flow['ack'] >= flow['syn']:
        reasons.append('reply traffic to ephemeral local ports')
        return {
            'prediction': 'Normal',
            'attack_type': 'Normal',
            'confidence': max(float(confidence), 75.0),
            'reasons': reasons,
        }

    if ml is not None:
        if ml['prediction'] == 'Attack' and (heur['is_attack'] or heur['score'] >= 35 or len(low_target_ports) > 8):
            prediction = 'Attack'
            confidence = max(confidence, ml['confidence'])
            if attack_type == 'Normal':
                attack_type = infer_live_attack_type(flow)
            reasons.append(f"ML confirmed ({ml['confidence']}%)")
        elif ml['prediction'] == 'Normal' and prediction == 'Normal':
            confidence = max(confidence, ml['confidence'])

    if prediction == 'Normal':
        attack_type = 'Normal'
        if not reasons:
            reasons.append('Normal traffic')
    elif attack_type == 'Normal':
        attack_type = infer_live_attack_type(flow)

    return {
        'prediction': prediction,
        'attack_type': attack_type,
        'confidence': min(float(confidence), 99.9),
        'reasons': reasons,
    }


def scapy_packet_callback(pkt):
    """Called for every captured packet by scapy."""
    global packet_buffer
    if not live_monitoring_active:
        return
    if IP in pkt:
        info = {
            'time': time.time(),
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'proto': pkt[IP].proto,
            'size': len(pkt),
            'ip_hdr_len': pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20,
            'ttl': pkt[IP].ttl,
            'tcp_flags': int(pkt[TCP].flags) if TCP in pkt else 0,
            'sport': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dport': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
        }
        with packet_buffer_lock:
            if len(packet_buffer) < 5000:  # Prevent memory exhaustion during flood attacks
                packet_buffer.append(info)


def aggregate_flows(packets, my_ips):
    """Group packets into directional flows around the local machine."""
    flows = {}
    for pkt in packets:
        key = packet_flow_key(pkt, my_ips)
        if key is None:
            continue

        direction, remote_ip = key
        if direction == 'outgoing':
            local_ip = pkt['src_ip']
            local_port = pkt['sport']
            remote_port = pkt['dport']
        elif direction == 'incoming':
            local_ip = pkt['dst_ip']
            local_port = pkt['dport']
            remote_port = pkt['sport']
        else:
            local_ip = pkt['src_ip']
            local_port = pkt['sport']
            remote_port = pkt['dport']

        if key not in flows:
            flows[key] = {
                'src_ip': pkt['src_ip'],
                'dst_ip': pkt['dst_ip'],
                'remote_ip': remote_ip,
                'local_ip': local_ip,
                'direction': direction,
                'times': [], 'sizes': [],
                'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0, 'ece': 0,
                'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0,
                'target_ports': set(), 'local_ports': set(), 'remote_ports': set(), 'ttls': [],
            }
        f = flows[key]
        f['times'].append(pkt['time'])
        f['sizes'].append(pkt['size'])
        f['target_ports'].add(pkt['dport'])
        if local_port:
            f['local_ports'].add(local_port)
        if remote_port:
            f['remote_ports'].add(remote_port)
        f['ttls'].append(pkt['ttl'])
        flags = pkt['tcp_flags']
        if flags:
            if flags & 0x02: f['syn'] += 1
            if flags & 0x10: f['ack'] += 1
            if flags & 0x01: f['fin'] += 1
            if flags & 0x04: f['rst'] += 1
            if flags & 0x08: f['psh'] += 1
            if flags & 0x40: f['ece'] += 1
        if pkt['proto'] == 6:
            f['tcp_count'] += 1
        elif pkt['proto'] == 17:
            f['udp_count'] += 1
        elif pkt['proto'] == 1:
            f['icmp_count'] += 1
    return flows


def extract_flow_features(flow, feature_names):
    """Map flow statistics to model feature vector for ML prediction."""
    n = len(flow['times'])
    if n == 0:
        return None

    sizes = flow['sizes']
    times = flow['times']
    duration = max(times) - min(times) if n > 1 else 0.001
    total = sum(sizes)
    rate = n / max(duration, 0.001)

    # Size stats
    mn = min(sizes)
    mx = max(sizes)
    avg = np.mean(sizes)
    std = float(np.std(sizes)) if n > 1 else 0

    # IAT
    if n > 1:
        iats = [times[i+1] - times[i] for i in range(n-1)]
        iat = np.mean(iats) * 1000  # ms
    else:
        iat = 0

    service_ports = flow.get('target_ports', set()) | flow.get('remote_ports', set())
    ttl = int(np.mean(flow['ttls'])) if flow['ttls'] else 64

    feature_map = {
        'syn_flag_number': flow['syn'] / n,
        'ack_flag_number': flow['ack'] / n,
        'fin_flag_number': flow['fin'] / n,
        'rst_flag_number': flow['rst'] / n,
        'psh_flag_number': flow['psh'] / n,
        'ece_flag_number': flow['ece'] / n,
        'cwr_flag_number': 0,
        'ack_count': flow['ack'],
        'syn_count': flow['syn'],
        'fin_count': flow['fin'],
        'rst_count': flow['rst'],
        'Rate': rate,
        'Srate': rate * 0.6,
        'Drate': rate * 0.4,
        'Tot sum': total,
        'Tot size': total,
        'Min': mn, 'Max': mx, 'AVG': avg, 'Std': std,
        'IAT': iat,
        'Number': n,
        'Duration': duration,
        'Header_Length': 40,
        'Protocol Type': 6 if flow['tcp_count'] >= flow['udp_count'] else 17,
        'Time_To_Live': ttl,
        'HTTP': 1 if (80 in service_ports or 8080 in service_ports) else 0,
        'HTTPS': 1 if 443 in service_ports else 0,
        'DNS': 1 if 53 in service_ports else 0,
        'Telnet': 1 if 23 in service_ports else 0,
        'SSH': 1 if 22 in service_ports else 0,
        'SMTP': 1 if 25 in service_ports else 0,
        'IRC': 1 if 6667 in service_ports else 0,
        'TCP': flow['tcp_count'] / n,
        'UDP': flow['udp_count'] / n,
        'ICMP': flow['icmp_count'] / n,
        'DHCP': 0, 'ARP': 0, 'IGMP': 0, 'IPv': 1, 'LLC': 0,
        'Magnitude': np.sqrt(total * rate) if total > 0 else 0,
        'Radius': std,
        'Covariance': 0,
        'Variance': std ** 2,
        'Weight': n * avg if avg > 0 else 0,
    }

    row = {}
    for fname in feature_names:
        row[fname] = feature_map.get(fname, 0)
    return row


def heuristic_analysis(flow):
    """Heuristic threat scoring based on flow patterns."""
    n = len(flow['times'])
    score = 0
    reasons = []
    ports = flow.get('target_ports', set())
    local_ports = flow.get('local_ports', set())
    remote_ports = flow.get('remote_ports', set())
    ephemeral_target_ports = {p for p in ports if p >= EPHEMERAL_PORT_START}
    low_target_ports = {p for p in ports if p and p < EPHEMERAL_PORT_START}
    service_ports = {p for p in (ports | local_ports | remote_ports) if p and p < EPHEMERAL_PORT_START}

    # SYN flood / scan indicators
    if flow['syn'] > 5 and flow['ack'] < 2:
        score += 60
        reasons.append(f"{flow['syn']} SYN w/o ACK")
    elif flow['syn'] > 3:
        score += 30
        reasons.append(f"{flow['syn']} SYN packets")

    # Many unique ports targeted = port scan
    if len(low_target_ports) > 20:
        score += 60
        reasons.append(f"{len(low_target_ports)} service ports targeted (scan)")
    elif len(low_target_ports) > 10:
        score += 30
        reasons.append(f"{len(low_target_ports)} service ports targeted")

    # Suspicious ports
    sus = service_ports & SUSPICIOUS_PORTS
    if sus:
        score += 40
        reasons.append(f"suspicious port(s): {', '.join(str(p) for p in sorted(sus)[:4])}")

    # WSL-to-host probes are often observed on Windows as repeated SYN-ACK replies
    # from a local service port back to the WSL guest.
    if flow.get('direction') in {'outgoing', 'internal'} and flow['syn'] > 10 and flow['ack'] > 10 and sus:
        score += 45
        reasons.append('repeated SYN-ACK replies from local service')

    # High packet rate (only relevant for sustained flows)
    duration = max(flow['times']) - min(flow['times']) if n > 1 else 0.0
    rate = n / duration if duration > 0.01 else 0.0
    if rate > 500 and n > 20:
        score += 60
        reasons.append(f"extreme rate {rate:.0f}pps")
    elif rate > 100 and n > 10:
        score += 30
        reasons.append(f"high rate {rate:.0f}pps")

    # Many RST = connection reset flood
    if flow['rst'] > 5:
        score += 25
        reasons.append(f"{flow['rst']} RSTs")

    # ICMP flood
    if flow['icmp_count'] > 10:
        score += 35
        reasons.append(f"{flow['icmp_count']} ICMP")

    # Incoming replies to many ephemeral local ports often come from normal client traffic.
    if flow.get('direction') == 'incoming' and len(ephemeral_target_ports) >= 8 and not low_target_ports and flow['ack'] >= flow['syn']:
        score -= 40
        reasons.append("incoming reply traffic to ephemeral local ports")

    # Normal patterns reduce score
    safe = (service_ports | remote_ports) & KNOWN_SAFE_PORTS
    safe_service_flow = safe and not sus and len(ports) <= 3
    one_sided_syn_burst = flow['syn'] > 10 and flow['ack'] < 2

    if safe_service_flow and not one_sided_syn_burst:
        score -= 35
        reasons.append("known safe service traffic")

    if flow.get('direction') == 'incoming' and safe and flow['ack'] >= flow['syn']:
        score -= 15

    if 22 in ports and flow['syn'] > 10 and flow['ack'] < 2:
        score += 25
        reasons.append("repeated SSH attempts")

    is_attack = score >= 60

    if is_attack:
        if len(service_ports) > 10:
            atype = 'Port Scanning'
        elif 22 in service_ports and flow['syn'] > 10 and flow['ack'] < 2:
            atype = 'Brute Force'
        elif sus or (flow.get('direction') in {'outgoing', 'internal'} and flow['syn'] > 10 and flow['ack'] > 10):
            atype = 'Service Exploit'
        elif flow['syn'] > 10 and rate > 100:
            atype = 'DDoS Attack'
        elif flow['syn'] > 5 and rate > 50:
            atype = 'DDoS Attack'
        elif flow['icmp_count'] > 20:
            atype = 'DDoS Attack'
        else:
            atype = 'Suspicious Activity'
    else:
        atype = 'Normal'

    conf = min(max(score, 0), 99) if is_attack else min(max(100 - score, 50), 99)

    return {
        'is_attack': is_attack,
        'attack_type': atype,
        'confidence': conf,
        'reasons': reasons,
        'score': score,
    }


def ml_prediction_on_flow(flow):
    """Run ML model on flow features. Returns prediction dict or None."""
    if MODEL is None or FEATURE_NAMES is None:
        return None
    if len(flow['times']) < 3:
        return None
    features = extract_flow_features(flow, FEATURE_NAMES)
    if features is None:
        return None
    try:
        df = pd.DataFrame([features])
        df = df.replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        pred = MODEL.predict(df)[0]
        prob = MODEL.predict_proba(df)[0]
        confidence = round(float(prob[1]) * 100, 1) if pred == 1 else round(float(prob[0]) * 100, 1)
        return {
            'prediction': 'Attack' if pred == 1 else 'Normal',
            'confidence': min(confidence, 99.9),
        }
    except Exception as e:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING THREAD
# ═══════════════════════════════════════════════════════════════════════════════

def monitoring_loop():
    """Main monitoring loop — captures packets (or connections), analyzes flows."""
    global live_monitoring_active, packet_buffer, live_stats, live_log_buffer, analysis_results, live_flow_results, live_session_results

    net_info = get_network_info()
    my_ips = set(e['ip'] for e in net_info['interfaces'])
    my_ips.add('127.0.0.1')
    capture_ifaces = get_capture_interfaces(net_info) if SCAPY_AVAILABLE else []
    rolling_packets = []

    live_stats['start_time'] = time.time()
    live_stats['capture_mode'] = 'scapy' if SCAPY_AVAILABLE else 'psutil'

    add_log('🚀 Starting enhanced monitoring...', 'green')
    add_log(f'📡 Capture mode: {"Scapy (packet-level)" if SCAPY_AVAILABLE else "psutil (connection-level)"}', 'blue')
    if capture_ifaces:
        add_log(f'🧭 Listening on {len(capture_ifaces)} interface(s)', 'blue')
    add_log(f'🌐 Network Interfaces:', 'yellow')
    for iface in net_info['interfaces']:
        marker = ' ← Primary' if iface['ip'] == net_info['primary_ip'] else ''
        marker = ' ← WSL' if iface['ip'] == net_info['wsl_ip'] else marker
        add_log(f'   {iface["name"]}: {iface["ip"]}{marker}', 'white')

    add_log(f'', 'white')
    add_log(f'💡 Attack Commands (Linux vs Windows equivalents):', 'yellow')
    add_log('   Replace <YOUR_TARGET_IP> with the current host IP shown in the interface list above.', 'gray')
    for ac in get_attack_commands():
        add_log(f'   {ac["name"]:15s} (L): {ac["cmd"]}', 'cyan')
        add_log(f'   {"":15s} (W): {ac["win_cmd"]}', 'green')

    add_log(f'', 'white')
    add_log(f'🔥 Monitoring started. Press Stop to end.', 'green')
    add_log(f'{"=" * 65}', 'gray')

    while live_monitoring_active:
        try:
            cycle_started_at = time.time()
            if SCAPY_AVAILABLE:
                with packet_buffer_lock:
                    packet_buffer.clear()
                try:
                    sniff_args = {'prn': scapy_packet_callback, 'timeout': 1, 'store': 0}
                    if capture_ifaces:
                        sniff_args['iface'] = capture_ifaces
                    sniff(**sniff_args)
                except Exception as e:
                    add_log(f'⚠ Capture error: {e}', 'red')
                    time.sleep(1)
                    continue

                with packet_buffer_lock:
                    captured = list(packet_buffer)

                if not captured:
                    cutoff = cycle_started_at - FLOW_WINDOW_SECONDS
                    rolling_packets = [pkt for pkt in rolling_packets if pkt['time'] >= cutoff]
                    for key in list(live_flow_results.keys()):
                        if live_flow_results[key].get('last_seen', 0) < cutoff:
                            live_flow_results.pop(key)
                    live_stats['total_flows'] = len(live_flow_results)
                    live_stats['threats'] = sum(1 for r in live_flow_results.values() if r['prediction'] == 'Attack')
                    live_stats['normal'] = sum(1 for r in live_flow_results.values() if r['prediction'] == 'Normal')
                    add_log(f'📡 No packets this cycle', 'gray')
                    continue

                live_stats['total_packets'] += len(captured)
            else:
                captured = psutil_capture_packets(my_ips)
                live_stats['total_packets'] += len(captured)
                time.sleep(1)

            rolling_packets.extend(captured)
            cutoff = cycle_started_at - FLOW_WINDOW_SECONDS
            rolling_packets = [pkt for pkt in rolling_packets if pkt['time'] >= cutoff]

            current_flows = aggregate_flows(captured, my_ips)
            if not current_flows:
                add_log(f'📡 {len(captured)} pkts captured — no host-related flows', 'gray')
                continue

            window_flows = aggregate_flows(rolling_packets, my_ips)
            batch_threats = 0
            batch_normal = 0

            for flow_key in current_flows:
                flow = window_flows.get(flow_key, current_flows[flow_key])
                n = len(flow['times'])
                heur = heuristic_analysis(flow)
                ml = ml_prediction_on_flow(flow)
                verdict = combine_live_verdict(flow, heur, ml)

                port_str = ', '.join(str(p) for p in sorted(list(flow['target_ports']))[:8]) or '—'
                flow_id = f'{flow["direction"]}:{flow["remote_ip"]}'
                existing = live_flow_results.get(flow_id, {})
                result = {
                    'id': existing.get('id', next_live_result_id()),
                    'ip_address': flow['remote_ip'],
                    'direction': flow['direction'],
                    'prediction': verdict['prediction'],
                    'attack_type': verdict['attack_type'],
                    'confidence': round(verdict['confidence'], 1),
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'source': 'Live Monitor',
                    'packets': n,
                    'ports': port_str,
                    'reason': '; '.join(verdict['reasons']),
                    'duration': '-',
                    'source_bytes': '-',
                    'download_bytes': '-',
                    'last_seen': cycle_started_at,
                }
                live_flow_results[flow_id] = result

                if verdict['prediction'] == 'Attack':
                    batch_threats += 1
                else:
                    batch_normal += 1

                state_changed = (
                    existing.get('prediction') != result['prediction'] or
                    existing.get('attack_type') != result['attack_type'] or
                    existing.get('ports') != result['ports']
                )
                history_entry = {k: v for k, v in result.items() if k != 'last_seen'}
                history_entry['id'] = len(analysis_results) + 1
                analysis_results.append(history_entry)
                live_session_results.append(history_entry.copy())

                if verdict['prediction'] == 'Attack' and (state_changed or existing.get('prediction') != 'Attack'):
                    summary = describe_live_result(flow['direction'], verdict['attack_type'], flow['remote_ip'])
                    add_log(f'🚨 THREAT: {summary} ({n} pkts, ports:{port_str})', 'red')
                    live_stats['last_event'] = summary

            for key in list(live_flow_results.keys()):
                if live_flow_results[key].get('last_seen', 0) < cutoff:
                    live_flow_results.pop(key)

            live_stats['total_flows'] = len(live_flow_results)
            live_stats['threats'] = sum(1 for r in live_flow_results.values() if r['prediction'] == 'Attack')
            live_stats['normal'] = sum(1 for r in live_flow_results.values() if r['prediction'] == 'Normal')

            pkt_count = len(captured)
            if batch_threats == 0:
                add_log(f'🔍 {pkt_count} pkts → {len(current_flows)} flows — all normal', 'green')
            else:
                add_log(f'🔍 {pkt_count} pkts → {len(current_flows)} flows — {batch_threats} threats, {batch_normal} normal', 'orange')

        except Exception as e:
            add_log(f'⚠ Error: {e}', 'red')
            time.sleep(3)

    add_log(f'⏹ Monitoring stopped.', 'yellow')


def psutil_capture_packets(my_ips):
    """Fallback: approximate active connections as packet events."""
    packets = []
    try:
        connections = psutil.net_connections(kind='inet')
    except:
        return packets

    now = time.time()
    for c in connections:
        if not c.raddr or not c.laddr:
            continue
        remote_ip = c.raddr.ip
        if remote_ip in my_ips or remote_ip.startswith(('127.', '0.0.', '::1')):
            continue

        tcp_flags = 0
        if c.status == 'SYN_SENT':
            tcp_flags = 0x02
        elif c.status == 'SYN_RECV':
            tcp_flags = 0x12
        elif c.status == 'ESTABLISHED':
            tcp_flags = 0x10
        elif c.status in ('FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'LAST_ACK', 'CLOSING'):
            tcp_flags = 0x01
        elif c.status in ('CLOSE_WAIT', 'CLOSED'):
            tcp_flags = 0x04

        if c.status == 'SYN_RECV':
            src_ip, dst_ip = remote_ip, c.laddr.ip
            sport, dport = c.raddr.port, c.laddr.port
        else:
            src_ip, dst_ip = c.laddr.ip, remote_ip
            sport, dport = c.laddr.port, c.raddr.port

        packets.append({
            'time': now,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': 6 if c.type == socket.SOCK_STREAM else 17,
            'size': 64,
            'ip_hdr_len': 20,
            'ttl': 64,
            'tcp_flags': tcp_flags,
            'sport': sport,
            'dport': dport,
        })

    return packets


def add_log(text, color='white'):
    """Add a line to the live monitoring console log."""
    live_log_buffer.append({'text': text, 'color': color, 'time': time.time()})
    while len(live_log_buffer) > 5000:
        live_log_buffer.pop(0)


# ═══════════════════════════════════════════════════════════════════════════════
# CLASSIFY (for CSV upload)
# ═══════════════════════════════════════════════════════════════════════════════

def classify_attack_type(row, prediction, confidence):
    if prediction == 0:
        return 'Normal'
    syn = float(row.get('syn_flag_number', row.get('Avg_syn_flag', 0)) or 0)
    fin = float(row.get('fin_flag_number', row.get('Avg_fin_flag', 0)) or 0)
    rst = float(row.get('rst_flag_number', row.get('Avg_rst_flag', 0)) or 0)
    psh = float(row.get('psh_flag_number', row.get('Avg_psh_flag', 0)) or 0)
    rate = float(row.get('Rate', row.get('Flow_Pkts/s', 0)) or 0)
    udp = float(row.get('UDP', row.get('Avg_UDP_pkt', 0)) or 0)
    ssh = float(row.get('SSH', 0) or 0)
    http = float(row.get('HTTP', 0) or 0)
    dns = float(row.get('DNS', row.get('Avg_DNS_pkt', 0)) or 0)
    scores = {'DDoS Attack': 0, 'Port Scanning': 0, 'Brute Force': 0,
              'Service Exploit': 0, 'DNS Spoofing': 0, 'MITM Attack': 0}
    if syn > 0.5: scores['DDoS Attack'] += 3; scores['Port Scanning'] += 1
    if syn > 0.5 and rate > 50: scores['DDoS Attack'] += 3
    if rate > 100: scores['DDoS Attack'] += 2
    if udp > 0.5: scores['DDoS Attack'] += 2
    if ssh > 0.5: scores['Brute Force'] += 3
    if rst > 0.5: scores['Brute Force'] += 2
    if http > 0.5 and psh > 0.3: scores['Service Exploit'] += 3
    if dns > 0.5: scores['DNS Spoofing'] += 3
    if fin > 0.3 and rst > 0.3: scores['MITM Attack'] += 2
    best = max(scores, key=scores.get)

    # Keep uncertain or weakly matched attack predictions in a generic bucket
    # instead of forcing them into a specific named attack type.
    if scores[best] <= 1:
        return 'Suspicious Activity'
    if confidence < 70 and scores[best] < 3:
        return 'Suspicious Activity'
    return best


def build_results(X_test, preds, probs, source='Upload', real_ips=None):
    results = []
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for i in range(len(preds)):
        row_dict = X_test.iloc[i].to_dict()
        pred_label = 'Attack' if preds[i] == 1 else 'Normal'
        conf = round(float(probs[i]) * 100, 1) if preds[i] == 1 else round((1 - float(probs[i])) * 100, 1)
        attack_type = classify_attack_type(row_dict, preds[i], conf)
        ip = real_ips[i] if real_ips and i < len(real_ips) else f'192.168.{random.randint(0,255)}.{random.randint(1,254)}'
        results.append({
            'id': len(analysis_results) + len(results) + 1,
            'ip_address': ip, 'prediction': pred_label, 'attack_type': attack_type,
            'confidence': conf, 'timestamp': ts, 'source': source,
        })
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    trained_models = get_trained_models_info()
    total = len(analysis_results)
    attacks = sum(1 for r in analysis_results if r['prediction'] == 'Attack')
    benign = total - attacks
    trust = round((benign / total) * 100, 1) if total > 0 else 98.0
    recent = analysis_results[-10:][::-1]
    attack_types = {}
    for r in analysis_results:
        t = r.get('attack_type', 'Normal')
        attack_types[t] = attack_types.get(t, 0) + 1
    return render_template('dashboard.html', active='dashboard',
        total=total, attacks=attacks, benign=benign, trust=trust,
        recent=recent, attack_types=json.dumps(attack_types),
        model_metrics=MODEL_METRICS, algorithms=ALGORITHMS,
        model_dataset=MODEL_DATASET_NAME,
        feature_count=len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        trained_models=trained_models, active_model_key=MODEL_DATASET_KEY)


@app.route('/overview')
def overview():
    trained_models = get_trained_models_info()
    active_dataset_key, active_dataset = get_active_dataset_info()
    return render_template('overview.html', active='overview',
        feature_names=FEATURE_NAMES or [],
        feature_count=len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        datasets=DATASETS, model_metrics=MODEL_METRICS, algorithms=ALGORITHMS,
        active_dataset=active_dataset, active_dataset_key=active_dataset_key,
        trained_models=trained_models)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    global analysis_results, latest_upload_export_rows
    if request.method == 'POST':
        if MODEL is None or FEATURE_NAMES is None:
            flash('Model not loaded. Train first.', 'danger')
            return redirect(url_for('upload'))
        if 'csv_file' not in request.files:
            flash('No file selected.', 'warning')
            return redirect(url_for('upload'))

        file = request.files['csv_file']
        if file.filename == '' or not file.filename.lower().endswith('.csv'):
            flash('Select a valid CSV file.', 'warning')
            return redirect(url_for('upload'))

        chunk_size = 5000
        max_report_rows = 2000

        try:
            header_df = pd.read_csv(file, nrows=0)
            available_cols = list(header_df.columns)
            file.stream.seek(0)
        except Exception as e:
            flash(f'Error reading CSV header: {e}', 'danger')
            return redirect(url_for('upload'))

        selected_cols = [col for col in FEATURE_NAMES if col in available_cols]
        if not selected_cols:
            flash('Uploaded CSV does not contain any of the required CIC-IoT23 feature columns.', 'danger')
            return redirect(url_for('upload'))

        missing = [col for col in FEATURE_NAMES if col not in available_cols]
        total_records = 0
        total_attacks = 0
        stored_results = []
        export_rows_written = 0
        export_fields = ['id', 'ip_address', 'prediction', 'attack_type', 'confidence', 'timestamp', 'source']

        try:
            with open(LATEST_UPLOAD_EXPORT_FILE, 'w', newline='', encoding='utf-8') as export_handle:
                writer = csv.DictWriter(export_handle, fieldnames=export_fields, extrasaction='ignore')
                writer.writeheader()

                reader = pd.read_csv(file, usecols=selected_cols, chunksize=chunk_size, low_memory=False)
                for chunk in reader:
                    total_records += len(chunk)

                    X_test = pd.DataFrame(index=chunk.index)
                    for col in FEATURE_NAMES:
                        if col in chunk.columns:
                            X_test[col] = chunk[col]
                        else:
                            X_test[col] = 0

                    X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
                    preds = MODEL.predict(X_test)
                    probs = MODEL.predict_proba(X_test)[:, 1]
                    total_attacks += int((preds == 1).sum())

                    chunk_results = build_results(X_test.reset_index(drop=True), preds, probs, source='CSV Upload')
                    for row in chunk_results:
                        export_rows_written += 1
                        row['id'] = export_rows_written
                    writer.writerows(chunk_results)

                    remaining = max_report_rows - len(stored_results)
                    if remaining > 0:
                        stored_results.extend(chunk_results[:remaining])
        except Exception as e:
            flash(f'Error processing CSV: {e}', 'danger')
            return redirect(url_for('upload'))

        latest_upload_export_rows = export_rows_written
        analysis_results.extend(stored_results)
        if len(analysis_results) > max_report_rows:
            analysis_results = analysis_results[-max_report_rows:]
            for idx, row in enumerate(analysis_results, start=1):
                row['id'] = idx

        if missing:
            flash(f'{len(missing)} columns were missing and filled with 0 automatically.', 'warning')

        if total_records > len(stored_results):
            flash(f'Analyzed {total_records:,} records. {total_attacks:,} threats found. Reports shows a {len(stored_results):,}-row preview, and Export CSV contains all {export_rows_written:,} analyzed rows.', 'success')
        else:
            flash(f'Analyzed {total_records:,} records. {total_attacks:,} threats found.', 'success')
        return redirect(url_for('reports'))

    active_dataset_key, active_dataset = get_active_dataset_info()
    trained_models = get_trained_models_info()
    return render_template('upload.html', active='upload',
        feature_names=FEATURE_NAMES or [], model_dataset=MODEL_DATASET_NAME,
        datasets=DATASETS, active_dataset=active_dataset,
        active_dataset_key=active_dataset_key, trained_models=trained_models)


@app.route('/training')
def training():
    trained_models = get_trained_models_info()
    return render_template('training.html', active='training',
        datasets=DATASETS, training_status=training_status,
        feature_count=len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        model_metrics=MODEL_METRICS, algorithms=ALGORITHMS,
        model_dataset=MODEL_DATASET_NAME,
        trained_models=trained_models,
        active_model_key=MODEL_DATASET_KEY)


@app.route('/api/train', methods=['POST'])
def api_train():
    global training_status
    if training_status['running']:
        return jsonify({'error': 'Training already running'}), 400
    data = request.get_json() or {}
    sample_frac = float(data.get('sample_frac', 0.10))
    sample_frac = max(0.05, min(sample_frac, 1.0))
    dataset_key = 'ciciot23'
    ds = DATASETS[dataset_key]
    base_dir = os.path.dirname(os.path.abspath(__file__))
    missing = [f for f in ds['files'] if not os.path.exists(os.path.join(base_dir, f))]
    if missing:
        return jsonify({'error': f'Missing: {", ".join(missing)}'}), 400
    training_status = {
        'running': True,
        'progress': 0,
        'message': 'Starting balanced CIC-IoT23 training...',
        'metrics': None,
    }

    def train_thread():
        global training_status
        try:
            from imblearn.over_sampling import SMOTE
            from xgboost import XGBClassifier
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.tree import DecisionTreeClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

            training_status.update(message='Loading CIC-IoT23 source files...', progress=5)
            dfs = []
            for csv_file in ds['files']:
                path = os.path.join(base_dir, csv_file)
                training_status['message'] = f'Loading {csv_file} ({sample_frac * 100:.0f}% sample)...'
                dfs.append(pd.read_csv(path).sample(frac=sample_frac, random_state=42))
            if not dfs:
                training_status.update(running=False, message='No data')
                return

            df = pd.concat(dfs, ignore_index=True)
            training_status.update(
                message=f'{len(df):,} sampled rows loaded. Selecting CIC-IoT23 features...',
                progress=15,
            )

            feat_names = [c for c in CICIOT23_FEATURES if c in df.columns]
            X = df[feat_names]
            y = df[ds['label_col']].apply(lambda x: 0 if str(x).strip().lower() in ds['benign_labels'] else 1)
            X = X.replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)

            training_status.update(message='Creating balanced CIC-IoT23 dataset with SMOTE...', progress=30)
            X_res, y_res = SMOTE(random_state=42).fit_resample(X, y)
            balanced_df = pd.DataFrame(X_res, columns=feat_names)
            balanced_df['label'] = y_res
            balanced_path = os.path.join(base_dir, 'balanced_data.csv')
            balanced_df.to_csv(balanced_path, index=False)

            training_status.update(
                message=f'Balanced dataset saved to balanced_data.csv with {len(balanced_df):,} rows.',
                progress=45,
            )
            X_train, X_test, y_train, y_test = train_test_split(
                X_res, y_res, test_size=0.2, random_state=42, stratify=y_res
            )

            metrics = {}

            training_status.update(message='Training Random Forest (1/3)...', progress=58)
            rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
            rf.fit(X_train, y_train)
            yp = rf.predict(X_test)
            metrics['random_forest'] = {
                'accuracy': round(accuracy_score(y_test, yp) * 100, 2),
                'precision': round(precision_score(y_test, yp) * 100, 2),
                'recall': round(recall_score(y_test, yp) * 100, 2),
                'f1_score': round(f1_score(y_test, yp) * 100, 2),
            }

            training_status.update(message='Training Decision Tree (2/3)...', progress=72)
            dt = DecisionTreeClassifier(random_state=42, max_depth=14, min_samples_split=8)
            dt.fit(X_train, y_train)
            yp = dt.predict(X_test)
            metrics['decision_tree'] = {
                'accuracy': round(accuracy_score(y_test, yp) * 100, 2),
                'precision': round(precision_score(y_test, yp) * 100, 2),
                'recall': round(recall_score(y_test, yp) * 100, 2),
                'f1_score': round(f1_score(y_test, yp) * 100, 2),
            }

            training_status.update(message='Training tuned XGBoost (3/3)...', progress=86)
            xgb = XGBClassifier(
                use_label_encoder=False,
                eval_metric='logloss',
                random_state=42,
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                n_jobs=4,
            )
            xgb.fit(X_train, y_train)
            yp = xgb.predict(X_test)
            metrics['xgboost'] = {
                'accuracy': round(accuracy_score(y_test, yp) * 100, 2),
                'precision': round(precision_score(y_test, yp) * 100, 2),
                'recall': round(recall_score(y_test, yp) * 100, 2),
                'f1_score': round(f1_score(y_test, yp) * 100, 2),
            }

            metrics['meta'] = {
                'dataset': ds['name'],
                'dataset_key': dataset_key,
                'features': len(feat_names),
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'balanced_samples': len(balanced_df),
                'sample_fraction': sample_frac,
                'balancing_method': 'SMOTE',
            }

            training_status.update(message='Saving CIC-IoT23 model artifacts...', progress=95)
            paths = model_artifact_paths(dataset_key)
            joblib.dump(xgb, paths['model'])
            joblib.dump(feat_names, paths['features'])
            with open(paths['metrics'], 'w') as f:
                json.dump(metrics, f, indent=2)
            save_active_model_key(dataset_key)
            load_model(dataset_key)
            training_status.update(
                metrics=metrics,
                message='Balanced CIC-IoT23 training complete!',
                progress=100,
                running=False,
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            training_status.update(running=False, message=f'Error: {e}', progress=0)

    threading.Thread(target=train_thread, daemon=True).start()
    return jsonify({'status': 'started'})


@app.route('/api/train-status')
def api_train_status():
    return jsonify(training_status)


@app.route('/api/model/select', methods=['POST'])
def api_model_select():
    data = request.get_json() or {}
    dataset_key = data.get('dataset')
    if dataset_key not in DATASETS:
        return jsonify({'error': 'Invalid dataset'}), 400

    trained_models = get_trained_models_info()
    if not trained_models.get(dataset_key, {}).get('trained'):
        return jsonify({'error': f'{DATASETS[dataset_key]["name"]} has not been trained yet'}), 400

    if not load_model(dataset_key):
        return jsonify({'error': 'Failed to load selected model'}), 500

    return jsonify({
        'status': 'ok',
        'dataset': MODEL_DATASET_NAME,
        'dataset_key': MODEL_DATASET_KEY,
        'features': len(FEATURE_NAMES) if FEATURE_NAMES else 0,
    })


@app.route('/reports')
def reports():
    atk_filter = request.args.get('attack_type', 'All Types')
    ip_filter = request.args.get('ip_address', '')
    filtered = analysis_results[:]
    attack_type_options = sorted({r.get('attack_type', 'Normal') for r in analysis_results} | {'Suspicious Activity'})
    if atk_filter and atk_filter != 'All Types':
        filtered = [r for r in filtered if r['attack_type'] == atk_filter]
    if ip_filter:
        filtered = [r for r in filtered if ip_filter in r['ip_address']]
    total = len(filtered); attacks = sum(1 for r in filtered if r['prediction'] == 'Attack')
    benign = total - attacks
    avg_conf = round(sum(r['confidence'] for r in filtered) / total, 1) if total > 0 else 0
    attack_types = {}
    for r in filtered:
        t = r.get('attack_type', 'Normal')
        attack_types[t] = attack_types.get(t, 0) + 1
    sorted_results = sorted(filtered, key=lambda r: -r['id'])
    return render_template('reports.html', active='reports',
        results=sorted_results, total=total, attacks=attacks, benign=benign,
        avg_conf=avg_conf, attack_types=json.dumps(attack_types),
        attack_type_filter=atk_filter, ip_filter=ip_filter,
        attack_type_options=attack_type_options)


@app.route('/live-monitoring')
def live_monitoring():
    return render_template('live_monitoring.html', active='live_monitoring',
        model_loaded=MODEL is not None, is_active=live_monitoring_active,
        scapy_available=SCAPY_AVAILABLE, model_dataset=MODEL_DATASET_NAME,
        active_model_key=MODEL_DATASET_KEY)


@app.route('/api/live-start', methods=['POST'])
def api_live_start():
    global live_monitoring_active, live_monitor_thread, live_log_buffer, live_stats, live_flow_results, live_session_results, live_result_counter
    if live_monitoring_active:
        return jsonify({'status': 'already_running'})
    live_monitoring_active = True
    live_log_buffer.clear()
    live_flow_results = {}
    live_session_results = []
    live_result_counter = 0
    live_stats = {'total_packets': 0, 'total_flows': 0, 'threats': 0, 'normal': 0,
                  'start_time': time.time(), 'last_event': '', 'capture_mode': ''}
    net_info = get_network_info()
    live_monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    live_monitor_thread.start()
    return jsonify({'status': 'started', 'network': net_info,
                    'attack_commands': get_attack_commands()})


@app.route('/api/live-stop', methods=['POST'])
def api_live_stop():
    global live_monitoring_active
    live_monitoring_active = False
    return jsonify({'status': 'stopped'})


@app.route('/api/live-poll')
def api_live_poll():
    if not live_monitoring_active and not live_log_buffer and not live_session_results:
        return jsonify({'active': False, 'logs': [], 'results': [], 'stats': live_stats})

    logs = list(live_log_buffer)
    recent = list(reversed(live_session_results))

    return jsonify({
        'active': live_monitoring_active,
        'logs': logs,
        'results': recent,
        'stats': live_stats,
    })


@app.route('/download-sample-csv')
def download_sample_csv():
    if not FEATURE_NAMES:
        flash('No features. Train first.', 'danger')
        return redirect(url_for('upload'))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(FEATURE_NAMES)
    for _ in range(5):
        writer.writerow([round(random.uniform(0, 100), 2) for _ in FEATURE_NAMES])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv', as_attachment=True, download_name='sample_network_traffic.csv')


@app.route('/export-csv')
def export_csv():
    if os.path.exists(LATEST_UPLOAD_EXPORT_FILE) and os.path.getsize(LATEST_UPLOAD_EXPORT_FILE) > 0:
        return send_file(LATEST_UPLOAD_EXPORT_FILE,
            mimetype='text/csv', as_attachment=True, download_name='ids_results_full.csv')

    if not analysis_results:
        flash('No results.', 'warning')
        return redirect(url_for('reports'))

    output = io.StringIO()
    keys = ['id', 'ip_address', 'prediction', 'attack_type', 'confidence', 'timestamp', 'source']
    writer = csv.DictWriter(output, fieldnames=keys, extrasaction='ignore')
    writer.writeheader(); writer.writerows(analysis_results)
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv', as_attachment=True, download_name='ids_results.csv')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
