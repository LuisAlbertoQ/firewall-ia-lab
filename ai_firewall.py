#!/usr/bin/env python3
"""
ai_firewall.py
Motor de decisión en tiempo real: captura tráfico → extrae features
→ modelo IA → bloquea IPs maliciosas en nftables.
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
import json
from datetime import datetime
from collections import defaultdict
from alerter import alert_monitor
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ─────────────────────────────────────────────
# Configuración global
# ─────────────────────────────────────────────
BASE_DIR      = '/opt/ai_firewall'
MODEL_PATH    = f'{BASE_DIR}/models/firewall_ai_model.joblib'
SCALER_PATH   = f'{BASE_DIR}/models/scaler.joblib'
LOG_PATH      = f'{BASE_DIR}/logs/ai_firewall.log'
DECISIONS_LOG = f'{BASE_DIR}/logs/decisions.json'
PID_FILE      = '/tmp/ai_firewall.pid'
IFACE         = os.environ.get('LAB_IFACE', 'enp0s8')

# Ventana de análisis en segundos
WINDOW_SEC = 15

# Umbral de confianza mínimo para bloquear
CONFIDENCE_THRESHOLD = 0.75

# IPs que NUNCA se bloquean
WHITELIST = {
    '127.0.0.1',
    '192.168.10.1',
    #'192.168.10.20',
    '8.8.8.8',
    '1.1.1.1',
    '10.0.2.1',
    '10.0.2.2',
    '10.0.2.3',
    '10.0.2.15',
}

FEATURES = [
    'total_pkts', 'tcp_pkts', 'udp_pkts', 'other_pkts',
    'unique_dports_count', 'syn_ratio', 'avg_pkt_size',
    'duration_sec', 'bytes_per_sec', 'port_scan_score',
    'small_syn_score', 'potential_flood', 'potential_scan',
]

# ─────────────────────────────────────────────
# Logging estructurado
# ─────────────────────────────────────────────
os.makedirs(f'{BASE_DIR}/logs', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger('ai_firewall')


# ─────────────────────────────────────────────
# Estado global compartido entre hilos
# ─────────────────────────────────────────────
class FirewallState:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'total_pkts':    0,
            'tcp_pkts':      0,
            'udp_pkts':      0,
            'other_pkts':    0,
            'syn_pkts':      0,
            'total_bytes':   0,
            'pkt_sizes':     [],
            'unique_dports': set(),
            'timestamps':    [],
        })
        self.blocked_ips = set()
        self.decisions   = []
        self.lock        = threading.Lock()
        self.running     = True
        self.stats = {
            'total_analyzed': 0,
            'total_blocked':  0,
            'total_allowed':  0,
            'false_positives': 0,
        }

state = FirewallState()


# ─────────────────────────────────────────────
# Cargar modelo
# ─────────────────────────────────────────────
def load_model():
    if not os.path.exists(MODEL_PATH):
        log.error(f"Modelo no encontrado: {MODEL_PATH}")
        log.error("Ejecuta primero: python3 train_model.py")
        sys.exit(1)

    clf    = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    log.info(f"Modelo cargado: {MODEL_PATH}")
    log.info(f"Clases del modelo: {clf.classes_}")
    return clf, scaler


# ─────────────────────────────────────────────
# Captura de paquetes (hilo dedicado)
# ─────────────────────────────────────────────
def packet_callback(pkt):
    """Procesa cada paquete y actualiza el estado de flujos."""
    if IP not in pkt:
        return

    src  = pkt[IP].src
    size = len(pkt)

    if src in WHITELIST:
        return

    with state.lock:
        f = state.flows[src]
        f['total_pkts']  += 1
        f['total_bytes'] += size
        f['pkt_sizes'].append(size)
        f['timestamps'].append(float(pkt.time))

        if TCP in pkt:
            f['tcp_pkts'] += 1
            f['unique_dports'].add(pkt[TCP].dport)
            # SYN sin ACK = SYN puro
            if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
                f['syn_pkts'] += 1
        elif UDP in pkt:
            f['udp_pkts'] += 1
            f['unique_dports'].add(pkt[UDP].dport)
        else:
            f['other_pkts'] += 1


def start_capture():
    """Inicia la captura en la interfaz configurada."""
    log.info(f"Capturando en interfaz: {IFACE}")
    try:
        sniff(
            iface=IFACE,
            # Solo capturar tráfico que viene de la red interna
            filter="src net 192.168.10.0/24",
            prn=packet_callback,
            store=False,
            stop_filter=lambda _: not state.running,
        )
    except Exception as e:
        log.error(f"Error en captura: {e}")
        state.running = False

# ─────────────────────────────────────────────
# Extracción de features desde flujo activo
# ─────────────────────────────────────────────
def extract_features_from_flow(f: dict) -> np.ndarray:
    """Convierte un flujo en vector de 13 features."""
    total  = f['total_pkts']
    tcp    = f['tcp_pkts']
    syn    = f['syn_pkts']
    bytes_ = f['total_bytes']
    sizes  = f['pkt_sizes']
    dports = f['unique_dports']
    times  = sorted(f['timestamps'])

    duration        = (times[-1] - times[0]) if len(times) > 1 else 0.001
    avg_pkt_size    = float(np.mean(sizes)) if sizes else 0.0
    syn_ratio       = syn / tcp if tcp > 0 else 0.0
    bytes_per_sec   = bytes_ / duration if duration > 0 else 0.0
    unique_dports_c = len(dports)
    port_scan_score = unique_dports_c / total if total > 0 else 0.0
    small_syn_score = (syn_ratio / avg_pkt_size * 10000) if avg_pkt_size > 0 else 0.0
    potential_flood = int(syn_ratio > 0.5 and total > 500)
    potential_scan  = int(unique_dports_c > 100)

    return np.array([[
        total,
        tcp,
        f['udp_pkts'],
        f['other_pkts'],
        unique_dports_c,
        syn_ratio,
        avg_pkt_size,
        duration,
        bytes_per_sec,
        port_scan_score,
        small_syn_score,
        potential_flood,
        potential_scan,
    ]], dtype=float)


# ─────────────────────────────────────────────
# Guardar decisions.json de forma atómica
# ─────────────────────────────────────────────
def save_decisions():
    """Escritura atómica — nunca deja el archivo a medias."""
    try:
        tmp = DECISIONS_LOG + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state.decisions[-100:], f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, DECISIONS_LOG)
    except Exception as e:
        log.error(f"Error guardando decisions.json: {e}")


# ─────────────────────────────────────────────
# Bloqueo de IP en nftables
# ─────────────────────────────────────────────
def block_ip(ip: str) -> bool:
    """Agrega IP al set ia_blocklist. Renueva timeout si ya existe."""
    cmd = [
        'sudo', 'nft', 'add', 'element',
        'inet', 'filter', 'ia_blocklist',
        f'{{ {ip} }}',
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            if ip not in state.blocked_ips:
                state.stats['total_blocked'] += 1
                log.warning(f"BLOQUEADO (nuevo): {ip}")
            else:
                log.warning(f"BLOQUEADO (renovado): {ip}")
            state.blocked_ips.add(ip)
            return True
        else:
            log.error(f"Error al bloquear {ip}: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        log.error(f"Timeout al bloquear {ip}")
        return False
    except Exception as e:
        log.error(f"Excepcion al bloquear {ip}: {e}")
        return False


# ─────────────────────────────────────────────
# Desbloqueo de IP
# ─────────────────────────────────────────────
def unblock_ip(ip: str) -> bool:
    """Elimina IP del set ia_blocklist."""
    cmd = [
        'sudo', 'nft', 'delete', 'element',
        'inet', 'filter', 'ia_blocklist',
        f'{{ {ip} }}',
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            state.blocked_ips.discard(ip)
            state.stats['false_positives'] += 1
            log.info(f"DESBLOQUEADO (FP): {ip}")
            return True
        return False
    except Exception as e:
        log.error(f"Error al desbloquear {ip}: {e}")
        return False


# ─────────────────────────────────────────────
# Motor de análisis — hilo principal
# ─────────────────────────────────────────────
def analysis_loop(clf, scaler):
    """
    Cada WINDOW_SEC segundos analiza todos los flujos activos
    y toma decisiones de bloqueo.
    """
    log.info(f"Motor de análisis iniciado (ventana: {WINDOW_SEC}s)")

    while state.running:
        time.sleep(WINDOW_SEC)

        # Snapshot y limpieza atómica
        with state.lock:
            flows_snapshot = dict(state.flows)
            state.flows.clear()

        if not flows_snapshot:
            log.info("Sin tráfico en esta ventana.")
            continue

        log.info(f"Analizando {len(flows_snapshot)} IPs...")

        for ip, flow in flows_snapshot.items():
            # Ignorar flujos con muy pocos paquetes
            if flow['total_pkts'] < 3:
                continue

            try:
                X      = extract_features_from_flow(flow)
                X_sc   = scaler.transform(X)
                pred   = clf.predict(X_sc)[0]
                proba  = clf.predict_proba(X_sc)[0]

                classes     = list(clf.classes_)
                attack_idx  = classes.index('attack')
                attack_conf = float(proba[attack_idx])

                state.stats['total_analyzed'] += 1

                is_attack = (pred == 'attack' and
                             attack_conf >= CONFIDENCE_THRESHOLD)

                decision = {
                    'timestamp':  datetime.now().isoformat(),
                    'ip':         ip,
                    'label':      str(pred),
                    'confidence': round(attack_conf, 4),
                    'action':     'BLOCK' if is_attack else 'ALLOW',
                    'pkts':       int(flow['total_pkts']),
                    'dports':     int(len(flow['unique_dports'])),
                    'syn_ratio':  round(
                        flow['syn_pkts'] / flow['tcp_pkts'], 4
                    ) if flow['tcp_pkts'] > 0 else 0.0,
                }

                state.decisions.append(decision)

                # Mantener solo las últimas 500 en memoria
                if len(state.decisions) > 500:
                    state.decisions.pop(0)

                # Guardar a disco de forma atómica
                save_decisions()

                if is_attack:
                    log.warning(
                        f"ATAQUE detectado | IP: {ip} | "
                        f"confianza: {attack_conf*100:.1f}% | "
                        f"pkts: {flow['total_pkts']} | "
                        f"dports: {len(flow['unique_dports'])} | "
                        f"syn_ratio: {decision['syn_ratio']}"
                    )
                    block_ip(ip)
                    alert_monitor.add_event(decision)
                else:
                    state.stats['total_allowed'] += 1
                    log.info(
                        f"Normal | IP: {ip} | "
                        f"confianza attack: {attack_conf*100:.1f}% | "
                        f"pkts: {flow['total_pkts']}"
                    )

            except Exception as e:
                log.error(f"Error analizando {ip}: {e}")

        log.info(
            f"Resumen | Analizadas: {state.stats['total_analyzed']} | "
            f"Bloqueadas: {state.stats['total_blocked']} | "
            f"Permitidas: {state.stats['total_allowed']}"
        )


# ─────────────────────────────────────────────
# Manejo de señales
# ─────────────────────────────────────────────
def signal_handler(sig, frame):
    log.info("Señal recibida — deteniendo motor IA...")
    state.running = False
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    alert_monitor.stop()
    sys.exit(0)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── Control de instancia única ────────────
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            old_pid = f.read().strip()
        try:
            os.kill(int(old_pid), 0)
            log.error(f"Ya hay una instancia corriendo (PID {old_pid})")
            sys.exit(1)
        except (OSError, ValueError):
            pass  # proceso muerto, continuar

    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    log.info("=" * 50)
    log.info("  Motor Firewall IA — iniciando")
    log.info(f"  PID: {os.getpid()}")
    log.info(f"  Interfaz: {IFACE}")
    log.info(f"  Ventana de analisis: {WINDOW_SEC}s")
    log.info(f"  Umbral de confianza: {CONFIDENCE_THRESHOLD}")
    log.info(f"  Whitelist: {WHITELIST}")
    log.info("=" * 50)

    # ── Verificar nftables ────────────────────
    result = subprocess.run(
        ['sudo', 'nft', 'list', 'set', 'inet', 'filter', 'ia_blocklist'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error("nftables no configurado — ejecuta: sudo nft -f /etc/nftables.conf")
        os.remove(PID_FILE)
        sys.exit(1)

    log.info("nftables verificado OK")

    # ── Inicializar decisions.json si no existe ─
    if not os.path.exists(DECISIONS_LOG):
        with open(DECISIONS_LOG, 'w') as f:
            json.dump([], f)
        os.chmod(DECISIONS_LOG, 0o666)

    # ── Cargar modelo ─────────────────────────
    clf, scaler = load_model()

    # ── Hilo de captura (único) ───────────────
    capture_thread = threading.Thread(
        target=start_capture,
        daemon=True,
        name='PacketCapture',
    )
    alert_monitor.start()
    capture_thread.start()
    log.info("Hilo de captura iniciado")

    # ── Bucle de análisis en hilo principal ───
    try:
        analysis_loop(clf, scaler)
    finally:
        state.running = False
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        log.info("Motor detenido.")


if __name__ == '__main__':
    main()
