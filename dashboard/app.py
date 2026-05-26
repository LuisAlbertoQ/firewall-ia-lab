#!/usr/bin/env python3
"""
dashboard/app.py — Dashboard Firewall IA
"""

import os
import json
import time
import subprocess
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, Response

BASE_DIR      = '/opt/ai_firewall'
DECISIONS_LOG = f'{BASE_DIR}/logs/decisions.json'
METRICS_JSON  = f'{BASE_DIR}/models/metrics.json'
AI_LOG        = f'{BASE_DIR}/logs/ai_firewall.log'

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('dashboard')

app = Flask(__name__)

# ── Caché simple ──────────────────────────────
_cache     = {}
CACHE_TTL  = 4

def cached(key, fn):
    now = time.time()
    if key not in _cache or now - _cache[key]['ts'] > CACHE_TTL:
        try:
            _cache[key] = {'ts': now, 'data': fn()}
        except Exception as e:
            log.error(f"Cache error {key}: {e}")
            if key in _cache:
                return _cache[key]['data']
            return None
    return _cache[key]['data']


# ── Helpers ───────────────────────────────────
def load_decisions():
    try:
        if not os.path.exists(DECISIONS_LOG):
            return []
        with open(DECISIONS_LOG, 'r') as f:
            raw = f.read().strip()
        if not raw or raw == '[]':
            return []
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except Exception as e:
        log.error(f"Error leyendo decisions: {e}")
        return []


def load_metrics():
    try:
        with open(METRICS_JSON, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def fetch_blocked_ips():
    try:
        r = subprocess.run(
            ['sudo', 'nft', 'list', 'set', 'inet', 'filter', 'ia_blocklist'],
            capture_output=True, text=True, timeout=3
        )
        ips    = []
        inside = False
        for line in r.stdout.splitlines():
            if 'elements' in line:
                inside = True
            if inside and '}' in line and 'elements' not in line:
                break
            if inside and 'elements' not in line:
                for p in line.replace(',', ' ').split():
                    if p.count('.') == 3 and all(
                        x.isdigit() and 0 <= int(x) <= 255
                        for x in p.split('.')
                    ):
                        ips.append(p.strip())
        return ips
    except Exception as e:
        log.error(f"Error leyendo blocklist: {e}")
        return []


def fetch_service_status():
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', 'ai-firewall'],
            capture_output=True, text=True, timeout=3
        )
        active = r.stdout.strip() == 'active'
    except Exception:
        active = False
    return {
        'active':    active,
        'status':    'Activo' if active else 'Detenido',
        'timestamp': datetime.now().strftime('%H:%M:%S'),
    }


def get_last_log_lines(n=15):
    try:
        with open(AI_LOG, 'r') as f:
            return [l.rstrip() for l in f.readlines()[-n:]]
    except Exception:
        return []


def compute_summary(decisions):
    total   = len(decisions)
    blocked = sum(1 for d in decisions if d.get('action') == 'BLOCK')
    allowed = total - blocked
    return {
        'total':      total,
        'blocked':    blocked,
        'allowed':    allowed,
        'block_rate': round(blocked / total * 100, 1) if total else 0,
    }


# ── Rutas ─────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    decisions   = load_decisions()
    summary     = compute_summary(decisions)
    blocked_ips = cached('blocked_ips', fetch_blocked_ips) or []
    service     = cached('service',     fetch_service_status) or {}

    # Timeline por minuto
    timeline = {}
    for d in decisions:
        minute = d.get('timestamp', '')[:16]
        if not minute:
            continue
        if minute not in timeline:
            timeline[minute] = {'block': 0, 'allow': 0}
        if d.get('action') == 'BLOCK':
            timeline[minute]['block'] += 1
        else:
            timeline[minute]['allow'] += 1

    timeline_list = [
        {'time': k, 'block': v['block'], 'allow': v['allow']}
        for k, v in sorted(timeline.items())
    ][-30:]

    # Top IPs
    ip_counts = {}
    for d in decisions:
        if d.get('action') == 'BLOCK':
            ip = d.get('ip', '')
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    payload = {
        'summary':     summary,
        'blocked_ips': blocked_ips,
        'decisions':   decisions[-50:],
        'timeline':    timeline_list,
        'top_ips':     [{'ip': ip, 'count': c} for ip, c in top_ips],
        'metrics':     load_metrics(),
        'service':     service,
        'log_lines':   get_last_log_lines(),
    }

    # Respuesta con headers explícitos
    response = Response(
        json.dumps(payload, default=str),
        status=200,
        mimetype='application/json',
    )
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Cache-Control'] = 'no-cache, no-store'
    return response


@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock(ip):
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return jsonify({'success': False, 'error': 'IP invalida'}), 400
    r = subprocess.run(
        ['sudo', 'nft', 'delete', 'element',
         'inet', 'filter', 'ia_blocklist', f'{{ {ip} }}'],
        capture_output=True, text=True, timeout=5
    )
    _cache.pop('blocked_ips', None)  # invalidar caché
    return jsonify({
        'success': r.returncode == 0,
        'ip':      ip,
        'message': f'IP {ip} desbloqueada' if r.returncode == 0 else r.stderr.strip()
    })


@app.route('/api/block/<ip>', methods=['POST'])
def api_block(ip):
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return jsonify({'success': False, 'error': 'IP invalida'}), 400
    r = subprocess.run(
        ['sudo', 'nft', 'add', 'element',
         'inet', 'filter', 'ia_blocklist', f'{{ {ip} }}'],
        capture_output=True, text=True, timeout=5
    )
    _cache.pop('blocked_ips', None)
    return jsonify({
        'success': r.returncode == 0,
        'ip':      ip,
        'message': f'IP {ip} bloqueada' if r.returncode == 0 else r.stderr.strip()
    })


@app.route('/api/test')
def api_test():
    """Endpoint de prueba — siempre devuelve OK."""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})


if __name__ == '__main__':
    log.info("Dashboard iniciando en http://0.0.0.0:5000")
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000, threads=4)
