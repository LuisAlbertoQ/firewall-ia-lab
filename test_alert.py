#!/usr/bin/env python3
"""
test_alert.py — Prueba el sistema de alertas sin esperar ataques reales.
"""
import sys
sys.path.insert(0, '/opt/ai_firewall')

from alerter import load_config, send_alert_email
from datetime import datetime

config = load_config()

if not config.get('enabled'):
    print("[!] Alertas deshabilitadas en alert_config.json")
    print("    Verifica que 'enabled': true y las credenciales son correctas")
    sys.exit(1)

# Eventos de prueba
test_events = [
    {
        'timestamp':  datetime.now().isoformat(),
        'ip':         '192.168.10.10',
        'label':      'attack',
        'confidence': 0.97,
        'action':     'BLOCK',
        'pkts':       85000,
        'dports':     1,
        'syn_ratio':  1.0,
    },
    {
        'timestamp':  datetime.now().isoformat(),
        'ip':         '192.168.10.10',
        'label':      'attack',
        'confidence': 1.0,
        'action':     'BLOCK',
        'pkts':       120000,
        'dports':     500,
        'syn_ratio':  0.95,
    },
    {
        'timestamp':  datetime.now().isoformat(),
        'ip':         '192.168.10.99',
        'label':      'attack',
        'confidence': 0.92,
        'action':     'BLOCK',
        'pkts':       3500,
        'dports':     412,
        'syn_ratio':  0.88,
    },
]

summary = {
    'total_blocks': len(test_events),
    'unique_ips':   2,
    'blocked_ips':  ['192.168.10.10', '192.168.10.99'],
    'window_min':   2,
}

print(f"[*] Enviando email de prueba a: {config['mail_to']}")
print(f"[*] SMTP: {config['smtp_host']}:{config['smtp_port']}")

success = send_alert_email(config, test_events, summary)

if success:
    print("[OK] Email enviado correctamente — revisa tu bandeja de entrada")
else:
    print("[!] Error enviando email — revisa los logs")
