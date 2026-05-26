#!/usr/bin/env python3
"""
alerter.py
Sistema de alertas por email para el Firewall IA.
Se ejecuta como hilo dentro de ai_firewall.py
"""

import json
import logging
import os
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import deque

log = logging.getLogger('ai_firewall.alerter')

CONFIG_PATH = '/opt/ai_firewall/alert_config.json'


# ─────────────────────────────────────────────
# Cargar configuración
# ─────────────────────────────────────────────
def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning(f"alert_config.json no encontrado: {CONFIG_PATH}")
        return {'enabled': False}
    except Exception as e:
        log.error(f"Error leyendo alert_config.json: {e}")
        return {'enabled': False}


# ─────────────────────────────────────────────
# Construir el cuerpo del email HTML
# ─────────────────────────────────────────────
def build_email_html(events: list, summary: dict) -> str:
    rows = ''
    for e in events[-20:]:
        ts   = e.get('timestamp', '')[:19].replace('T', ' ')
        ip   = e.get('ip', '')
        conf = round(e.get('confidence', 0) * 100, 1)
        pkts = e.get('pkts', 0)
        syn  = e.get('syn_ratio', 0)
        rows += f"""
        <tr>
            <td style="padding:6px 12px;border-bottom:1px solid #2d3748">{ts}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #2d3748;
                       font-family:monospace">{ip}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #2d3748;
                       color:#e24b4a;font-weight:bold">{conf}%</td>
            <td style="padding:6px 12px;border-bottom:1px solid #2d3748">{pkts}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #2d3748">{syn}</td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;
                 padding:20px;margin:0">

        <div style="max-width:700px;margin:0 auto">

            <!-- Header -->
            <div style="background:#1a1d2e;border-left:4px solid #e24b4a;
                        padding:20px;border-radius:8px;margin-bottom:20px">
                <h1 style="margin:0;color:#e24b4a;font-size:1.4rem">
                    Alerta de Seguridad — Firewall IA
                </h1>
                <p style="margin:8px 0 0;color:#718096;font-size:0.9rem">
                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
                </p>
            </div>

            <!-- Resumen -->
            <div style="display:grid;grid-template-columns:repeat(3,1fr);
                        gap:12px;margin-bottom:20px">
                <div style="background:#1a1d2e;padding:16px;border-radius:8px;
                            text-align:center">
                    <div style="font-size:0.75rem;color:#718096;
                                text-transform:uppercase">Ataques detectados</div>
                    <div style="font-size:2rem;font-weight:700;
                                color:#e24b4a">{summary['total_blocks']}</div>
                </div>
                <div style="background:#1a1d2e;padding:16px;border-radius:8px;
                            text-align:center">
                    <div style="font-size:0.75rem;color:#718096;
                                text-transform:uppercase">IPs únicas</div>
                    <div style="font-size:2rem;font-weight:700;
                                color:#ef9f27">{summary['unique_ips']}</div>
                </div>
                <div style="background:#1a1d2e;padding:16px;border-radius:8px;
                            text-align:center">
                    <div style="font-size:0.75rem;color:#718096;
                                text-transform:uppercase">Ventana</div>
                    <div style="font-size:2rem;font-weight:700;
                                color:#7f77dd">{summary['window_min']}m</div>
                </div>
            </div>

            <!-- Tabla de eventos -->
            <div style="background:#1a1d2e;border-radius:8px;
                        overflow:hidden;margin-bottom:20px">
                <div style="padding:12px 16px;border-bottom:1px solid #2d3748">
                    <h2 style="margin:0;font-size:1rem;color:#a0aec0">
                        Detalle de eventos
                    </h2>
                </div>
                <table style="width:100%;border-collapse:collapse">
                    <thead>
                        <tr style="background:#0d0f18">
                            <th style="padding:8px 12px;text-align:left;
                                       color:#718096;font-weight:500">Timestamp</th>
                            <th style="padding:8px 12px;text-align:left;
                                       color:#718096;font-weight:500">IP</th>
                            <th style="padding:8px 12px;text-align:left;
                                       color:#718096;font-weight:500">Confianza</th>
                            <th style="padding:8px 12px;text-align:left;
                                       color:#718096;font-weight:500">Paquetes</th>
                            <th style="padding:8px 12px;text-align:left;
                                       color:#718096;font-weight:500">SYN ratio</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>

            <!-- IPs bloqueadas -->
            <div style="background:#1a1d2e;border-radius:8px;padding:16px;
                        margin-bottom:20px">
                <h2 style="margin:0 0 12px;font-size:1rem;color:#a0aec0">
                    IPs bloqueadas en esta alerta
                </h2>
                <div style="display:flex;flex-wrap:wrap;gap:8px">
                    {''.join(f'<span style="background:#2d1515;color:#e24b4a;padding:4px 12px;border-radius:20px;font-family:monospace;font-size:0.85rem">{ip}</span>' for ip in summary['blocked_ips'])}
                </div>
            </div>

            <!-- Acciones recomendadas -->
            <div style="background:#0d2e1f;border:1px solid #1d9e7544;
                        border-radius:8px;padding:16px;margin-bottom:20px">
                <h2 style="margin:0 0 8px;font-size:1rem;color:#1d9e75">
                    Acciones recomendadas
                </h2>
                <ul style="margin:0;padding-left:20px;color:#a0aec0;
                           font-size:0.9rem;line-height:1.8">
                    <li>Verificar el dashboard: 
                        <a href="http://192.168.10.1:5000" 
                           style="color:#7f77dd">http://192.168.10.1:5000</a>
                    </li>
                    <li>Revisar logs: 
                        <code style="background:#0d0f18;padding:2px 6px;
                                     border-radius:4px">
                            journalctl -u ai-firewall -n 50
                        </code>
                    </li>
                    <li>Verificar falsos positivos antes de mantener el bloqueo</li>
                    <li>Si es un FP: 
                        <code style="background:#0d0f18;padding:2px 6px;
                                     border-radius:4px">
                            sudo nft delete element inet filter ia_blocklist {{IP}}
                        </code>
                    </li>
                </ul>
            </div>

            <!-- Footer -->
            <p style="text-align:center;color:#4a5568;font-size:0.8rem;margin:0">
                Firewall IA Lab v1.0 — Generado automáticamente
            </p>

        </div>
    </body>
    </html>
    """


# ─────────────────────────────────────────────
# Enviar email
# ─────────────────────────────────────────────
def send_alert_email(config: dict, events: list, summary: dict) -> bool:
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = (
            f"[ALERTA] Firewall IA — {summary['total_blocks']} ataques "
            f"detectados desde {summary['unique_ips']} IPs"
        )
        msg['From']    = config['mail_from']
        msg['To']      = ', '.join(config['mail_to'])

        # Versión texto plano
        text_body = (
            f"ALERTA DE SEGURIDAD — Firewall IA\n"
            f"{'='*50}\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Ataques detectados: {summary['total_blocks']}\n"
            f"IPs únicas: {summary['unique_ips']}\n"
            f"IPs bloqueadas: {', '.join(summary['blocked_ips'])}\n\n"
            f"Últimos eventos:\n"
        )
        for e in events[-10:]:
            text_body += (
                f"  {e['timestamp'][:19]} | {e['ip']} | "
                f"{round(e['confidence']*100,1)}% | {e['pkts']} pkts\n"
            )
        text_body += f"\nDashboard: http://192.168.10.1:5000\n"

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(build_email_html(events, summary), 'html'))

        # Enviar
        with smtplib.SMTP(config['smtp_host'], config['smtp_port']) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(config['smtp_user'], config['smtp_pass'])
            server.sendmail(
                config['mail_from'],
                config['mail_to'],
                msg.as_string(),
            )

        log.info(f"Email de alerta enviado a: {config['mail_to']}")
        return True

    except smtplib.SMTPAuthenticationError:
        log.error("Error de autenticación SMTP — verifica smtp_user y smtp_pass")
        return False
    except smtplib.SMTPException as e:
        log.error(f"Error SMTP: {e}")
        return False
    except Exception as e:
        log.error(f"Error enviando email: {e}")
        return False


# ─────────────────────────────────────────────
# Monitor de alertas — corre como hilo
# ─────────────────────────────────────────────
class AlertMonitor:
    def __init__(self):
        self.config          = load_config()
        self.last_alert_time = None
        self.event_window    = deque()
        self.lock            = threading.Lock()
        self.running         = True
        self._thread         = None

    def reload_config(self):
        self.config = load_config()

    def add_event(self, decision: dict):
        """Llamado por el motor IA cada vez que detecta un ataque."""
        if not self.config.get('enabled', False):
            return
        if decision.get('action') != 'BLOCK':
            return

        with self.lock:
            self.event_window.append(decision)

    def _check_and_alert(self):
        """Verifica si se deben enviar alertas según los umbrales."""
        if not self.config.get('enabled', False):
            return

        thresholds    = self.config.get('thresholds', {})
        blocks_needed = thresholds.get('blocks_per_window', 3)
        window_min    = thresholds.get('window_minutes', 2)
        cooldown_min  = self.config.get('cooldown_minutes', 10)

        now      = datetime.now()
        cutoff   = now - timedelta(minutes=window_min)

        with self.lock:
            # Limpiar eventos fuera de la ventana
            while self.event_window and (
                datetime.fromisoformat(
                    self.event_window[0]['timestamp']
                ) < cutoff
            ):
                self.event_window.popleft()

            recent_blocks = list(self.event_window)

        if len(recent_blocks) < blocks_needed:
            return

        # Verificar cooldown
        if self.last_alert_time:
            elapsed = (now - self.last_alert_time).total_seconds() / 60
            if elapsed < cooldown_min:
                log.info(
                    f"Alerta en cooldown — "
                    f"{cooldown_min - elapsed:.1f} min restantes"
                )
                return

        # Construir resumen
        unique_ips = list(set(e['ip'] for e in recent_blocks))
        summary = {
            'total_blocks': len(recent_blocks),
            'unique_ips':   len(unique_ips),
            'blocked_ips':  unique_ips,
            'window_min':   window_min,
        }

        log.warning(
            f"UMBRAL ALCANZADO — {len(recent_blocks)} ataques "
            f"en {window_min} min desde {len(unique_ips)} IPs — "
            f"enviando alerta..."
        )

        success = send_alert_email(self.config, recent_blocks, summary)
        if success:
            self.last_alert_time = now
            with self.lock:
                self.event_window.clear()

    def _monitor_loop(self):
        log.info("Monitor de alertas iniciado")
        while self.running:
            try:
                self._check_and_alert()
            except Exception as e:
                log.error(f"Error en monitor de alertas: {e}")
            time.sleep(30)  # verificar cada 30 segundos

    def start(self):
        if not self.config.get('enabled', False):
            log.info("Sistema de alertas deshabilitado en alert_config.json")
            return
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='AlertMonitor',
        )
        self._thread.start()
        log.info(
            f"Sistema de alertas activo — "
            f"umbral: {self.config['thresholds']['blocks_per_window']} "
            f"bloques en {self.config['thresholds']['window_minutes']} min"
        )

    def stop(self):
        self.running = False


# Instancia global
alert_monitor = AlertMonitor()
