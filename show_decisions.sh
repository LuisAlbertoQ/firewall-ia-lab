#!/bin/bash
echo "=== Últimas decisiones del motor IA ==="
if [ -f /opt/ai_firewall/logs/decisions.json ]; then
    python3 -c "
import json
with open('/opt/ai_firewall/logs/decisions.json') as f:
    decisions = json.load(f)
print(f'Total decisiones: {len(decisions)}')
print()
print(f'{\"Timestamp\":<22} {\"IP\":<18} {\"Label\":<8} {\"Conf%\":>6} {\"Accion\":<8} {\"Pkts\":>6}')
print('-'*75)
for d in decisions[-20:]:
    ts   = d['timestamp'][:19]
    conf = round(d['confidence']*100, 1)
    print(f'{ts:<22} {d[\"ip\"]:<18} {d[\"label\"]:<8} {conf:>6} {d[\"action\"]:<8} {d[\"pkts\"]:>6}')
"
else
    echo "Sin decisiones aún. El motor necesita al menos una ventana de análisis (15s)."
fi
