# Firewall con Inteligencia Artificial

Laboratorio práctico de ciberseguridad que implementa un firewall adaptativo
combinando nftables con un modelo de Machine Learning (RandomForest) para
detección y bloqueo automático de tráfico malicioso en tiempo real.

## Arquitectura
Internet → Ubuntu Server (router/firewall) → Red interna
↓
nftables + IA
↓
Kali Linux | Linux Mint

## Stack tecnológico

| Componente | Herramienta |
|---|---|
| Sistema Operativo | Ubuntu Server 22.04 |
| Firewall | nftables |
| Captura | tcpdump + scapy |
| ML Pipeline | scikit-learn (RandomForest) |
| Dashboard | Flask + Chart.js |
| Alertas | SMTP / Gmail |

## Estructura del proyecto
firewall-ia-lab/
├── ai_firewall.py          # Motor de decisión IA en tiempo real
├── alerter.py              # Sistema de alertas por email
├── extract_features.py     # Extracción de 13 features desde pcap
├── train_model.py          # Entrenamiento y comparativa de modelos
├── build_dataset.py        # Construcción del dataset balanceado
├── rebuild_dataset.py      # Rebalanceo con nuevos datos
├── test_alert.py           # Prueba del sistema de alertas
├── nftables.conf           # Configuración del firewall
├── data/
│   └── raw/                # CSVs de features extraídas
├── models/
│   ├── firewall_ai_model.joblib
│   └── scaler.joblib
├── dashboard/
│   ├── app.py              # Servidor Flask
│   └── templates/
│       └── index.html      # Dashboard web
└── systemd/
├── ai-firewall.service
└── ai-dashboard.service

## Funciones extra implementadas

1. **Dashboard web en tiempo real** — Flask + Chart.js, actualización cada 5s
2. **Sistema de alertas por email** — notificación automática por umbrales

## Métricas del modelo

| Modelo | Accuracy | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|
| Random Forest | 0.974 | 0.975 | 0.972 | 0.974 | 0.997 |
| Gradient Boosting | 0.968 | 0.969 | 0.968 | 0.968 | 0.995 |
| Decision Tree | 0.954 | 0.955 | 0.954 | 0.954 | 0.954 |
| Logistic Regression | 0.921 | 0.922 | 0.921 | 0.921 | 0.981 |

## Instalación rápida

```bash
# Clonar repositorio
git clone https://github.com/tu_usuario/firewall-ia-lab.git
cd firewall-ia-lab

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Aplicar firewall
sudo nft -f nftables.conf

# Iniciar servicios
sudo systemctl start ai-firewall
sudo systemctl start ai-dashboard
```

## Uso

```bash
# Ver estado del sistema
sudo systemctl status ai-firewall ai-dashboard

# Ver IPs bloqueadas
sudo nft list set inet filter ia_blocklist

# Ver decisiones del motor
cat logs/decisions.json | python3 -m json.tool

# Dashboard web
http://192.168.10.1:5000
```

## Entorno de laboratorio

| VM | IP | Rol |
|---|---|---|
| Ubuntu Server | 192.168.10.1 | Router + Firewall + IA |
| Kali Linux | 192.168.10.10 | Máquina atacante |
| Linux Mint | 192.168.10.20 | Cliente legítimo |

## Uso educativo

Laboratorio desarrollado con fines académicos.
Versión 1.0 — Mayo 2026
