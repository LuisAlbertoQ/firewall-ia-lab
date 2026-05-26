# 🛡️ Firewall Inteligente con Machine Learning  
### `firewall-ia-lab`

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%2022.04-orange?logo=ubuntu)
![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-f7931e?logo=scikitlearn)
![Flask](https://img.shields.io/badge/Web-Flask-black?logo=flask)
![nftables](https://img.shields.io/badge/Firewall-nftables-green)
![License](https://img.shields.io/badge/License-Educational-lightgrey)

Sistema experimental de **ciberseguridad ofensiva y defensiva** que integra un firewall basado en **nftables** con un modelo de **Machine Learning** para detectar, clasificar y bloquear tráfico malicioso en tiempo real.

El proyecto simula un entorno de laboratorio donde una IA analiza patrones de red y toma decisiones automáticas de mitigación sobre conexiones sospechosas.

---

# 🚀 Características Principales

- 🔥 Firewall dinámico usando **nftables**
- 🤖 Detección inteligente de tráfico malicioso mediante **Random Forest**
- 📡 Captura y análisis de paquetes en tiempo real
- 📊 Dashboard web interactivo con métricas en vivo
- 🚫 Bloqueo automático de IPs sospechosas
- 📧 Sistema de alertas por correo electrónico
- 🧠 Pipeline completo de entrenamiento y evaluación ML
- 🛠️ Scripts de automatización y diagnóstico

---

# 🗺️ Arquitectura del Laboratorio

```text
                         INTERNET
                             │
                             ▼
        ┌──────────────────────────────────┐
        │ Ubuntu Server 22.04 LTS         │
        │ Router + Firewall + IA Engine   │
        │                                  │
        │  • nftables                      │
        │  • RandomForest Classifier       │
        │  • Scapy / tcpdump               │
        │  • Flask Dashboard               │
        └──────────────┬───────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼

 ┌────────────────┐        ┌────────────────┐
 │ Kali Linux     │        │ Linux Mint     │
 │ 192.168.10.10  │        │ 192.168.10.20  │
 │ Máquina atacante│       │ Cliente legítimo│
 └────────────────┘        └────────────────┘
```

---

# ⚙️ Stack Tecnológico

| Área | Tecnología |
|---|---|
| **Sistema Operativo** | Ubuntu Server 22.04 LTS |
| **Firewall** | nftables |
| **Captura de tráfico** | Scapy + tcpdump |
| **Machine Learning** | scikit-learn |
| **Modelo principal** | Random Forest |
| **Backend Dashboard** | Flask + Flask-SocketIO |
| **Frontend Dashboard** | HTML + Chart.js |
| **Alertas** | SMTP (Gmail Secure Alerts) |
| **Automatización** | Bash + Systemd |

---

# 📁 Estructura del Proyecto

```text
firewall-ia-lab/
│
├── ai_firewall.py
├── alerter.py
├── extract_features.py
├── train_model.py
├── build_dataset.py
├── rebuild_dataset.py
├── test_alert.py
│
├── nftables.conf
├── requirements.txt
│
├── fw_block.sh
├── fw_unblock.sh
├── fw_status.sh
├── show_decisions.sh
│
├── data/
│   └── raw/
│       ├── attack.csv
│       └── normal.csv
│
├── models/
│   ├── firewall_ai_model.joblib
│   └── scaler.joblib
│
└── dashboard/
    ├── app.py
    └── templates/
        └── index.html
```

---

# 🧠 Flujo de Funcionamiento

```text
Captura de tráfico
        │
        ▼
Extracción de features
        │
        ▼
Modelo RandomForest
        │
 ┌──────┴──────┐
 ▼             ▼
NORMAL      MALICIOSO
 │             │
 ▼             ▼
Permitir    Bloquear IP
                  │
                  ▼
        Actualizar nftables
                  │
                  ▼
        Registrar evento + alerta
```

---

# 📊 Rendimiento del Modelo

Evaluación comparativa usando tráfico generado en el laboratorio:

| Modelo | Accuracy | Precision | Recall | F1-Score | AUC |
|---|---:|---:|---:|---:|---:|
| 🏆 **Random Forest** | **97.4%** | **97.5%** | **97.2%** | **97.4%** | **99.7%** |
| Gradient Boosting | 96.8% | 96.9% | 96.8% | 96.8% | 99.5% |
| Decision Tree | 95.4% | 95.5% | 95.4% | 95.4% | 95.4% |
| Logistic Regression | 92.1% | 92.2% | 92.1% | 92.1% | 98.1% |

---

# 🧪 Escenarios Simulados

El laboratorio fue probado contra:

- Escaneos de puertos (`nmap`)
- Ataques de denegación de servicio básicos
- Tráfico anómalo repetitivo
- Conexiones sospechosas automatizadas
- Tráfico legítimo de usuarios internos

---

# 🚀 Instalación

## 1️⃣ Clonar el repositorio

```bash
git clone https://github.com/TU-USUARIO/firewall-ia-lab.git

cd firewall-ia-lab
```

---

## 2️⃣ Crear entorno virtual

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## 3️⃣ Instalar dependencias

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Aplicar reglas del firewall

```bash
sudo nft -f nftables.conf
```

---

## 5️⃣ Iniciar servicios

```bash
sudo systemctl start ai-firewall

sudo systemctl start ai-dashboard
```

---

# 🛠️ Comandos Útiles

## Ver estado de servicios

```bash
sudo systemctl status ai-firewall ai-dashboard
```

---

## Ver IPs bloqueadas por IA

```bash
sudo nft list set inet filter ia_blocklist
```

---

## Revisar decisiones del motor IA

```bash
./show_decisions.sh
```

---

## Estado general del firewall

```bash
./fw_status.sh
```

---

# 🌐 Dashboard Web

Panel interactivo con:

- Tráfico en tiempo real
- IPs bloqueadas
- Eventos recientes
- Alertas generadas
- Métricas del modelo

### Acceso:

```text
http://192.168.10.1:5000
```

Actualización automática mediante **WebSockets** cada 5 segundos.

---

# 🖥️ Configuración del Laboratorio

| Máquina | IP | Función |
|---|---|---|
| Ubuntu Server | `192.168.10.1` | Gateway + Firewall + IA |
| Kali Linux | `192.168.10.10` | Máquina atacante |
| Linux Mint | `192.168.10.20` | Cliente legítimo |

---

# 🔐 Consideraciones de Seguridad

- Proyecto orientado a entornos educativos y de laboratorio
- No usar directamente en producción sin hardening adicional
- Recomendable ejecutar en red aislada o virtualizada
- Ajustar reglas nftables según el entorno real

---

# 📚 Objetivos Educativos

Este proyecto permite practicar:

- Seguridad ofensiva y defensiva
- Administración de firewalls Linux
- Machine Learning aplicado a ciberseguridad
- Análisis de tráfico de red
- Automatización de respuestas defensivas
- Visualización de eventos en tiempo real

---

# 📌 Futuras Mejoras

- [ ] Detección basada en Deep Learning
- [ ] Integración con Suricata o Zeek
- [ ] Panel de administración avanzado
- [ ] Exportación de logs SIEM
- [ ] Soporte IPv6
- [ ] Integración con Telegram/Discord alerts
- [ ] Detección de anomalías no supervisada

---

# 📄 Licencia

Proyecto académico y experimental con fines educativos.

---

# 👨‍💻 Autor

**LuisAlbertoQ**  
📅 Versión 1.0 — Mayo 2026
