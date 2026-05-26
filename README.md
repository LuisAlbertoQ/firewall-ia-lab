# 🛡️ Firewall con Inteligencia Artificial (firewall-ia-lab)

![Python](https://shields.io)
![Linux](https://shields.io)
![Scikit-Learn](https://shields.io)
![Flask](https://shields.io)

Laboratorio práctico de ciberseguridad avanzada. Implementa un firewall adaptativo que combina **nftables** con un modelo de Machine Learning (**RandomForest**) para la detección, mitigación y bloqueo automático de tráfico malicioso en tiempo real.

---

## 🗺️ Arquitectura de Red

Internet ──> [ Ubuntu Server (Router / Firewall / IA) ] ──> Red Interna│┌───────┴───────┐▼               ▼nftables + IA   Dashboard Web│├──> [ Kali Linux ] (Atacante: 192.168.10.10)└──> [ Linux Mint ] (Legítimo: 192.168.10.20)
---

## 💻 Stack Tecnológico


| Componente | Herramienta / Tecnología |
| :--- | :--- |
| **Sistema Operativo** | Ubuntu Server 22.04 LTS |
| **Seguridad de Red** | nftables (Framework de filtrado de paquetes) |
| **Análisis de Tráfico** | scapy + tcpdump |
| **Pipeline de ML** | scikit-learn (Algoritmo principal: RandomForest) |
| **Visualización** | Flask + Socket.IO + Chart.js (Dashboard en tiempo real) |
| **Notificaciones** | SMTP (Secure Gmail Alerter) |

---

## 📁 Estructura del Proyecto

```text
firewall-ia-lab/
├── ai_firewall.py          # Motor de inferencia IA y toma de decisiones
├── alerter.py              # Módulo de alertas automáticas por email
├── extract_features.py     # Extractor de 13 características (features) desde red/pcap
├── train_model.py          # Script de entrenamiento y evaluación de modelos
├── build_dataset.py        # Generador del dataset base balanceado
├── rebuild_dataset.py      # Rebalanceo dinámico con nuevas muestras capturadas
├── test_alert.py           # Script de diagnóstico para el sistema de alertas
├── nftables.conf           # Reglas base del firewall y definición de conjuntos (sets)
├── requirements.txt        # Dependencias congeladas del entorno virtual
├── fw_block.sh             # Script auxiliar para bloquear IPs sospechosas
├── fw_unblock.sh           # Script auxiliar para desbloquear IPs de la lista
├── fw_status.sh            # Script para verificar estado del firewall
├── show_decisions.sh       # Utilidad para formatear el registro de decisiones
├── data/
│   └── raw/                # Archivos CSV intermedios (attack.csv, normal.csv)
├── models/
│   ├── firewall_ai_model.joblib # Binario del modelo entrenado óptimo
│   └── scaler.joblib            # Escalador de características normalizado
└── dashboard/
    ├── app.py              # Servidor Web Flask backend
    └── templates/
        └── index.html      # Interfaz de usuario frontend interactiva
```

---

## 📊 Métricas de Rendimiento del Modelo

Evaluación comparativa realizada sobre el tráfico capturado en el laboratorio:


| Algoritmo / Modelo | Accuracy | Precision | Recall | F1-Score | AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **🏆 Random Forest** | **0.974** | **0.975** | **0.972** | **0.974** | **0.997** |
| Gradient Boosting | 0.968 | 0.969 | 0.968 | 0.968 | 0.995 |
| Decision Tree | 0.954 | 0.955 | 0.954 | 0.954 | 0.954 |
| Logistic Regression | 0.921 | 0.922 | 0.921 | 0.921 | 0.981 |

---

## 🚀 Instalación y Despliegue Rápido

### 1. Clonación del Entorno
```bash
git clone https://github.com
cd firewall-ia-lab
```

### 2. Configuración del Entorno Virtual (Python)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Aplicar Políticas del Firewall
```bash
sudo nft -f nftables.conf
```

### 4. Lanzamiento de Servicios
*(Se recomienda configurar como servicios Systemd usando los archivos en tu servidor)*
```bash
# Iniciar servicios del laboratorio
sudo systemctl start ai-firewall
sudo systemctl start ai-dashboard
```

---

## 🛠️ Operación y Diagnóstico

### Monitorear Servicios
```bash
sudo systemctl status ai-firewall ai-dashboard
```

### Inspeccionar la Lista Negra Activa (IPs Bloqueadas por IA)
```bash
sudo nft list set inet filter ia_blocklist
```

### Revisar Historial de Decisiones del Motor
```bash
./show_decisions.sh
```

### Acceso al Dashboard Web
Actualizaciones dinámicas cada 5 segundos mediante sockets:
👉 **`http://192.168.10.1:5000`**

---

## 🌐 Configuración del Laboratorio de Pruebas


| Máquina Virtual | Dirección IP | Rol en el Laboratorio |
| :--- | :--- | :--- |
| **Ubuntu Server** | `192.168.10.1` | Gateway + Firewall Perimetral + Motor IA |
| **Kali Linux** | `192.168.10.10` | Vector de ataque externo (Escaneos, DoS) |
| **Linux Mint** | `192.168.10.20` | Cliente interno / Tráfico legítimo |

---

## 📖 Notas Educativas
Proyecto con fines puramente académicos y de investigación en el ámbito de la automatización de la ciberdefensa.

**Autor:** LuisAlbertoQ  
**Versión:** 1.0 — Mayo 2026
