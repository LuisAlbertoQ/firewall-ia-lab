#!/usr/bin/env python3
"""
extract_features.py
Extrae 13 features por IP de origen desde archivos .pcap de forma eficiente.
Uso: python3 extract_features.py <archivo.pcap> <label> <salida.csv>
"""

import sys
import os
import pandas as pd
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from collections import defaultdict


def extract_features(pcap_file: str, label: str) -> pd.DataFrame:
    """
    Lee un archivo pcap eficientemente y extrae features por IP de origen.
    
    Args:
        pcap_file: ruta al archivo .pcap
        label: 'normal' o 'attack'
    
    Returns:
        DataFrame con una fila por IP de origen
    """
    print(f"[*] Leyendo {pcap_file} de forma eficiente...")
    
    # Diccionario de flujos por IP de origen
    flows = defaultdict(lambda: {
        'total_pkts':     0,
        'tcp_pkts':       0,
        'udp_pkts':       0,
        'other_pkts':     0,
        'syn_pkts':       0,
        'total_bytes':    0,
        'pkt_sizes':      [],
        'unique_dports':  set(),
        'timestamps':     [],
    })

    # Contador para informar el progreso
    pkt_count = 0

    try:
        # PcapReader procesa el archivo bloque a bloque sin saturar la RAM
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                pkt_count += 1
                if pkt_count % 100000 == 0:
                    print(f"[*] Procesados {pkt_count} paquetes...")

                if IP not in pkt:
                    continue

                src = pkt[IP].src
                size = len(pkt)

                flows[src]['total_pkts']  += 1
                flows[src]['total_bytes'] += size
                flows[src]['pkt_sizes'].append(size)
                flows[src]['timestamps'].append(float(pkt.time))

                if TCP in pkt:
                    flows[src]['tcp_pkts'] += 1
                    flows[src]['unique_dports'].add(pkt[TCP].dport)
                    # Detectar flag SYN (0x02) sin ACK (0x10) = SYN puro
                    if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
                        flows[src]['syn_pkts'] += 1

                elif UDP in pkt:
                    flows[src]['udp_pkts'] += 1
                    flows[src]['unique_dports'].add(pkt[UDP].dport)

                else:
                    flows[src]['other_pkts'] += 1
    except Exception as e:
        print(f"[!] Error leyendo pcap: {e}")
        sys.exit(1)

    print(f"[*] Total paquetes procesados: {pkt_count}")

    # Construir el DataFrame de features
    rows = []

    for ip, d in flows.items():
        total     = d['total_pkts']
        tcp       = d['tcp_pkts']
        udp       = d['udp_pkts']
        syn       = d['syn_pkts']
        bytes_    = d['total_bytes']
        sizes     = d['pkt_sizes']
        dports    = d['unique_dports']
        times     = sorted(d['timestamps'])

        # Duración del flujo en segundos
        duration  = (times[-1] - times[0]) if len(times) > 1 else 0.001

        # Features calculadas
        avg_pkt_size    = np.mean(sizes) if sizes else 0
        syn_ratio       = syn / tcp if tcp > 0 else 0
        bytes_per_sec   = bytes_ / duration if duration > 0 else 0
        unique_dports_c = len(dports)
        port_scan_score = unique_dports_c / total if total > 0 else 0
        small_syn_score = (syn_ratio / avg_pkt_size * 10000) if avg_pkt_size > 0 else 0
        potential_flood = int(syn_ratio > 0.5 and total > 500)
        potential_scan  = int(unique_dports_c > 100)

        rows.append({
            'src_ip':             ip,
            'total_pkts':         total,
            'tcp_pkts':           tcp,
            'udp_pkts':           udp,
            'other_pkts':         d['other_pkts'],
            'unique_dports_count': unique_dports_c,
            'syn_ratio':          round(syn_ratio, 4),
            'avg_pkt_size':       round(avg_pkt_size, 2),
            'duration_sec':       round(duration, 4),
            'bytes_per_sec':      round(bytes_per_sec, 2),
            'port_scan_score':    round(port_scan_score, 4),
            'small_syn_score':    round(small_syn_score, 4),
            'potential_flood':    potential_flood,
            'potential_scan':     potential_scan,
            'label':              label,
        })

    df = pd.DataFrame(rows)
    print(f"[*] IPs únicas encontradas: {len(df)}")
    print(f"[*] Features extraídas: {len(df.columns) - 2} (+ src_ip + label)")
    return df


def main():
    if len(sys.argv) != 4:
        print("Uso: python3 extract_features.py <archivo.pcap> <label> <salida.csv>")
        print("  label: 'normal' o 'attack'")
        print("  Ejemplo: python3 extract_features.py traffic-normal.pcap normal normal.csv")
        sys.exit(1)

    pcap_file  = sys.argv[1]
    label      = sys.argv[2]
    output_csv = sys.argv[3]

    if label not in ('normal', 'attack'):
        print("[!] El label debe ser 'normal' o 'attack'")
        sys.exit(1)

    if not os.path.exists(pcap_file):
        print(f"[!] Archivo no encontrado: {pcap_file}")
        sys.exit(1)

    df = extract_features(pcap_file, label)

    df.to_csv(output_csv, index=False)
    print(f"[+] Dataset guardado en: {output_csv}")
    print(f"[+] Shape: {df.shape}")
    print("\n--- Primeras 3 filas ---")
    print(df.head(3).to_string())
    print("\n--- Estadísticas ---")
    print(df.describe().to_string())


if __name__ == '__main__':
    main()
