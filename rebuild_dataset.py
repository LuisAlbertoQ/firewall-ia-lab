#!/usr/bin/env python3
"""
rebuild_dataset.py
Reconstruye el dataset combinando todos los CSV disponibles
y asegura un balance 1:1 entre normal y attack.
"""

import pandas as pd
import numpy as np
import os
import glob

RAW_DIR = 'data/raw'
OUTPUT  = 'data/dataset.csv'

def rebuild():
    # Cargar todos los CSV normales
    normal_files = glob.glob(f'{RAW_DIR}/normal*.csv')
    attack_files = glob.glob(f'{RAW_DIR}/attack*.csv')

    print(f"[*] Archivos normales encontrados: {normal_files}")
    print(f"[*] Archivos de ataque encontrados: {attack_files}")

    dfs_normal = []
    for f in normal_files:
        df = pd.read_csv(f)
        dfs_normal.append(df)
        print(f"    {f}: {len(df)} muestras")

    dfs_attack = []
    for f in attack_files:
        df = pd.read_csv(f)
        dfs_attack.append(df)
        print(f"    {f}: {len(df)} muestras")

    df_normal = pd.concat(dfs_normal, ignore_index=True)
    df_attack = pd.concat(dfs_attack, ignore_index=True)

    # Eliminar duplicados por src_ip manteniendo el último
    if 'src_ip' in df_normal.columns:
        df_normal = df_normal.drop_duplicates(subset=['src_ip'], keep='last')
        df_attack = df_attack.drop_duplicates(subset=['src_ip'], keep='last')

    print(f"\n[*] Total normal antes de balanceo: {len(df_normal)}")
    print(f"[*] Total attack antes de balanceo: {len(df_attack)}")

    # Balanceo 1:1
    min_count = min(len(df_normal), len(df_attack))

    # Si hay muchos más de un tipo, hacer oversample del menor
    # y undersample del mayor para llegar a min_count * 1.5
    target = max(min_count, int(min_count * 1.5))
    target = min(target, max(len(df_normal), len(df_attack)))

    if len(df_normal) < target:
        # Oversample normal con ruido gaussiano pequeño
        extras_needed = target - len(df_normal)
        sample = df_normal.sample(
            n=extras_needed, replace=True, random_state=42
        )
        # Agregar ruido pequeño a features numéricas
        numeric_cols = [c for c in sample.columns
                       if c not in ['src_ip', 'label',
                                    'potential_flood', 'potential_scan']]
        noise = np.random.normal(0, 0.01, sample[numeric_cols].shape)
        sample[numeric_cols] = (sample[numeric_cols].values + noise).clip(min=0)
        df_normal = pd.concat([df_normal, sample], ignore_index=True)
        print(f"[*] Oversample normal: +{extras_needed} muestras sintéticas")

    if len(df_attack) < target:
        extras_needed = target - len(df_attack)
        sample = df_attack.sample(
            n=extras_needed, replace=True, random_state=42
        )
        numeric_cols = [c for c in sample.columns
                       if c not in ['src_ip', 'label',
                                    'potential_flood', 'potential_scan']]
        noise = np.random.normal(0, 0.01, sample[numeric_cols].shape)
        sample[numeric_cols] = (sample[numeric_cols].values + noise).clip(min=0)
        df_attack = pd.concat([df_attack, sample], ignore_index=True)
        print(f"[*] Oversample attack: +{extras_needed} muestras sintéticas")

    # Undersample al mismo tamaño
    min_final = min(len(df_normal), len(df_attack))
    df_normal = df_normal.sample(n=min_final, random_state=42)
    df_attack = df_attack.sample(n=min_final, random_state=42)

    # Combinar y mezclar
    df = pd.concat([df_normal, df_attack], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Eliminar src_ip
    if 'src_ip' in df.columns:
        df = df.drop(columns=['src_ip'])

    # Limpiar NaN
    df = df.fillna(0)

    # Guardar
    df.to_csv(OUTPUT, index=False)

    print(f"\n[+] Dataset reconstruido: {OUTPUT}")
    print(f"[+] Shape final: {df.shape}")
    print(f"[+] Distribución de clases:")
    print(df['label'].value_counts())
    print(f"\n--- Comparativa de medias por clase ---")
    print(df.groupby('label')[
        ['total_pkts', 'syn_ratio',
         'unique_dports_count', 'avg_pkt_size']
    ].mean().round(3))

if __name__ == '__main__':
    rebuild()
