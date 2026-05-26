#!/usr/bin/env python3
"""
build_dataset.py
Combina normal.csv y attack.csv en un dataset final balanceado.
"""

import pandas as pd
import numpy as np
import os

RAW_DIR    = 'data/raw'
OUTPUT     = 'data/dataset.csv'

def build_dataset():
    # Cargar ambos CSV
    normal_path = os.path.join(RAW_DIR, 'normal.csv')
    attack_path = os.path.join(RAW_DIR, 'attack.csv')

    df_normal = pd.read_csv(normal_path)
    df_attack = pd.read_csv(attack_path)

    print(f"[*] Muestras normales: {len(df_normal)}")
    print(f"[*] Muestras de ataque: {len(df_attack)}")

    # Verificar balance — ratio máximo 3:1
    ratio = max(len(df_normal), len(df_attack)) / max(min(len(df_normal), len(df_attack)), 1)
    print(f"[*] Ratio de clases: {ratio:.2f}:1")

    if ratio > 3:
        print("[!] Dataset muy desbalanceado, aplicando undersampling...")
        min_count = min(len(df_normal), len(df_attack))
        max_count = min_count * 3
        if len(df_normal) > len(df_attack):
            df_normal = df_normal.sample(n=max_count, random_state=42)
        else:
            df_attack = df_attack.sample(n=max_count, random_state=42)
        print(f"[*] Tras balanceo — normal: {len(df_normal)}, attack: {len(df_attack)}")

    # Combinar y mezclar
    df = pd.concat([df_normal, df_attack], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Eliminar columna src_ip del dataset final (no es una feature)
    if 'src_ip' in df.columns:
        df = df.drop(columns=['src_ip'])

    # Verificar que no haya NaN
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        print(f"[!] Encontrados {nan_count} valores NaN — rellenando con 0")
        df = df.fillna(0)

    # Guardar
    df.to_csv(OUTPUT, index=False)

    print(f"\n[+] Dataset final guardado en: {OUTPUT}")
    print(f"[+] Shape: {df.shape}")
    print(f"[+] Columnas: {list(df.columns)}")
    print(f"\n--- Distribución de clases ---")
    print(df['label'].value_counts())
    print(f"\n--- Estadísticas generales ---")
    print(df.describe().to_string())


if __name__ == '__main__':
    build_dataset()
