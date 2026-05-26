#!/usr/bin/env python3
"""
train_model.py
Entrena y compara 4 modelos de clasificación.
Guarda el mejor modelo (RandomForest) en models/
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # sin pantalla gráfica en servidor
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

# ─────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────
DATASET_PATH  = 'data/dataset.csv'
MODELS_DIR    = 'models'
LOGS_DIR      = 'logs'
PLOTS_DIR     = 'logs/plots'

FEATURES = [
    'total_pkts', 'tcp_pkts', 'udp_pkts', 'other_pkts',
    'unique_dports_count', 'syn_ratio', 'avg_pkt_size',
    'duration_sec', 'bytes_per_sec', 'port_scan_score',
    'small_syn_score', 'potential_flood', 'potential_scan',
]

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,  exist_ok=True)


# ─────────────────────────────────────────────
# 1. Cargar y preparar datos
# ─────────────────────────────────────────────
def load_data():
    print("[*] Cargando dataset...")
    df = pd.read_csv(DATASET_PATH)

    # Verificaciones básicas
    assert all(f in df.columns for f in FEATURES), "Faltan features en el dataset"
    assert 'label' in df.columns, "Falta columna label"
    assert df.isnull().sum().sum() == 0, "Dataset tiene valores NaN"

    X = df[FEATURES].values
    y = df['label'].values

    print(f"[*] Shape: {df.shape}")
    print(f"[*] Clases: {dict(pd.Series(y).value_counts())}")
    return X, y


# ─────────────────────────────────────────────
# 2. Definir modelos candidatos
# ─────────────────────────────────────────────
def get_models():
    return {
        'Random Forest': RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=10,
            class_weight='balanced',
            random_state=42,
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            random_state=42,
        ),
    }


# ─────────────────────────────────────────────
# 3. Entrenar y evaluar cada modelo
# ─────────────────────────────────────────────
def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    print(f"\n[*] Entrenando: {name}...")

    model.fit(X_train, y_train)
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

    # Convertir labels a binario para métricas
    le = LabelEncoder()
    y_test_bin = le.fit_transform(y_test)
    y_pred_bin = le.transform(y_pred)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label='attack', zero_division=0)
    rec  = recall_score(y_test, y_pred, pos_label='attack', zero_division=0)
    f1   = f1_score(y_test, y_pred, pos_label='attack', zero_division=0)
    auc  = roc_auc_score(y_test_bin, y_proba) if y_proba is not None else 0.0

    print(f"    Accuracy:  {acc:.4f}")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}  ← clave en seguridad")
    print(f"    F1-Score:  {f1:.4f}")
    print(f"    AUC-ROC:   {auc:.4f}")
    print(f"\n{classification_report(y_test, y_pred, zero_division=0)}")

    return {
        'name':      name,
        'model':     model,
        'accuracy':  acc,
        'precision': prec,
        'recall':    rec,
        'f1':        f1,
        'auc':       auc,
        'y_pred':    y_pred,
        'y_proba':   y_proba,
    }


# ─────────────────────────────────────────────
# 4. Gráfica comparativa de métricas
# ─────────────────────────────────────────────
def plot_metrics(results):
    names   = [r['name'] for r in results]
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    labels  = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC-ROC']

    x     = np.arange(len(metrics))
    width = 0.18
    fig, ax = plt.subplots(figsize=(12, 6))

    colors = ['#534AB7', '#1D9E75', '#D85A30', '#BA7517']

    for i, r in enumerate(results):
        vals = [r[m] for m in metrics]
        ax.bar(x + i * width, vals, width, label=r['name'], color=colors[i], alpha=0.85)

    ax.set_ylabel('Score')
    ax.set_title('Comparativa de métricas por modelo')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(labels)
    ax.set_ylim(0.8, 1.02)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    path = f'{PLOTS_DIR}/metrics_comparison.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Gráfica guardada: {path}")


# ─────────────────────────────────────────────
# 5. Curvas ROC
# ─────────────────────────────────────────────
def plot_roc_curves(results, y_test):
    le = LabelEncoder()
    y_test_bin = le.fit_transform(y_test)

    fig, ax = plt.subplots(figsize=(8, 6))
    colors  = ['#534AB7', '#1D9E75', '#D85A30', '#BA7517']

    for i, r in enumerate(results):
        if r['y_proba'] is not None:
            fpr, tpr, _ = roc_curve(y_test_bin, r['y_proba'])
            ax.plot(fpr, tpr, color=colors[i],
                    label=f"{r['name']} (AUC={r['auc']:.3f})", linewidth=2)

    ax.plot([0, 1], [0, 1], 'k--', alpha=0.4, label='Random (AUC=0.500)')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('Curvas ROC — comparativa de modelos')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)

    plt.tight_layout()
    path = f'{PLOTS_DIR}/roc_curves.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Curvas ROC guardadas: {path}")


# ─────────────────────────────────────────────
# 6. Matriz de confusión del mejor modelo
# ─────────────────────────────────────────────
def plot_confusion_matrix(best, y_test):
    cm     = confusion_matrix(y_test, best['y_pred'], labels=['normal', 'attack'])
    fig, ax = plt.subplots(figsize=(6, 5))

    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=['normal', 'attack'],
        yticklabels=['normal', 'attack'],
        ax=ax,
    )
    ax.set_xlabel('Predicho')
    ax.set_ylabel('Real')
    ax.set_title(f'Matriz de confusión — {best["name"]}')

    plt.tight_layout()
    path = f'{PLOTS_DIR}/confusion_matrix.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Matriz de confusión guardada: {path}")


# ─────────────────────────────────────────────
# 7. Importancia de features
# ─────────────────────────────────────────────
def plot_feature_importance(best_model):
    if not hasattr(best_model, 'feature_importances_'):
        return

    importances = best_model.feature_importances_
    indices     = np.argsort(importances)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(
        [FEATURES[i] for i in indices],
        importances[indices],
        color='#534AB7', alpha=0.8,
    )
    ax.set_xlabel('Importancia (Gini)')
    ax.set_title('Importancia de features — Random Forest')
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    path = f'{PLOTS_DIR}/feature_importance.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Importancia de features guardada: {path}")


# ─────────────────────────────────────────────
# 8. Guardar modelo y métricas
# ─────────────────────────────────────────────
def save_best_model(best, scaler, results):
    # Guardar modelo y scaler
    joblib.dump(best['model'],  f'{MODELS_DIR}/firewall_ai_model.joblib')
    joblib.dump(scaler,          f'{MODELS_DIR}/scaler.joblib')

    # Guardar métricas en JSON para el dashboard
    metrics_summary = []
    for r in results:
        metrics_summary.append({
            'model':     r['name'],
            'accuracy':  round(r['accuracy'],  4),
            'precision': round(r['precision'], 4),
            'recall':    round(r['recall'],    4),
            'f1':        round(r['f1'],        4),
            'auc':       round(r['auc'],       4),
        })

    with open(f'{MODELS_DIR}/metrics.json', 'w') as f:
        json.dump(metrics_summary, f, indent=2)

    print(f"\n[+] Modelo guardado: {MODELS_DIR}/firewall_ai_model.joblib")
    print(f"[+] Scaler guardado: {MODELS_DIR}/scaler.joblib")
    print(f"[+] Métricas guardadas: {MODELS_DIR}/metrics.json")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  Entrenamiento del modelo Firewall IA")
    print("=" * 55)

    # Cargar datos
    X, y = load_data()

    # Split estratificado 70/30
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    # Escalar features
    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    print(f"[*] Train: {X_train_sc.shape} | Test: {X_test_sc.shape}")

    # Entrenar y evaluar todos los modelos
    results = []
    for name, model in get_models().items():
        r = evaluate_model(name, model, X_train_sc, X_test_sc, y_train, y_test)
        results.append(r)

    # Seleccionar mejor modelo por F1 en clase attack
    best = max(results, key=lambda r: r['f1'])
    print(f"\n{'=' * 55}")
    print(f"  Mejor modelo: {best['name']}")
    print(f"  F1={best['f1']:.4f} | AUC={best['auc']:.4f} | Recall={best['recall']:.4f}")
    print(f"{'=' * 55}")

    # Tabla comparativa
    print("\n--- Tabla comparativa ---")
    print(f"{'Modelo':<22} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6}")
    print("-" * 55)
    for r in results:
        print(f"{r['name']:<22} {r['accuracy']:>6.3f} {r['precision']:>6.3f} "
              f"{r['recall']:>6.3f} {r['f1']:>6.3f} {r['auc']:>6.3f}")

    # Generar gráficas
    print("\n[*] Generando gráficas...")
    plot_metrics(results)
    plot_roc_curves(results, y_test)
    plot_confusion_matrix(best, y_test)
    plot_feature_importance(best['model'])

    # Guardar modelo
    save_best_model(best, scaler, results)

    print("\n[OK] Entrenamiento completado.")
    print(f"[OK] Gráficas en: {PLOTS_DIR}/")


if __name__ == '__main__':
    main()
