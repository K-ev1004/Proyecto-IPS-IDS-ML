# -*- coding: utf-8 -*-
"""
graficar_curva_sqli_guard.py — Curva Precision/Recall de SQLiGuard
==================================================================
Justificación académica del umbral canónico (0.30) del detector binario
de Inyección SQL. Evalúa la RUTA DE PRODUCCIÓN exacta (ids._features_sqli_guard
+ ids.sqli_guard) sobre el dataset externo D2 (Zenodo, 57,229 flujos NetFlow).

Salidas:
  docs/ml/curva_sqli_guard.csv  : tabla completa de la curva por umbral
  docs/ml/curva_sqli_guard.png  : PR (recall vs precision) + F1 + tasa FP
"""

import os
import sys
import numpy as np
import pandas as pd

os.environ.setdefault('MPLBACKEND', 'Agg')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import ids  # carga modelos v5 + SQLiGuard (ruta de producción)

SALIDA_CSV = os.path.join(BASE_DIR, "docs", "ml", "curva_sqli_guard.csv")
SALIDA_PNG = os.path.join(BASE_DIR, "docs", "ml", "curva_sqli_guard.png")
D2_PATH = os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo", "D2_test.csv")

UMBRALES_CLAVE = [0.10, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50]


def netflow_a_cic_fecha(row):
    """Convierte una fila NetFlow (D2) al dict CIC que consume la cadena.
    Copia exacta del helper de test_masivo.py."""
    dv = abs(float(row['last']) - float(row['first']))
    dur_ms = max(dv, 1e-6)
    prot = int(row.get('prot', 0))
    flags = int(row.get('tcp_flags', 0))
    def cnt(bit):
        return 1 if flags & bit else 0
    total_pkts = int(row.get('dpkts', 0))
    total_bytes = int(row.get('doctets', 0))
    dur_s = dur_ms / 1000.0
    feat = {
        'Src Port': float(row.get('srcport', 0)),
        'Dst Port': float(row.get('dstport', 0)),
        'Protocol': prot,
        'Flow Duration': dur_ms * 1000.0,
        'Tot Fwd Pkts': total_pkts, 'Tot Bwd Pkts': 0,
        'TotLen Fwd Pkts': total_bytes, 'TotLen Bwd Pkts': 0,
        'Flow Byts/s': total_bytes / dur_s,
        'Flow Pkts/s': total_pkts / dur_s,
        'FIN Flag Cnt': cnt(1), 'SYN Flag Cnt': cnt(2),
        'RST Flag Cnt': cnt(4), 'PSH Flag Cnt': cnt(8),
        'ACK Flag Cnt': cnt(16), 'URG Flag Cnt': cnt(32),
        '_y': 1 if int(row.get('Label', 0)) == 1 else 0,
    }
    return feat


def main():
    feats = list(ids.SQLI_GUARD_FEATURES)
    d2 = pd.read_csv(D2_PATH)
    print(f"[*] D2 cargado: {len(d2):,} flujos")

    filas, y_true = [], []
    for _, r in d2.iterrows():
        cic = netflow_a_cic_fecha(r)
        filas.append([ids._features_sqli_guard(cic)[k] for k in feats])
        y_true.append(cic['_y'])
    G = pd.DataFrame(filas, columns=feats)
    y = np.array(y_true)

    proba = ids.sqli_guard.predict_proba(G)[:, 1]
    print(f"[*] Predicciones (ruta producción): {len(proba):,} | "
          f"benignos={int((y==0).sum()):,} ataques={int((y==1).sum()):,}")

    # Barrido de umbrales: malla ancha + malla fina en la zona de interés
    umbrales = np.unique(np.concatenate([
        np.arange(0.05, 0.951, 0.05),
        np.arange(0.10, 0.501, 0.01),
    ]))

    registros = []
    for umbral in umbrales:
        pred = (proba >= umbral).astype(int)
        tn = int(((pred == 0) & (y == 0)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        tp = int(((pred == 1) & (y == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        tasa_fp = fp / (fp + tn) if (fp + tn) else 0.0
        registros.append({
            'umbral': float(umbral), 'precision': round(precision, 4),
            'recall': round(recall, 4), 'f1': round(f1, 4),
            'tasa_fp': round(tasa_fp, 5), 'tn': tn, 'fp': fp,
            'fn': fn, 'tp': tp,
        })

    df = pd.DataFrame(registros)

    def punto(u):
        row = df.iloc[(df['umbral'] - u).abs().idxmin()]
        return row

    print("\n=== Puntos clave de la curva (para la tesis) ===")
    for u in UMBRALES_CLAVE:
        r = punto(u)
        print(f"  umbral={u:4.2f} | precision={r['precision']:.4f} "
              f"recall={r['recall']:.4f} f1={r['f1']:.4f} "
              f"FP={r['fp']} FP/benigno={r['tasa_fp']:.4%}")

    mejor_f1 = df.loc[df['f1'].idxmax()]
    print(f"\n[+] Mejor F1: {mejor_f1['f1']:.4f} en umbral {mejor_f1['umbral']:.2f}")

    df.to_csv(SALIDA_CSV, index=False)
    print(f"[+] CSV guardado: {SALIDA_CSV} ({len(df)} umbrales)")

    # --- Gráfica ---
    p30, p50 = punto(0.30), punto(0.50)
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    ax = axes[0]
    ax.plot(df['recall'], df['precision'], '-o', ms=3, lw=1.5,
            color='#1f77b4', label='SQLiGuard (D2 externo)')
    for p, color, tag in [(p30, '#d62728', '0.30 (canónico)'),
                          (p50, '#2ca02c', '0.50 (histórico)')]:
        ax.plot(p['recall'], p['precision'], 'o', ms=9, color=color)
        ax.annotate(tag + f"\n(P={p['precision']:.3f}, R={p['recall']:.3f})",
                    xy=(p['recall'], p['precision']),
                    xytext=(0.08, -0.34), textcoords='offset points',
                    fontsize=8, color=color)
    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')
    ax.set_title('Curva Precision-Recall de SQLiGuard')
    ax.grid(True, alpha=0.3)
    ax.legend(loc='lower left', fontsize=8)

    ax = axes[1]
    ax.plot(df['umbral'], df['f1'], '-o', ms=3, lw=1.5, color='#9467bd')
    for p in (p30, p50):
        ax.axvline(p['umbral'], ls='--', lw=1, color='#d62728' if p is p30 else '#2ca02c', alpha=0.7)
        ax.plot(p['umbral'], p['f1'], 'o', ms=8, color='#d62728' if p is p30 else '#2ca02c')
    ax.set_xlabel('Umbral')
    ax.set_ylabel('F1-score')
    ax.set_title('F1 por umbral de confirmación')
    ax.grid(True, alpha=0.3)

    ax = axes[2]
    ax.plot(df['umbral'], df['tasa_fp'] * 100, '-o', ms=3, lw=1.5, color='#ff7f0e')
    for p in (p30, p50):
        ax.axvline(p['umbral'], ls='--', lw=1,
                   color='#d62728' if p is p30 else '#2ca02c', alpha=0.7)
    ax.set_xlabel('Umbral')
    ax.set_ylabel('Tasa FP sobre benigno (%)')
    ax.set_title('Falsos positivos por umbral')
    ax.grid(True, alpha=0.3)

    fig.suptitle('Justificación del umbral de SQLiGuard — 57,229 flujos D2 (Zenodo, ruta producción)')
    fig.tight_layout()
    fig.savefig(SALIDA_PNG, dpi=150)
    print(f"[+] PNG guardado: {SALIDA_PNG}")


if __name__ == '__main__':
    main()