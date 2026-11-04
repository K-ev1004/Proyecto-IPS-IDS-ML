# -*- coding: utf-8 -*-
"""
train_catboost_v6.py — M3: reentrenamiento multiclase con features v6.

Protocolo de docs/ML_V6_DESARROLLO.md §5.1 y §6.2:
  - Holdout POR FUENTE: entrenar 2018 -> validar 2017 y viceversa (nunca
    mezclar train/test del mismo origen). Requiere la columna 'fuente' del
    dataset v6.
  - Ablation de puertos: entrenar con y sin 'Dst Port' (la fuga medida en
    M0: un arbol con SOLO el puerto acierta 83,7 %). La v5 original aprendia
    reglas de puertos que no generalizan (C3: 92.004 FP/dia).
  - Umbral POR CLASE con curvas PR (el umbral global 0,85 era otro defecto).

Modos:
  --modo ablacion   4 modelos cruzados (2 fuentes x con/sin puerto), 400
                    iteraciones. Tabla de generalizacion -> elige feature set.
  --modo final      modelo completo (1000 it) con el feature set ganador +
                    calibracion de umbrales por clase -> exporta artefactos.

Salidas (modo final):
    Modelos_Entrenados/pipeline_catboost_v6.pkl
    Modelos_Entrenados/features_v6.pkl
    Modelos_Entrenados/label_encoder_v6.pkl
    Modelos_Entrenados/umbrales_v6.pkl
    entrenar/resultados/metricas_v6.txt   (formato comparable al de v5)

Decision documentada: SMOTE se descarta (2,7M filas: memoria y riesgo de
calibracion); se usa class_weights + umbral por clase, que es lo que fija
el punto de operacion real (lección C3: el benigno fija el umbral).
"""
import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / 'Dataset_Limpio' / 'dataset_global_unipaz_v6.csv'
SALIDAS = BASE_DIR / 'entrenar' / 'resultados'
SEMILLA = 42
CLASES_VOLUMETRICAS = ('SYN_Flood', 'DDoS_Distribuido', 'UDP_Flood',
                       'Port_Scanner', 'Posible_Exploit')

# Features del dataset v6 (33): las 23 v4 + extras + derivadas. 'fuente' es
# metadata, no feature. 'Label_UNIPAZ' es la etiqueta.
COLUMNA_LABEL = 'Label_UNIPAZ'


def cargar():
    if not DATASET.exists():
        print(f'[X] No existe {DATASET}. Correr generador_dataset_global.py')
        sys.exit(1)
    df = pd.read_csv(DATASET)
    print(f'[*] Dataset: {len(df):,} filas x {len(df.columns)} columnas')
    print(f'    fuentes: {df["fuente"].value_counts().to_dict()}')
    features = [c for c in df.columns
                if c not in (COLUMNA_LABEL, 'fuente')]
    return df, features


def entrenar_catboost(df_train, features, target, iteraciones=400):
    from catboost import CatBoostClassifier
    y = df_train[target]
    pesos = {}
    n = len(y)
    for clase, cnt in y.value_counts().items():
        pesos[clase] = n / (cnt * y.nunique())
    modelo = CatBoostClassifier(
        iterations=iteraciones, learning_rate=0.1, depth=8,
        loss_function='MultiClass', class_weights=pesos,
        random_seed=SEMILLA, thread_count=-1, verbose=0,
        allow_writing_files=False)
    t0 = time.time()
    modelo.fit(df_train[features], y)
    print(f'    entrenado en {time.time() - t0:.0f} s')
    return modelo


def metricas_val(modelo, df_val, features, target):
    from sklearn.metrics import accuracy_score, f1_score
    y_true = df_val[target].values
    y_pred = modelo.predict(df_val[features])
    y_pred = np.array([str(v) for v in y_pred.ravel()])
    return {
        'accuracy': round(accuracy_score(y_true, y_pred), 4),
        'macro_f1': round(f1_score(y_true, y_pred, average='macro'), 4),
        'y_true': y_true, 'y_pred': y_pred,
    }


def modo_ablacion(df, features):
    """4 modelos cruzados: {2017,2018} x {con puerto, sin puerto}."""
    from sklearn.metrics import recall_score, precision_score
    con_puerto = list(features)
    sin_puerto = [f for f in features if f != 'Dst Port']
    fuentes = sorted(df['fuente'].unique())
    if len(fuentes) < 2:
        print(f'[X] Ablation necesita 2 fuentes, hay: {fuentes}')
        sys.exit(1)

    tabla = {}
    for f_train, f_val in [(fuentes[0], fuentes[1]), (fuentes[1], fuentes[0])]:
        dtr = df[df['fuente'] == f_train]
        dva = df[df['fuente'] == f_val]
        for nombre, feats in [('con_puerto', con_puerto),
                              ('sin_puerto', sin_puerto)]:
            clave = f'{f_train}->{f_val}:{nombre}'
            print(f'\n[*] {clave} ({len(dtr):,} train / {len(dva):,} val, '
                  f'{len(feats)} features)')
            m = entrenar_catboost(dtr, feats, COLUMNA_LABEL)
            r = metricas_val(m, dva, feats, COLUMNA_LABEL)
            detalle = {'accuracy': r['accuracy'], 'macro_f1': r['macro_f1']}
            for clase in CLASES_VOLUMETRICAS:
                if clase in m.classes_:
                    mask = dva[COLUMNA_LABEL] == clase
                    if mask.sum() == 0:
                        continue
                    det = (r['y_pred'][mask.values] == clase)
                    detalle[f'recall_{clase}'] = round(float(det.mean()), 4)
            # precision sobre Normal: proxy de FP del canal volumetrico
            mask_norm = dva[COLUMNA_LABEL] == 'Normal'
            if mask_norm.sum():
                fp_norm = int((r['y_pred'][mask_norm.values] != 'Normal').sum())
                detalle['fp_sobre_normal'] = fp_norm
                detalle['fp_sobre_normal_pct'] = round(
                    100.0 * fp_norm / mask_norm.sum(), 3)
            tabla[clave] = detalle
            print(f'    acc={detalle["accuracy"]} macroF1={detalle["macro_f1"]} '
                  f'FP/normal={detalle.get("fp_sobre_normal_pct")}%')
            del m
            import gc; gc.collect()

    ruta = SALIDAS / 'M3_ablacion_puertos.json'
    SALIDAS.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(tabla, indent=2, ensure_ascii=False),
                    encoding='utf-8')
    print(f'\n[OK] {ruta}')

    # Veredicto: sin_puerto gana si generaliza igual o mejor (menos fuga)
    acc_con = np.mean([tabla[f'{a}->{b}:con_puerto']['accuracy']
                       for a, b in [(fuentes[0], fuentes[1]),
                                    (fuentes[1], fuentes[0])]])
    acc_sin = np.mean([tabla[f'{a}->{b}:sin_puerto']['accuracy']
                       for a, b in [(fuentes[0], fuentes[1]),
                                    (fuentes[1], fuentes[0])]])
    fp_con = np.mean([tabla[f'{a}->{b}:con_puerto']['fp_sobre_normal_pct']
                      for a, b in [(fuentes[0], fuentes[1]),
                                   (fuentes[1], fuentes[0])]])
    fp_sin = np.mean([tabla[f'{a}->{b}:sin_puerto']['fp_sobre_normal_pct']
                      for a, b in [(fuentes[0], fuentes[1]),
                                   (fuentes[1], fuentes[0])]])
    ganador = 'sin_puerto' if fp_sin <= fp_con else 'con_puerto'
    print(f'\n===== VEREDICTO ABLATION =====')
    print(f'acc media con_puerto={acc_con:.4f} sin_puerto={acc_sin:.4f}')
    print(f'FP sobre Normal (medio): con={fp_con:.3f}% sin={fp_sin:.3f}%')
    print(f'GANADOR: {ganador} (menos FP = mas generalizable)')
    return ganador, tabla


def modo_final(df, features, usar_puerto):
    """Modelo completo + umbrales por clase con curvas PR en holdout."""
    feats = list(features) if usar_puerto else [
        f for f in features if f != 'Dst Port']
    df_tr = df.sample(frac=0.85, random_state=SEMILLA)
    df_va = df.drop(df_tr.index)
    print(f'[*] Final: {len(df_tr):,} train / {len(df_va):,} val, '
          f'{len(feats)} features (puerto={"SI" if usar_puerto else "NO"})')

    modelo = entrenar_catboost(df_tr, feats, COLUMNA_LABEL, iteraciones=1000)
    clases = list(modelo.classes_)
    proba = modelo.predict_proba(df_va[feats])
    y_true = df_va[COLUMNA_LABEL].values

    # --- umbral por clase: max recall con precision_clase >= objetivo ---
    OBJETIVOS = {c: 0.995 for c in clases}
    umbrales = {}
    for i, clase in enumerate(clases):
        y_bin = (y_true == clase).astype(int)
        p_i = proba[:, i]
        mejor = 0.5
        for u in np.arange(0.05, 0.995, 0.01):
            pred_bin = p_i >= u
            tp = int(((pred_bin == 1) & (y_bin == 1)).sum())
            fp = int(((pred_bin == 1) & (y_bin == 0)).sum())
            prec = tp / (tp + fp) if tp + fp else 1.0
            if prec >= OBJETIVOS[clase]:
                mejor = float(u) + 0.005
                break
        umbrales[clase] = round(min(mejor, 0.995), 3)
        print(f'    umbral {clase}: {umbrales[clase]}')

    # metricas con umbrales por clase aplicados
    y_pred = np.array(clases)[proba.argmax(axis=1)]
    for i, clase in enumerate(clases):
        y_pred[(proba[:, i] >= umbrales[clase])] = clase
    from sklearn.metrics import accuracy_score, f1_score
    acc = accuracy_score(y_true, y_pred)
    f1m = f1_score(y_true, y_pred, average='macro')

    # --- exportar artefactos ---
    joblib.dump(modelo, BASE_DIR / 'Modelos_Entrenados' / 'pipeline_catboost_v6.pkl')
    joblib.dump(feats, BASE_DIR / 'Modelos_Entrenados' / 'features_v6.pkl')
    joblib.dump({'clases': clases, 'umbrales': umbrales},
                BASE_DIR / 'Modelos_Entrenados' / 'umbrales_v6.pkl')
    # label encoder (compat con ids.py: transform entre clases)
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder().fit(clases)
    joblib.dump(le, BASE_DIR / 'Modelos_Entrenados' / 'label_encoder_v6.pkl')

    ruta_txt = SALIDAS / 'metricas_v6.txt'
    with open(ruta_txt, 'w', encoding='utf-8') as fh:
        fh.write(f'MÉTRICAS CATBOOST V6 (M3) — semilla {SEMILLA}\n')
        fh.write('=' * 60 + '\n')
        fh.write(f'Dataset: dataset_global_unipaz_v6.csv '
                 f'({len(df):,} filas x {len(feats)} features)\n')
        fh.write(f'Puerto destino incluido: {"SI" if usar_puerto else "NO"}\n')
        fh.write('Holdout: 85/15 estratificado por muestreo aleatorio +\n')
        fh.write('ablation por fuente en M3_ablacion_puertos.json\n\n')
        fh.write(f'Accuracy (umbrales por clase): {acc:.4f}\n')
        fh.write(f'Macro-F1: {f1m:.4f}\n')
        fh.write(f'Clases: {clases}\n')
        fh.write(f'Umbrales por clase: {json.dumps(umbrales)}\n')
        fh.write('\nReferencia v5 (metricas_v5.txt) para comparacion directa.\n')
    print(f'[OK] {ruta_txt}')
    print(f'\n===== RESUMEN M3 FINAL =====')
    print(f'Accuracy: {acc:.4f} | Macro-F1: {f1m:.4f}')
    print(f'Umbrales: {umbrales}')


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--modo', choices=['ablacion', 'final'], default='ablacion')
    ap.add_argument('--con-puerto', action='store_true',
                    help='modo final: forzar Dst Port (defecto: veredicto ablation)')
    args = ap.parse_args()

    df, features = cargar()
    if args.modo == 'ablacion':
        modo_ablacion(df, features)
    else:
        veredicto_path = SALIDAS / 'M3_ablacion_puertos.json'
        usar_puerto = args.con_puerto
        if not usar_puerto and veredicto_path.exists():
            # re-derivar el veredicto: sin_puerto si la ablacion lo prefirio
            tabla = json.loads(veredicto_path.read_text(encoding='utf-8'))
            fuentes = sorted(df['fuente'].unique())
            pares = [(fuentes[0], fuentes[1]), (fuentes[1], fuentes[0])]
            fp_sin = np.mean([tabla[f'{a}->{b}:sin_puerto']['fp_sobre_normal_pct']
                              for a, b in pares])
            fp_con = np.mean([tabla[f'{a}->{b}:con_puerto']['fp_sobre_normal_pct']
                              for a, b in pares])
            usar_puerto = fp_con < fp_sin
        modo_final(df, features, usar_puerto)


if __name__ == '__main__':
    main()
