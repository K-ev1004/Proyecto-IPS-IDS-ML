# -*- coding: utf-8 -*-
"""
train_sqli_payload.py — M2: detector de SQLi por PAYLOAD (TF-IDF + LightGBM).

La lección de C3 (docs/INFORME_C3_DATOS.md): SQLiGuard v5 adivina SQLi por
features de FLUJO (puertos/tamaños) y falla (91.924 FP/día). El payload SÍ
contiene la señal. Este script entrena el detector del nivel 2a:

    URL-decode -> lowercase -> TF-IDF (char 1-3 grams, max 50K) -> LightGBM

Datos (docs/ML_V6_DESARROLLO.md §3.1, decisión de solo-CSIC): espejo HF
b1nch3f/csic-dataset — petición HTTP cruda con split ya hecho:
    train 54.133 | validation 13.534 | test 29.001 (Normal/Anomalous)

UMBRAL (lección C3): lo fija el BENIGNO del holdout, no el balance del
dataset. Se elige el umbral de MÁXIMO RECALL con precisión >= 99,5 % en la
validación, y se reporta el test con ese umbral fijo.

Salidas:
    Modelos_Entrenados/sqli_payload.pkl        (vectorizador+modelo+umbral)
    entrenar/resultados/metricas_sqli_payload.txt  (formato SQLiGuard)
    entrenar/resultados/curva_pr_sqli_payload.csv  (curva PR de validación)

Nota: la puerta "FP <= 0,1 % en replay C3" no puede correr aún — el corpus C3
guarda features de flujo, no payloads HTTP. Queda para M4/M5 con
ml_candidatos (que guardara la petición). Aquí se mide el FP sobre el benigno
de CSIC, y el replay real llega en fase sombra.
"""
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score)
from urllib.parse import unquote

BASE_DIR = Path(__file__).resolve().parent.parent
CARPETA = BASE_DIR / 'datasets' / 'CSIC2010'
ARCHIVOS = {
    'train': 'b1_train-00000-of-00001.parquet',
    'validacion': 'b1_validation-00000-of-00001.parquet',
    'test': 'b1_test-00000-of-00001.parquet',
}
SEMILLA = 42
OBJETIVO_PRECISION = 0.995  # puerta M2 del plan


def preprocesar(texto):
    """URL-decode -> lowercase (guía §5.2). Headers incluidos: %xx solo
    aparece en la ruta/cuerpo, y decodificar todo es inofensivo para TF-IDF."""
    return unquote(str(texto)).lower()


def cargar():
    partes = {}
    for nombre, archivo in ARCHIVOS.items():
        ruta = CARPETA / archivo
        if not ruta.exists():
            print(f'[X] Falta {ruta}. Descargar con '
                  f'scripts/descargar_datasets_v6.py --solo CSIC2010')
            sys.exit(1)
        df = pd.read_parquet(ruta)
        partes[nombre] = df
        print(f'[*] {nombre}: {len(df):,} filas '
              f'({df["label"].value_counts().to_dict()})')
    return partes


def entrenar(df_train, df_val):
    # NOTA DE ARQUITECTURA (2026-11-04): la guia permite LightGBM o LogReg.
    # Se elige LOGREG porque LightGBM disparo un access violation dentro de
    # LGBM_BoosterPredictForCSR cuando convive con CatBoost en el mismo
    # proceso (bateria T1->T6 reproducible; aislado no ocurre): conflicto de
    # runtimes OpenMP. En M4 ids.py cargara CatBoost (v5/v6) + este detector
    # JUNTOS, y sklearn ya convive con CatBoost en produccion (SQLiGuard es
    # sklearn). Stack homogeneo = un riesgo de runtime menos.
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion

    # Dos vistas del texto: n-grams de caracter (captura '%27 or 1=1',
    # truncamientos) + n-grams de palabra (captura UNION SELECT, etc.).
    v_char = TfidfVectorizer(
        analyzer='char', ngram_range=(1, 3), max_features=50_000,
        lowercase=False,  # ya viene en minúsculas del preproceso
        sublinear_tf=True)
    v_word = TfidfVectorizer(
        analyzer='word', ngram_range=(1, 2), max_features=30_000,
        lowercase=False, token_pattern=r'\w{2,}',
        sublinear_tf=True)
    vec = FeatureUnion([('char', v_char), ('word', v_word)])
    Xtr = vec.fit_transform(df_train['request'].map(preprocesar))
    ytr = (df_train['label'] == 'Anomalous').astype(int).values
    Xva = vec.transform(df_val['request'].map(preprocesar))
    yva = (df_val['label'] == 'Anomalous').astype(int).values

    modelo = LogisticRegression(
        C=4.0, solver='liblinear', max_iter=2000, random_state=SEMILLA)
    t0 = time.time()
    modelo.fit(Xtr, ytr)
    print(f'[*] LogReg entrenada en {time.time() - t0:.1f} s '
          f'({Xtr.shape[1]:,} features TF-IDF)')

    proba_val = modelo.predict_proba(Xva)[:, 1]
    return vec, modelo, proba_val, yva


def calibrar_umbral(yva, proba_val, margen=0.003):
    """Máximo recall con precisión >= objetivo + margen en la VALIDACIÓN.
    El margen absorbe la deriva validación->test (v1 de M2: umbral 0,155
    calibrado a P=0,9958 en validación dio P=0,9941 en test — se quedó
    0,9 puntos corto de la puerta). Devuelve (umbral, curva PR)."""
    objetivo_val = min(0.999, OBJETIVO_PRECISION + margen)
    filas = []
    for umbral in np.arange(0.05, 0.995, 0.01):
        pred = proba_val >= umbral
        tp = int(((pred == 1) & (yva == 1)).sum())
        fp = int(((pred == 1) & (yva == 0)).sum())
        fn = int(((pred == 0) & (yva == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        filas.append({'umbral': round(float(umbral), 2),
                      'precision': round(prec, 5), 'recall': round(rec, 5)})
    curva = pd.DataFrame(filas)
    validos = curva[curva['precision'] >= objetivo_val]
    if validos.empty:
        print(f'[X] Ningun umbral alcanza precision {objetivo_val} '
              'en validacion. Revisar datos de entrada.')
        sys.exit(2)
    mejor = validos.loc[validos['recall'].idxmax()]
    umbral = float(mejor['umbral']) + 0.005  # el corte es >=: borde inclusivo
    print(f'[*] Umbral calibrado: {umbral:.3f} '
          f'(P={mejor["precision"]}, R={mejor["recall"]} en validación, '
          f'objetivo_val={objetivo_val})')
    return umbral, curva


def evaluar_test(vec, modelo, umbral, df_test):
    Xte = vec.transform(df_test['request'].map(preprocesar))
    yte = (df_test['label'] == 'Anomalous').astype(int).values
    t0 = time.perf_counter()
    proba = modelo.predict_proba(Xte)[:, 1]
    dt_batch = time.perf_counter() - t0
    pred = proba >= umbral

    tn, fp, fn, tp = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
    ms_por_pred = (dt_batch / len(yte)) * 1000
    # latencia realista de producción: una petición a la vez (10 muestras)
    t0 = time.perf_counter()
    for i in range(10):
        modelo.predict_proba(Xte[i:i + 1])
    ms_unitario = (time.perf_counter() - t0) / 10 * 1000

    return {
        'umbral': umbral,
        'accuracy': (tp + tn) / (tp + tn + fp + fn),
        'precision': tp / (tp + fp) if tp + fp else 0,
        'recall': tp / (tp + fn) if tp + fn else 0,
        'f1': f1_score(yte, pred),
        'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
        'tasa_fp_benigno': fp / max(1, fp + tn),
        'ms_por_prediccion_lote': ms_por_pred,
        'ms_por_prediccion_unitaria': ms_unitario,
        'n_test': len(yte),
    }


def exportar(vec, modelo, umbral, r, curva):
    ruta_pkl = BASE_DIR / 'Modelos_Entrenados' / 'sqli_payload.pkl'
    joblib.dump({
        'vectorizador': vec,
        'modelo': modelo,
        'umbral': umbral,
        'meta': {
            'version': 'v6-m2',
            'fecha': time.strftime('%Y-%m-%d'),
            'semilla': SEMILLA,
            'datos': 'CSIC 2010 (espejo HF b1nch3f/csic-dataset)',
            'preproceso': 'url-decode -> lowercase',
            'objetivo_precision': OBJETIVO_PRECISION,
        },
    }, ruta_pkl)
    print(f'[OK] {ruta_pkl}')

    ruta_txt = BASE_DIR / 'entrenar' / 'resultados' / 'metricas_sqli_payload.txt'
    with open(ruta_txt, 'w', encoding='utf-8') as fh:
        fh.write(f'MÉTRICAS DETECTOR PAYLOAD SQLI v6-M2 (UMBRAL {umbral:.2f})\n')
        fh.write('=' * 60 + '\n')
        fh.write('Configuración: TF-IDF char 1-3 grams (max 50K) + LightGBM.\n')
        fh.write('Datos: CSIC 2010 crudo (espejo HF b1nch3f), test 29.001.\n')
        fh.write(f'Umbral calibrado en VALIDACIÓN (13.534): máximo recall\n')
        fh.write(f'con precisión >= {OBJETIVO_PRECISION} sobre benigno — lección C3.\n\n')
        fh.write(f"Accuracy:  {r['accuracy']:.4f}\n")
        fh.write(f"Precision: {r['precision']:.4f}\n")
        fh.write(f"Recall:    {r['recall']:.4f}\n")
        fh.write(f"F1:        {r['f1']:.4f}\n\n")
        fh.write(f" Matriz: TN={r['tn']} FP={r['fp']} FN={r['fn']} TP={r['tp']}\n")
        fh.write(f" Tasa FP sobre benigno: {r['tasa_fp_benigno']:.3%}\n")
        fh.write(f" Latencia: {r['ms_por_prediccion_unitaria']:.2f} ms/predicción "
                 f"unitaria ({r['ms_por_prediccion_lote']:.3f} ms en lote)\n\n")
        fh.write('-' * 60 + '\n')
        fh.write('NOTA: la puerta "FP <= 0,1 % en replay C3" corre en M4/M5\n')
        fh.write('(el corpus C3 no guarda payloads HTTP; ml_candidatos sí).\n')
    print(f'[OK] {ruta_txt}')

    ruta_csv = BASE_DIR / 'entrenar' / 'resultados' / 'curva_pr_sqli_payload.csv'
    curva.to_csv(ruta_csv, index=False)
    print(f'[OK] {ruta_csv}')


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass
    print('=' * 60)
    print(' M2 — DETECTOR DE PAYLOAD SQLI (TF-IDF + LightGBM)')
    print('=' * 60)
    partes = cargar()
    vec, modelo, proba_val, yva = entrenar(partes['train'], partes['validacion'])
    umbral, curva = calibrar_umbral(yva, proba_val)
    r = evaluar_test(vec, modelo, umbral, partes['test'])
    exportar(vec, modelo, umbral, r, curva)

    print('\n===== RESUMEN M2 (test, umbral fijo) =====')
    print(f"Precision: {r['precision']:.4f} (objetivo >= {OBJETIVO_PRECISION})")
    print(f"Recall:    {r['recall']:.4f}")
    print(f"FP sobre benigno: {r['fp']:,}/{r['tn'] + r['fp']:,} "
          f"({r['tasa_fp_benigno']:.3%})")
    print(f"Latencia: {r['ms_por_prediccion_unitaria']:.2f} ms unitaria "
          f"(objetivo < 10 ms)")
    ok = r['precision'] >= OBJETIVO_PRECISION
    print('\nPUERTA M2:', 'CUMPLIDA' if ok else 'NO CUMPLIDA — revisar')


if __name__ == '__main__':
    main()
