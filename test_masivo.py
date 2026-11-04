# -*- coding: utf-8 -*-
"""
test_masivo.py — Bateria de tests masivos del subsistema ML IDS/IPS (UNIPAZ)
=============================================================================
Verifica el funcionamiento END-TO-END usando datos REALES y las MISMAS rutas
de codigo de produccion (ids.py, flujos_red.py, entrenar_sqli_guard.py y el
exportador de logs).

Secuencia:
  T1. Modelo v5 (multiclase) sobre una muestra grande del dataset v5.
  T2. SQLiGuard (produccion, via `_features_sqli_guard`) sobre los 57 K flujos
      de D2 (Zenodo): precision/recall/F1 y tasa de falsos positivos.
  T3. Cadena completa `on_flow_ready` (v5 + SQLiGuard + umbrales unificados +
      trazabilidad) sobre un lote amplio, usando una BD TEMPORAL (no toca la
      BD de produccion) y desactivando alertas/Telegram.
  T4. Exportador de logs (`log_exporter`): comprobacion de escritura .log.
  T6. Detector de payload SQLI v6-M2 (sqli_payload.pkl): precision/recall
      sobre el test de CSIC 2010 con el umbral calibrado en validacion.
"""

import os
import sys
import time
import json
import tempfile
import sqlite3

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# P1: aislar los logs de PRODUCCIÓN. log_exporter respeta la variable de
# entorno LOG_FOLDER; el test escribe en una carpeta temporal y no ensucia
# logs_ciberseguridad/. Debe definirse ANTES de importar ids (importa
# log_exporter en su cabecera).
os.environ['LOG_FOLDER'] = tempfile.mkdtemp(prefix='ids_logs_test_')

# P1: la batería carga CatBoost v5 (T1) y LightGBM (T6) en el MISMO proceso;
# con n_jobs=-1 LightGBM llegó a disparar un access violation dentro de
# LGBM_BoosterPredictForCSR al correr la batería completa (solo no ocurre
# aislado). Capar hilos OMP antes de que cargue la librería lo elimina.
os.environ.setdefault('OMP_NUM_THREADS', '4')

print("=" * 70)
print(" TEST MASIVO — SUBSISTEMA ML IDS/IPS (UNIPAZ)")
print("=" * 70)

RESULTADOS = {}

# ---------------------------------------------------------------------------
# Utils: convertir una fila NetFlow (Zenodo D2) en dict CIC que consume la
# cadena de produccion. Ejercita exactamente el codigo real.
# ---------------------------------------------------------------------------
def netflow_a_cic_fecha(row):
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
        'Flow Duration': dur_ms * 1000.0,          # us (como CIC)
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

# ---------------------------------------------------------------------------
# T1. Modelo v5 sobre muestra grande del dataset global
# ---------------------------------------------------------------------------
print("\n[T1] Modelo v5 (multiclase) sobre muestra grande del dataset global...")
import ids
try:
    # Laboratorio ml-v6: solo existe el dataset v6 (33 features, las 23 del
    # modelo v5 incluidas con los mismos nombres). El v5 sigue en produccion.
    ruta_v5_csv = os.path.join(BASE_DIR, "Dataset_Limpio", "dataset_global_unipaz_v5.csv")
    ruta_v6_csv = os.path.join(BASE_DIR, "Dataset_Limpio", "dataset_global_unipaz_v6.csv")
    ruta_datos_t1 = ruta_v5_csv if os.path.exists(ruta_v5_csv) else ruta_v6_csv
    dfv5 = pd.read_csv(ruta_datos_t1, nrows=150000)
    X = dfv5[ids.features_seleccionadas].fillna(0)
    y_true = ids.tipo_ataque_encoder.transform(dfv5['Label_UNIPAZ'])
    t0 = time.time()
    y_pred = ids.modelo_ml.predict(X)
    probs = ids.modelo_ml.predict_proba(X)
    t_pred = time.time() - t0
    from sklearn.metrics import (accuracy_score, classification_report,
                                 f1_score, confusion_matrix)
    acc = accuracy_score(y_true, y_pred)
    f1m = f1_score(y_true, y_pred, average='macro')
    reporte = classification_report(y_true, y_pred, target_names=ids.tipo_ataque_encoder.classes_,
                                    zero_division=0, output_dict=True)
    cm = confusion_matrix(y_true, y_pred)
    n_clases = len(ids.tipo_ataque_encoder.classes_)

    # Métricas por clase individual (precision, recall, F1, FP, FN, TN, tasa_FP)
    clases_detalle = {}
    for i in range(n_clases):
        tp = cm[i, i]
        fp = cm[:, i].sum() - tp
        fn = cm[i, :].sum() - tp
        tn = cm.sum() - tp - fp - fn
        precision = cm[i, i] / (cm[i, i] + fp) if (cm[i, i] + fp) > 0 else 0.0
        recall = cm[i, i] / (cm[i, i] + fn) if (cm[i, i] + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        tasa_fp = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        clase_nombre = ids.tipo_ataque_encoder.classes_[i]
        clases_detalle[clase_nombre] = {
            'precision': round(float(precision), 4),
            'recall': round(float(recall), 4),
            'f1': round(float(f1), 4),
            'tp': int(tp),
            'fp': int(fp),
            'fn': int(fn),
            'tn': int(tn),
            'tasa_falsos_positivos': round(float(tasa_fp), 5),
        }

    RESULTADOS['T1'] = {
        'total_flujos': len(X),
        'accuracy': round(acc, 4),
        'f1_macro': round(f1m, 4),
        'tiempo_pred_s': round(t_pred, 2),
        'clases': n_clases,
        'clases_detalle': clases_detalle,
        'matriz_confusion': cm.tolist(),
        'reporte_clases': reporte,
    }
    # Precisión/recall de Inyeccion_SQL según el modelo v5 (referencia)
    idx_sql = int(ids.tipo_ataque_encoder.transform(['Inyeccion_SQL'])[0])
    neg_classes = [i for i in range(n_clases) if i != idx_sql]
    tp_sql = cm[idx_sql, idx_sql]
    fp_sql = sum(cm[i, idx_sql] for i in neg_classes)
    fn_sql = sum(cm[idx_sql, j] for j in neg_classes)
    prec_sql5 = tp_sql / (tp_sql + fp_sql) if (tp_sql + fp_sql) > 0 else 0
    rec_sql5 = tp_sql / (tp_sql + fn_sql) if (tp_sql + fn_sql) > 0 else 0
    RESULTADOS['T1']['sql_prec_v5'] = round(prec_sql5, 4)
    RESULTADOS['T1']['sql_rec_v5'] = round(rec_sql5, 4)
    print(f"      flujos={len(X)}  acc={acc:.4f}  f1_macro={f1m:.4f}  "
          f"pred={t_pred:.2f}s")
    print(f"      v5 SQLi -> precision={prec_sql5:.4f} recall={rec_sql5:.4f}")
    print(f"      Métricas por clase guardadas en clases_detalle")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T1'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T2. SQLiGuard de produccion sobre todos los flujos de D2 (57 K)
# ---------------------------------------------------------------------------
print("\n[T2] SQLiGuard (ruta de produccion) sobre D2 (57 K flujos reales)...")
try:
    d2 = pd.read_csv(os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo", "D2_test.csv"))
    feats = ids.SQLI_GUARD_FEATURES
    guard_rows = []
    y_guard = []
    for _, r in d2.iterrows():
        cic = netflow_a_cic_fecha(r)
        guard_rows.append([ids._features_sqli_guard(cic)[k] for k in feats])
        y_guard.append(cic['_y'])
    G = pd.DataFrame(guard_rows, columns=feats)
    t0 = time.time()
    prob_guard = ids.sqli_guard.predict_proba(G)[:, 1]
    t_guard = time.time() - t0
    pred_guard = (prob_guard >= ids.UMBRAL_SQLI_GUARD).astype(int)
    y_guard = np.array(y_guard)
    tn = int(((pred_guard == 0) & (y_guard == 0)).sum())
    fp = int(((pred_guard == 1) & (y_guard == 0)).sum())
    fn = int(((pred_guard == 0) & (y_guard == 1)).sum())
    tp = int(((pred_guard == 1) & (y_guard == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    RESULTADOS['T2'] = {
        'total_flujos': len(G),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp,
        'tasa_fp_benigno': round(fp / (fp + tn), 5) if (fp + tn) else 0,
        'tiempo_pred_s': round(t_guard, 2),
        'umbral': ids.UMBRAL_SQLI_GUARD,
    }
    print(f"      flujos={len(G)}  precision={prec:.4f}  recall={rec:.4f}  f1={f1:.4f}")
    print(f"      TN={tn} FP={fp} FN={fn} TP={tp} | FP sobre benigno={fp/(fp+tn):.3%}")
    print(f"      prediccion ({len(G)} flujos): {t_guard:.2f}s")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T2'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T3. Cadena completa on_flow_ready con BD temporal (no toca produccion)
# ---------------------------------------------------------------------------
print("\n[T3] Cadena completa on_flow_ready (lote amplio, BD TEMPORAL)...")
try:
    # --- Redirigir a BD temporal y silenciar alertas/Telegram ---
    ids.conn.close()
    tmp_db = tempfile.mktemp(suffix='.db')
    ids.ruta_bd = tmp_db
    ids.conn = sqlite3.connect(tmp_db, check_same_thread=False)
    ids.cursor = ids.conn.cursor()
    ids.crear_tabla_ataques(ids.conn)   # esquema ÚNICO compartido con producción
    ids._enviar_alerta_async = lambda msg: None   # no spamear Telegram
    ids.ips_activo = False
    # T3 mide la cadena ML completa (v5 + SQLiGuard): se activa la via de
    # alerta SOLO dentro de este experimento offline. En produccion el defecto
    # es IDS_ML_ALERTAS=0 (docs/INFORME_C3_DATOS.md).
    ids.ML_ALERTAS = True

    # Muestra balanceada de D2: 3000 benignos + 3000 SQLi
    d2 = pd.read_csv(os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo", "D2_test.csv"))
    mue = d2[d2['Label'] == 0].sample(3000, random_state=1)
    mua = d2[d2['Label'] == 1].sample(3000, random_state=1)
    lote = pd.concat([mue, mua]).sample(frac=1, random_state=1).reset_index(drop=True)

    n_guard_conf = 0
    n_sqli_persistidos = 0
    t0 = time.time()
    for i, (_, r) in enumerate(lote.iterrows()):
        cic = netflow_a_cic_fecha(r)
        ip = f"TEST.IP.{i}.{r['Label']}"
        ids.on_flow_ready(ip, "10.0.0.5", cic)
        n_guard_conf += int((ids._features_sqli_guard(cic) is not None))
    t_cadena = time.time() - t0

    rows = ids.cursor.execute(
        "SELECT tipo_ataque, ip_src, confianza_ml, features_json FROM ataques").fetchall()
    n_sqli_persistidos = sum(1 for x in rows if 'Inyeccion_SQL' in x[0])
    con_trazabilidad = sum(1 for x in rows if x[3])
    # Recomputo exacto: precision/recall de la cadena (el ip guarda el label)
    import collections
    marcados = collections.defaultdict(int)
    for t, ip, conf, _ in rows:
        marcados[ip] = 1 if 'Inyeccion_SQL' in t else 0
    RESULTADOS['T3'] = {
        'flujos_procesados': len(lote),
        'sql_persistidos': n_sqli_persistidos,
        'con_trazabilidad_features_json': con_trazabilidad,
        'sql_guard_confirmados': n_guard_conf,
        'tiempo_cadena_s': round(t_cadena, 2),
        'filas_en_bd_tmp': len(rows),
    }
    tp3 = sum(1 for ip, m in marcados.items() if m == 1 and ip.endswith('.1'))
    fp3 = sum(1 for ip, m in marcados.items() if m == 1 and ip.endswith('.0'))
    fn3 = 3000 - tp3
    prec3 = tp3 / (tp3 + fp3) if (tp3 + fp3) else 0
    rec3 = tp3 / (tp3 + fn3) if (tp3 + fn3) else 0
    RESULTADOS['T3'].update({'precision_cadena': round(prec3, 4),
                             'recall_cadena': round(rec3, 4),
                             'tp': tp3, 'fp': fp3, 'fn': fn3})
    print(f"      flujos={len(lote)}  SQLi persistidos={n_sqli_persistidos} / 3000")
    print(f"      precision_cadena={prec3:.4f} recall_cadena={rec3:.4f} (tp={tp3} fp={fp3} fn={fn3})")
    print(f"      con trazabilidad features_json={con_trazabilidad}")
    print(f"      tiempo cadena ({len(lote)} flujos): {t_cadena:.2f}s")
    ids.conn.close()
    os.remove(tmp_db)
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T3'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T4. Exportador de logs
# ---------------------------------------------------------------------------
print("\n[T4] Exportador de logs (log_exporter)...")
try:
    from log_exporter import registrar_bloqueo_log, obtener_carpeta_logs
    ip_prueba = "203.0.113.199"
    registrar_bloqueo_log(ip_prueba, "BLOQUEO_TEST_MASIVO", 24)
    # Verificar que existe un log .log reciente con la linea
    # registrar_bloqueo_log escribe en la carpeta activa (LOG_FOLDER), que en
    # este test es una carpeta TEMPORAL para no contaminar producción.
    logs_dir = obtener_carpeta_logs()
    ruta_bloqueos = os.path.join(logs_dir, "logs_bloqueos.log")
    encontrado = False
    if os.path.exists(ruta_bloqueos):
        contenido = open(ruta_bloqueos, encoding='utf-8', errors='ignore').read()
        encontrado = ip_prueba in contenido and 'TEST_MASIVO' in contenido
    archivos = [f for f in os.listdir(logs_dir) if f.endswith('.log')]
    RESULTADOS['T4'] = {
        'archivos_log': archivos,
        'linea_bloqueo_escrita': encontrado,
        'ruta_bloqueos': ruta_bloqueos,
        'carpeta_logs_temp': logs_dir,
    }
    print(f"      archivos .log: {len(archivos)} | linea test en logs_bloqueos.log: {encontrado}")
    print(f"      carpeta logs (temporal): {logs_dir}")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T4'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T6. Detector de payload SQLI v6-M2 (TF-IDF + LightGBM) sobre CSIC test
# ---------------------------------------------------------------------------
print("\n[T6] Detector de payload SQLI (sqli_payload.pkl) sobre CSIC test...")
try:
    import joblib
    from urllib.parse import unquote as _unquote
    ruta_pkl = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sqli_payload.pkl')
    ruta_test = os.path.join(BASE_DIR, 'datasets', 'CSIC2010',
                             'b1_test-00000-of-00001.parquet')
    if not os.path.exists(ruta_pkl) or not os.path.exists(ruta_test):
        raise FileNotFoundError(
            f'faltan {ruta_pkl} o {ruta_test} (entrenar/train_sqli_payload.py)')

    bundle = joblib.load(ruta_pkl)
    vec, modelo_p, umbral_p = bundle['vectorizador'], bundle['modelo'], bundle['umbral']
    df_t6 = pd.read_parquet(ruta_test)
    X = vec.transform(df_t6['request'].map(lambda t: _unquote(str(t)).lower()))
    y = (df_t6['label'] == 'Anomalous').astype(int).values

    t0 = time.perf_counter()
    # Predicción por chunks (patrón de producción M4: el motor evalúa
    # peticiones sueltas o lotes pequeños; y así la batería no depende de
    # la RAM libre tras cargar el CatBoost v5 en T1).
    probs_chunks = []
    for i in range(0, X.shape[0], 5000):
        probs_chunks.append(modelo_p.predict_proba(X[i:i + 5000])[:, 1])
    proba = np.concatenate(probs_chunks)
    dt = time.perf_counter() - t0
    pred = proba >= umbral_p

    from sklearn.metrics import confusion_matrix as _cm, f1_score as _f1
    tn6, fp6, fn6, tp6 = _cm(y, pred, labels=[0, 1]).ravel()
    RESULTADOS['T6'] = {
        'umbral': umbral_p,
        'precision': round(tp6 / max(1, tp6 + fp6), 4),
        'recall': round(tp6 / max(1, tp6 + fn6), 4),
        'f1': round(float(_f1(y, pred)), 4),
        'fp': int(fp6), 'tn': int(tn6), 'tp': int(tp6), 'fn': int(fn6),
        'tasa_fp_benigno': round(fp6 / max(1, fp6 + tn6), 5),
        'ms_por_prediccion': round(dt / len(y) * 1000, 3),
    }
    print(f"      umbral={umbral_p:.2f} (calibrado en validacion, leccion C3)")
    print(f"      precision={RESULTADOS['T6']['precision']} "
          f"recall={RESULTADOS['T6']['recall']} f1={RESULTADOS['T6']['f1']}")
    print(f"      FP benigno: {fp6}/{fp6+tn6} "
          f"({RESULTADOS['T6']['tasa_fp_benigno']:.3%})")
    print(f"      latencia: {RESULTADOS['T6']['ms_por_prediccion']} ms/prediccion")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T6'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print(" RESUMEN RESULTADOS")
print("=" * 70)
for k, v in RESULTADOS.items():
    print(f"\n  {k}:")
    for kk, vv in v.items():
        print(f"      {kk}: {vv}")

# Guardar informe para referencia
out = os.path.join(BASE_DIR, "informe_test_masivo.json")
with open(out, 'w', encoding='utf-8') as f:
    json.dump(RESULTADOS, f, ensure_ascii=False, indent=2)
print(f"\n  Informe guardado: {out}")

# ---------------------------------------------------------------------------
# Gates de aprobación P1: PASS/FAIL por prueba + exit code (validación CI)
# ---------------------------------------------------------------------------
def _gate(nombre, ok, detalle):
    RESULTADOS.setdefault('gates', {})[nombre] = {'pass': bool(ok), 'detalle': detalle}
    return bool(ok)

def _t1_ok():
    d = RESULTADOS.get('T1', {})
    if 'error' in d:
        return False
    return d.get('accuracy', 0) >= 0.80 and d.get('f1_macro', 0) >= 0.70

def _t2_ok():
    d = RESULTADOS.get('T2', {})
    if 'error' in d:
        return False
    fp_rate = d.get('tasa_fp_benigno', 1.0)
    return d.get('precision', 0) >= 0.99 and fp_rate <= 0.0020

def _t3_ok():
    d = RESULTADOS.get('T3', {})
    if 'error' in d:
        return False
    return d.get('sql_persistidos', 0) >= 1500 and d.get('precision_cadena', 0) >= 0.95

def _t4_ok():
    d = RESULTADOS.get('T4', {})
    return bool(d.get('linea_bloqueo_escrita', False))

def _t6_ok():
    d = RESULTADOS.get('T6', {})
    if 'error' in d:
        return False
    # Puerta M2: precisión >= 99,5 % en holdout benigno + latencia < 10 ms
    return (d.get('precision', 0) >= 0.995
            and d.get('ms_por_prediccion', 1e9) < 10)

resultados_gates = [
    ('T1', _t1_ok(), f"acc>={RESULTADOS.get('T1', {}).get('accuracy', 0):.4f} "
                     f"f1_macro>={RESULTADOS.get('T1', {}).get('f1_macro', 0):.4f}"),
    ('T2', _t2_ok(), f"prec>={RESULTADOS.get('T2', {}).get('precision', 0):.4f} "
                     f"fp_rate>={RESULTADOS.get('T2', {}).get('tasa_fp_benigno', 1):.4%}"),
    ('T3', _t3_ok(), f"sql_persistidos>={RESULTADOS.get('T3', {}).get('sql_persistidos', 0)} "
                     f"prec_cadena>={RESULTADOS.get('T3', {}).get('precision_cadena', 0):.4f}"),
    ('T4', _t4_ok(), f"linea_bloqueo_escrita={RESULTADOS.get('T4', {}).get('linea_bloqueo_escrita', False)}"),
    ('T6', _t6_ok(), f"prec={RESULTADOS.get('T6', {}).get('precision', 0):.4f} "
                     f"lat={RESULTADOS.get('T6', {}).get('ms_por_prediccion', 999)}ms "
                     "(objetivo P>=0.995, <10ms)"),
]

print("\n" + "=" * 70)
print(" GATES DE APROBACIÓN (P1)")
print("=" * 70)
algun_fallo = False
for nombre, ok, detalle in resultados_gates:
    ok = _gate(nombre, ok, detalle)
    algun_fallo = algun_fallo or not ok
    print(f"  {nombre}: {'PASS' if ok else 'FAIL'}  ({detalle})")
if algun_fallo:
    print(f"\n[FAIL] Al menos un gate falló. Código de salida: 1")
    sys.exit(1)
print("\n[PASS] Todos los gates de aprobación superados.")
print("\n[FIN] Tests masivos ejecutados.")