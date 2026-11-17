# -*- coding: utf-8 -*-
"""
test_masivo_v6.py — Batería T*v6 (preserva las corridas históricas v5).
=====================================================================

Este archivo es NUEVO y NO sustituye a `test_masivo.py`. La batería histórica
sigue en `informe_test_masivo.json`; aquí se generan las evidencias v6 en
`informe_test_masivo_v6.json`.

Secuencia:
  T1v6. CatBoost v6 (33 features + umbrales por clase) sobre dataset v6.
  T2v6. Detector de payload v6 (M2) sobre CSIC 2010 — equivalente a T6.
  T3v6. Cadena v6 real: on_flow_ready con ML_ALERTAS=0,ML_V6=1,SOMBRA=0 y
        BD temporal; mide candidatos, alertas, precisión y trazabilidad.
  T4v6. Exportador de logs (independiente de la versión del modelo).
  T5v6. NO se ejecuta aquí: requiere las 3 CHR. Script preparado en
        docs/lab/t5_routeros_v6.py.

El dataset v6 NO se restaura ni se regenera: debe existir ya en
Dataset_Limpio/dataset_global_unipaz_v6.csv cuando se ejecute la batería.
"""

import os
import sys
import time
import json
import hashlib
import tempfile
import sqlite3

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

RUTA_DATASET_V6 = os.path.join(BASE_DIR, 'Dataset_Limpio',
                               'dataset_global_unipaz_v6.csv')
RUTA_CSIC = os.path.join(BASE_DIR, 'datasets', 'CSIC2010',
                         'b1_test-00000-of-00001.parquet')
RUTA_PAYLOAD = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sqli_payload.pkl')

# --- Aislamiento ANTES de importar ids (ids.py importa log_exporter) ----------
os.environ['LOG_FOLDER'] = tempfile.mkdtemp(prefix='ids_logs_test_v6_')
os.environ.setdefault('OMP_NUM_THREADS', '4')
os.environ['IDS_ML_V6'] = '1'
os.environ['IDS_ML_SOMBRA'] = '0'
os.environ['IDS_ML_ALERTAS'] = '0'
os.environ['IDS_IPS_AUTONOMO'] = '0'
os.environ['IDS_MODO_OBSERVACION'] = '0'
os.environ.setdefault('IDS_RUN_ID', 'test-v6')
os.environ.pop('IDS_POLITICA', None)

print("=" * 72)
print(" TEST MASIVO v6 — modelo v6 real, evidencias separadas")
print("=" * 72)

RESULTADOS = {
    'entorno': {
        'run_id': os.environ['IDS_RUN_ID'],
        'python': sys.version.split()[0],
        'ids_ml_v6': os.environ['IDS_ML_V6'],
        'ids_ml_sombra': os.environ['IDS_ML_SOMBRA'],
        'ids_ml_alertas': os.environ['IDS_ML_ALERTAS'],
        'ids_ips_autonomo': os.environ['IDS_IPS_AUTONOMO'],
        'dataset': 'Dataset_Limpio/dataset_global_unipaz_v6.csv',
    },
}
_SHA_CACHE = {}


def sha256_archivo(ruta):
    if ruta in _SHA_CACHE:
        return _SHA_CACHE[ruta]
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b''):
            h.update(bloque)
    _SHA_CACHE[ruta] = h.hexdigest()
    return _SHA_CACHE[ruta]


def preflight():
    faltan = []
    for ruta, nombre in [
        (RUTA_DATASET_V6, 'dataset_global_unipaz_v6.csv'),
        (RUTA_CSIC, 'CSIC2010/b1_test-00000-of-00001.parquet'),
        (RUTA_PAYLOAD, 'sqli_payload.pkl'),
    ]:
        if not os.path.isfile(ruta):
            faltan.append(nombre)
    if faltan:
        raise FileNotFoundError(
            "Faltan artefactos requeridos: " + ", ".join(faltan)
            + ". El dataset v6 NO se regenera; coloque el CSV ya generado.")


def _gate(nombre, ok, detalle):
    RESULTADOS.setdefault('gates', {})[nombre] = {
        'pass': bool(ok), 'detalle': detalle}
    print(f"  {nombre}: {'PASS' if ok else 'FAIL'}  ({detalle})")
    return bool(ok)


# ---------------------------------------------------------------------------
# Preflight: si falla, se escribe igualmente el informe para dejar rastro.
# ---------------------------------------------------------------------------
try:
    preflight()
    RESULTADOS['entorno']['dataset_sha256'] = sha256_archivo(RUTA_DATASET_V6)
    print("[OK] Preflight: dataset v6, CSIC y payload presentes.")
    _PREFLIGHT_OK = True
except Exception as e:
    _PREFLIGHT_OK = False
    RESULTADOS['PREFLIGHT'] = {'error': str(e)}
    print(f"[X] Preflight: {e}")

if _PREFLIGHT_OK:
    import ids

    if not (ids.ML_V6 and ids.modelo_v6 is not None and ids.features_v6):
        RESULTADOS['PREFLIGHT'] = {
            'error': 'ids.py no cargó los modelos v6 (IDS_ML_V6=1).'}
        print("[X] " + RESULTADOS['PREFLIGHT']['error'])
        _PREFLIGHT_OK = False

# ---------------------------------------------------------------------------
# T1v6. CatBoost v6 sobre dataset v6 (argmax + umbrales por clase)
# ---------------------------------------------------------------------------
if _PREFLIGHT_OK:
    print("\n[T1v6] CatBoost v6 sobre dataset v6 (33 features)...")
    try:
        df1 = pd.read_csv(RUTA_DATASET_V6, nrows=150000)
        columnas = ['Label_UNIPAZ'] + list(ids.features_v6)
        faltan_cols = [c for c in columnas if c not in df1.columns]
        if faltan_cols:
            raise ValueError(f"El dataset v6 no tiene: {faltan_cols}")

        clases = [str(c) for c in ids.modelo_v6.classes_]
        clase_a_idx = {c: i for i, c in enumerate(clases)}
        y_series = df1['Label_UNIPAZ'].astype(str).map(clase_a_idx)
        validas = y_series.notna().to_numpy()
        X = df1.loc[validas, ids.features_v6].fillna(0)
        y_true = y_series[validas].astype(int).to_numpy()

        t0 = time.time()
        proba = np.asarray(ids.modelo_v6.predict_proba(X))
        pred = np.argmax(proba, axis=1)
        t_pred = time.time() - t0

        from sklearn.metrics import (accuracy_score, f1_score,
                                     confusion_matrix)
        acc = accuracy_score(y_true, pred)
        f1m = f1_score(y_true, pred, average='macro', zero_division=0)
        cm = confusion_matrix(y_true, pred,
                              labels=list(range(len(clases))))

        detalle = {}
        for i, clase in enumerate(clases):
            tp = int(cm[i, i])
            fp = int(cm[:, i].sum() - tp)
            fn = int(cm[i, :].sum() - tp)
            tn = int(cm.sum() - tp - fp - fn)
            umbral = float(ids.umbrales_v6.get(clase, 1.0))
            senal = proba[:, i] >= umbral
            tp_u = int((senal & (y_true == i)).sum())
            fp_u = int((senal & (y_true != i)).sum())
            fn_u = int((~senal & (y_true == i)).sum())
            tn_u = int((~senal & (y_true != i)).sum())
            detalle[clase] = {
                'precision': round(tp / max(1, tp + fp), 4),
                'recall': round(tp / max(1, tp + fn), 4),
                'f1': round(2 * tp / max(1, 2 * tp + fp + fn), 4),
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'umbral': round(umbral, 6),
                'umbral_precision': round(tp_u / max(1, tp_u + fp_u), 4),
                'umbral_recall': round(tp_u / max(1, tp_u + fn_u), 4),
                'umbral_tp': tp_u, 'umbral_fp': fp_u,
                'umbral_fn': fn_u, 'umbral_tn': tn_u,
            }

        RESULTADOS['T1v6'] = {
            'modelo': 'pipeline_catboost_v6.pkl',
            'dataset': 'dataset_global_unipaz_v6.csv',
            'dataset_sha256': RESULTADOS['entorno']['dataset_sha256'],
            'total_flujos': int(len(X)),
            'flujos_descartados_etiqueta': int((~validas).sum()),
            'accuracy': round(float(acc), 4),
            'f1_macro': round(float(f1m), 4),
            'tiempo_pred_s': round(t_pred, 2),
            'clases': len(clases),
            'clases_detalle': detalle,
            'matriz_confusion': cm.tolist(),
        }
        print(f"      flujos={len(X)}  acc={acc:.4f}  f1_macro={f1m:.4f}  "
              f"pred={t_pred:.2f}s")
        print("      métricas argmax + umbral por clase guardadas.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        RESULTADOS['T1v6'] = {'error': str(e)}

# ---------------------------------------------------------------------------
# T2v6. Detector de payload v6 (M2) sobre CSIC 2010 — equivalente a T6.
# ---------------------------------------------------------------------------
if _PREFLIGHT_OK:
    print("\n[T2v6] Payload v6 (sqli_payload.pkl) sobre CSIC 2010...")
    try:
        import joblib
        from urllib.parse import unquote as _unquote

        bundle = ids.payload_bundle or joblib.load(RUTA_PAYLOAD)
        vec = bundle['vectorizador']
        modelo_p = bundle['modelo']
        umbral_p = float(bundle['umbral'])

        df2 = pd.read_parquet(RUTA_CSIC)
        X2 = vec.transform(
            df2['request'].map(lambda t: _unquote(str(t)).lower()))
        y2 = (df2['label'] == 'Anomalous').astype(int).to_numpy()

        t0 = time.perf_counter()
        partes = []
        for i in range(0, X2.shape[0], 5000):
            partes.append(modelo_p.predict_proba(X2[i:i + 5000])[:, 1])
        proba2 = np.concatenate(partes)
        dt = time.perf_counter() - t0
        pred2 = proba2 >= umbral_p

        from sklearn.metrics import confusion_matrix as _cm, f1_score as _f1
        tn, fp, fn, tp = _cm(y2, pred2, labels=[0, 1]).ravel()
        res = {
            'equivalente': 'T6',
            'umbral': umbral_p,
            'total_peticiones': int(len(y2)),
            'precision': round(tp / max(1, tp + fp), 4),
            'recall': round(tp / max(1, tp + fn), 4),
            'f1': round(float(_f1(y2, pred2)), 4),
            'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'tn': int(tn),
            'tasa_fp_benigno': round(fp / max(1, fp + tn), 5),
            'ms_por_prediccion': round(dt / len(y2) * 1000, 3),
        }
        RESULTADOS['T2v6'] = res
        RESULTADOS['T6'] = dict(res, alias_de='T2v6')
        print(f"      precision={res['precision']} recall={res['recall']} "
              f"FP={fp}/{fp+tn} lat={res['ms_por_prediccion']}ms")
    except Exception as e:
        import traceback
        traceback.print_exc()
        RESULTADOS['T2v6'] = {'error': str(e)}

# ---------------------------------------------------------------------------
# T3v6. Cadena v6 real con BD temporal
# ---------------------------------------------------------------------------
if _PREFLIGHT_OK:
    print("\n[T3v6] Cadena v6 real (on_flow_ready, BD TEMPORAL)...")
    tmp_db = None
    try:
        def _muestra_sql_normal(cantidad=3000):
            sql, normal = [], []
            n_sql = n_normal = 0
            for chunk in pd.read_csv(RUTA_DATASET_V6, chunksize=100000):
                etiqueta = chunk['Label_UNIPAZ'].astype(str)
                s = chunk[etiqueta == 'Inyeccion_SQL'].head(cantidad - n_sql)
                nn = chunk[etiqueta == 'Normal'].head(cantidad - n_normal)
                if len(s):
                    sql.append(s)
                    n_sql += len(s)
                if len(nn):
                    normal.append(nn)
                    n_normal += len(nn)
                if n_sql >= cantidad and n_normal >= cantidad:
                    break
            if n_sql < cantidad or n_normal < cantidad:
                raise ValueError(
                    f"El dataset v6 no tiene suficientes filas "
                    f"Inyeccion_SQL/Normal ({n_sql}/{n_normal}).")
            return (pd.concat(sql + normal)
                    .sample(frac=1, random_state=1)
                    .reset_index(drop=True))

        muestra = _muestra_sql_normal(3000)

        ids.conn.close()
        tmp_db = tempfile.mktemp(suffix='_v6.db')
        ids.ruta_bd = tmp_db
        ids.conn = sqlite3.connect(tmp_db, check_same_thread=False)
        ids.cursor = ids.conn.cursor()
        ids.crear_tabla_ataques(ids.conn)
        ids._enviar_alerta_async = lambda msg: None
        ids.ips_activo = False
        ids.modo_ips_autonomo = False
        # Clave: T3 histórico ponía ML_ALERTAS=True y por eso NO corría v6.
        ids.ML_ALERTAS = False
        ids.ML_V6 = True
        ids.ML_SOMBRA = False

        t0 = time.time()
        for i, (_, r) in muestra.iterrows():
            es_sql = str(r['Label_UNIPAZ']) == 'Inyeccion_SQL'
            features = {f: r.get(f, 0) for f in ids.features_v6}
            ip = f"TESTV6.{i}.{1 if es_sql else 0}"
            ids.on_flow_ready(ip, "10.0.0.5", features)
        t_cadena = time.time() - t0

        filas = ids.cursor.execute(
            "SELECT tipo_ataque, ip_src, confianza_ml, features_json "
            "FROM ataques").fetchall()
        marcados = {}
        for tipo, ip, _conf, fj in filas:
            marcados[ip] = 1 if 'Inyeccion_SQL' in str(tipo) else 0
        con_trazabilidad = sum(1 for x in filas if x[3])
        n_sql_persistidos = sum(v for v in marcados.values())

        tp3 = sum(1 for ip, m in marcados.items()
                  if m == 1 and ip.endswith('.1'))
        fp3 = sum(1 for ip, m in marcados.items()
                  if m == 1 and ip.endswith('.0'))
        fn3 = 3000 - tp3
        prec3 = tp3 / max(1, tp3 + fp3)
        rec3 = tp3 / max(1, tp3 + fn3)

        try:
            cand = ids.cursor.execute(
                "SELECT clase_predicha, decision, COUNT(*) "
                "FROM ml_candidatos GROUP BY 1,2").fetchall()
            candidatos = sum(c[2] for c in cand)
            descartados = sum(c[2] for c in cand if c[1] == 'descartado')
            alertas_cand = sum(c[2] for c in cand if c[1] == 'alerta')
            por_clase = [{'clase': c[0], 'decision': c[1], 'n': c[2]}
                         for c in cand]
        except Exception:
            candidatos = descartados = alertas_cand = 0
            por_clase = []

        RESULTADOS['T3v6'] = {
            'flujos_procesados': int(len(muestra)),
            'sql_persistidos': n_sql_persistidos,
            'precision_cadena': round(prec3, 4),
            'recall_cadena': round(rec3, 4),
            'tp': int(tp3), 'fp': int(fp3), 'fn': int(fn3),
            'con_trazabilidad_features_json': con_trazabilidad,
            'candidatos_v6': int(candidatos),
            'descartados': int(descartados),
            'alertas_candidatos': int(alertas_cand),
            'por_clase_decision': por_clase,
            'tiempo_cadena_s': round(t_cadena, 2),
            'run_id': os.environ['IDS_RUN_ID'],
            'sombra': ids.ML_SOMBRA,
            'ml_alertas': ids.ML_ALERTAS,
        }
        print(f"      flujos={len(muestra)} candidatos={candidatos} "
              f"SQLi persistidos={n_sql_persistidos}/3000")
        print(f"      precision={prec3:.4f} recall={rec3:.4f} "
              f"(tp={tp3} fp={fp3} fn={fn3})")
    except Exception as e:
        import traceback
        traceback.print_exc()
        RESULTADOS['T3v6'] = {'error': str(e)}
    finally:
        try:
            ids.conn.close()
        except Exception:
            pass
        if tmp_db and os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except OSError:
                pass

# ---------------------------------------------------------------------------
# T4v6. Exportador de logs (idéntico al histórico, sin tocar producción)
# ---------------------------------------------------------------------------
if _PREFLIGHT_OK:
    print("\n[T4v6] Exportador de logs (log_exporter)...")
    try:
        from log_exporter import registrar_bloqueo_log, obtener_carpeta_logs
        ip_prueba = "203.0.113.199"
        registrar_bloqueo_log(ip_prueba, "BLOQUEO_TEST_MASIVO_V6", 24)
        logs_dir = obtener_carpeta_logs()
        ruta_bloqueos = os.path.join(logs_dir, "logs_bloqueos.log")
        contenido = ''
        if os.path.exists(ruta_bloqueos):
            with open(ruta_bloqueos, encoding='utf-8', errors='ignore') as f:
                contenido = f.read()
        encontrado = ip_prueba in contenido and 'TEST_MASIVO_V6' in contenido
        RESULTADOS['T4v6'] = {
            'archivos_log': [f for f in os.listdir(logs_dir)
                             if f.endswith('.log')],
            'linea_bloqueo_escrita': encontrado,
            'ruta_bloqueos': ruta_bloqueos,
            'carpeta_logs_temp': logs_dir,
        }
        print(f"      línea v6 en logs_bloqueos.log: {encontrado}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        RESULTADOS['T4v6'] = {'error': str(e)}

# T5v6 queda preparada pero no se ejecuta sin las CHR.
RESULTADOS['T5v6'] = {
    'estado': 'NO_EJECUTADA',
    'motivo': 'Las 3 CHR están apagadas/en otro dispositivo.',
    'script': 'docs/lab/t5_routeros_v6.py',
    'evidencia_destino': 'docs/lab/corridas/v6/',
}

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------
print("\n" + "=" * 72)
print(" GATES DE APROBACIÓN — batería v6")
print("=" * 72)

resultados_gates = []

def _evaluar():
    resultados_gates.append(_gate(
        'PREFLIGHT', _PREFLIGHT_OK,
        RESULTADOS.get('PREFLIGHT', {}).get('error', 'artefactos v6 presentes')))

    d = RESULTADOS.get('T1v6', {})
    resultados_gates.append(_gate(
        'T1v6',
        'error' not in d and d.get('accuracy', 0) >= 0.80
        and d.get('f1_macro', 0) >= 0.70,
        f"acc>={d.get('accuracy', 0)} f1_macro>={d.get('f1_macro', 0)}"))

    d = RESULTADOS.get('T2v6', {})
    resultados_gates.append(_gate(
        'T2v6',
        'error' not in d and d.get('precision', 0) >= 0.995
        and d.get('ms_por_prediccion', 1e9) < 10,
        f"P={d.get('precision', 0)} lat={d.get('ms_por_prediccion', 999)}ms"))

    d = RESULTADOS.get('T3v6', {})
    resultados_gates.append(_gate(
        'T3v6',
        'error' not in d and d.get('sql_persistidos', 0) >= 1500
        and d.get('precision_cadena', 0) >= 0.95,
        f"sql={d.get('sql_persistidos', 0)}/3000 "
        f"P={d.get('precision_cadena', 0)}"))

    d = RESULTADOS.get('T4v6', {})
    resultados_gates.append(_gate(
        'T4v6', bool(d.get('linea_bloqueo_escrita', False)),
        f"linea_v6={d.get('linea_bloqueo_escrita', False)}"))

_evaluar()
RESULTADOS['T5v6']['gate'] = 'PENDIENTE_CHR'

fallo = any(not g for g in resultados_gates)
out = os.path.join(BASE_DIR, 'informe_test_masivo_v6.json')
with open(out, 'w', encoding='utf-8') as f:
    json.dump(RESULTADOS, f, ensure_ascii=False, indent=2)
print(f"\nInforme guardado: {out}")

if fallo:
    print("[FAIL] Al menos un gate v6 falló. Código de salida: 1")
    sys.exit(1)
print("[PASS] Gates v6 superados. T5v6 queda pendiente de CHR.")
print("[FIN] Batería v6 terminada.")
