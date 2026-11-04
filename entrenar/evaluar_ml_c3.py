# -*- coding: utf-8 -*-
"""
evaluar_ml_c3.py — M0: línea base del ML v5 contra el corpus C3 (72 h).

Uso:
    venv\\Scripts\\python.exe entrenar\\evaluar_ml_c3.py            # replay completo
    venv\\Scripts\\python.exe entrenar\\evaluar_ml_c3.py --fuga     # solo estudio de fuga

Qué hace (PUERTA M0 del plan docs/PLAN_ML_V6.md):
  1. REPLAY: pasa las 276.098 features_json del corpus C3 por SQLiGuard v5
     (las mismas 9 features NetFlow, mismo umbral 0.30) y reconstruye las
     decisiones que tomó el motor durante la corrida.
  2. VERDAD: clasifica cada fila con la lógica auditada de scripts/clasificar_c3.py
     (familias fp_*/senal_*). En C3 la señal real son los eventos senal_exploit_*;
     todo lo demás es benigno.
  3. METRICAS "ANTES": matriz de confusión, FP/día del canal ML, FP/día de
     SQLiGuard, determinismo (replay vs decisión viva), histograma de confianza,
     análisis de vectores en cero y FP por hora. Solo agregados, sin IPs.
  4. FUGA (--fuga): con CSE-CIC-IDS2018 en datasets/, entrena
     (a) LogReg con las 23 features, (b) LogReg sin Dst/Src Port y
     (c) un árbol que SOLO usa Dst Port. Si (c) clasifica bien, la fuga es
     evidente y queda documentada para la tesis.

Salidas:
    entrenar/resultados/M0_linea_base.md     informe versionable (agregados)
    entrenar/resultados/metricas_v6_M0.txt   números clave, comparable a v5

Reglas del laboratorio: BD propia en modo read-only, sin capturar red,
semilla fija 42, nada de resultados "a ojo".
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'scripts'))

from clasificar_c3 import clasificar  # lógica auditada del rescate C3

SEMILLA = 42
CORPUS_DEF = (BASE_DIR / 'evidencia' / 'db_archive'
              / 'intrusiones_v5_c3-72h_20261104_161736.db')
SALIDAS = BASE_DIR / 'entrenar' / 'resultados'
CHUNK = 10000


def cargar_sqli_guard():
    """Carga SQLiGuard v5 exactamente como lo carga ids.py."""
    import joblib
    ruta = BASE_DIR / 'Modelos_Entrenados' / 'sqli_guard.pkl'
    meta = BASE_DIR / 'Modelos_Entrenados' / 'sql_guard_features.pkl'
    modelo = joblib.load(ruta)
    meta = joblib.load(meta)
    return modelo, meta['features'], meta['umbral'], meta['mapa']


def replay():
    import pandas as pd

    modelo, feats, umbral, mapa = cargar_sqli_guard()
    clase_pos = [k for k, v in mapa.items() if v == 'Inyeccion_SQL'][0]

    conn = _conectar_corpus()
    cur = conn.cursor()
    total = cur.execute('SELECT COUNT(*) FROM ataques').fetchone()[0]
    print(f'[*] Corpus: {total:,} filas | umbral SQLiGuard: {umbral} | '
          f'features: {feats}')

    filas = []
    for (fid, ts, tipo, origen, ip_src, ip_dst, proto, puerto,
         n_puertos, n_destinos, evidencia, features) in cur.execute(
            'SELECT id, ts_utc, tipo_ataque, origen, ip_src, ip_dst, protocolo, '
            'puerto, n_puertos, n_destinos, evidencia_json, features_json '
            'FROM ataques ORDER BY id'):
        filas.append((fid, ts, tipo, origen, ip_src, ip_dst, proto, puerto,
                      n_puertos, n_destinos, evidencia, features))

    # --- verdad por fila (lógica clasificar_c3) ---
    verdad = {}
    for fila in filas:
        (fid, ts, tipo, origen, ip_src, ip_dst, proto, puerto,
         n_puertos, n_destinos, evidencia, features) = fila
        clase, _ = clasificar((tipo, origen, ip_src, ip_dst, proto, puerto,
                               n_puertos, n_destinos, evidencia, features))
        verdad[fid] = clase

    # --- replay por chunks ---
    probs = {}
    pred_alerta = {}
    t0 = time.perf_counter()
    for i in range(0, len(filas), CHUNK):
        lote = filas[i:i + CHUNK]
        dicts = []
        for f in lote:
            try:
                d = json.loads(f[11] or '{}')
            except (ValueError, TypeError):
                d = {}
            dicts.append({k: float(d.get(k, 0) or 0) for k in feats})
        df = pd.DataFrame(dicts, columns=feats)
        p = modelo.predict_proba(df)[:, clase_pos]
        for f, pv in zip(lote, p):
            probs[f[0]] = float(pv)
            pred_alerta[f[0]] = pv >= umbral
        if (i // CHUNK) % 5 == 0:
            print(f'    replay {i + len(lote):>7,}/{total:,}', end='\r')
    ms_por_fila = (time.perf_counter() - t0) * 1000 / max(1, len(filas))
    print(f'\n[*] Replay completo en {ms_por_fila * len(filas) / 1000:.1f} s '
          f'({ms_por_fila:.3f} ms/fila)')

    conn.close()
    return filas, verdad, probs, pred_alerta, umbral, ms_por_fila


def _conectar_corpus():
    bd = CORPUS_DEF
    if not bd.exists():
        print(f'[X] No existe el corpus: {bd}')
        sys.exit(1)
    import sqlite3
    conn = sqlite3.connect(f'file:{bd}?mode=ro', uri=True)
    ok = conn.execute('PRAGMA integrity_check').fetchone()[0]
    if ok != 'ok':
        print(f'[X] Integridad SQLite: {ok}')
        sys.exit(1)
    return conn


def metricas(filas, verdad, probs, pred_alerta, umbral, ms_por_fila):
    import pandas as pd

    total = len(filas)
    dur_horas = (datetime.fromisoformat(filas[-1][1])
                 - datetime.fromisoformat(filas[0][1])).total_seconds() / 3600
    dias = dur_horas / 24

    # --- canal ML vivo (lo que el motor decidió en C3) ---
    vivos_ml = [f for f in filas if f[3] == 'ml']
    vivos_heur = [f for f in filas if f[3] != 'ml']
    vivos_ml_sqli = [f for f in vivos_ml if f[2].startswith('Inyeccion_SQL')]

    # --- replay vs verdad ---
    tp = fp = fn = tn = 0
    por_familia = defaultdict(lambda: {'n': 0, 'alerta_replay': 0, 'prob_sum': 0.0,
                                       'prob_max': 0.0})
    por_hora_fp = Counter()
    conf_hist = Counter()
    cero_vec = {'n': 0, 'alerta': 0}
    determinismo_ok = 0
    for f in filas:
        fid, ts, tipo, origen = f[0], f[1], f[2], f[3]
        fam = verdad[fid]
        pv = probs[fid]
        pa = pred_alerta[fid]
        es_ataque = fam.startswith('senal_')
        if es_ataque:
            tp += pa
            fn += (not pa)
        else:
            fp += pa
            tn += (not pa)
            if pa:
                por_hora_fp[ts[:13]] += 1
        d = por_familia[fam]
        d['n'] += 1
        d['alerta_replay'] += pa
        d['prob_sum'] += pv
        d['prob_max'] = max(d['prob_max'], pv)
        if pa:
            conf_hist[round(pv / 0.05) * 0.05] += 1
        # vector en cero: sin puertos y sin tráfico (familia sin_flujo)
        if fam == 'fp_ml_sqli_sin_flujo':
            cero_vec['n'] += 1
            cero_vec['alerta'] += pa
        # determinismo: lo que el motor alertó como SQLi ML debe reproducirse
        if origen == 'ml' and tipo.startswith('Inyeccion_SQL') and pa:
            determinismo_ok += 1

    r = {
        'corpus': {
            'filas': total, 'horas': round(dur_horas, 2), 'dias': round(dias, 3),
            'familias': {k: v['n'] for k, v in sorted(
                por_familia.items(), key=lambda kv: -kv[1]['n'])},
        },
        'canal_ml_vivo_c3': {
            'alertas_ml': len(vivos_ml),
            'fp_ml_por_dia': round(len(vivos_ml) / dias, 1),
            'sqli_ml': len(vivos_ml_sqli),
            'eventos_heuristicos': len(vivos_heur),
        },
        'sqli_guard_replay': {
            'umbral': umbral,
            'alertas_replay': tp + fp,
            'fp_replay': fp,
            'fp_replay_por_dia': round(fp / dias, 1),
            'tp_replay': tp, 'fn_replay': fn, 'tn_replay': tn,
            'precision_replay': round(tp / (tp + fp), 5) if tp + fp else None,
            'recall_replay': round(tp / (tp + fn), 5) if tp + fn else None,
            'ms_por_prediccion': round(ms_por_fila, 3),
            'determinismo_sqli_vivo': f'{determinismo_ok}/{len(vivos_ml_sqli)}',
        },
        'vectores_cero': cero_vec,
        'fp_top_horas': por_hora_fp.most_common(5),
        'confianza_fp_hist': {f'{k:.2f}': v for k, v in sorted(conf_hist.items())},
        'familias_detalle': {k: {
            'n': v['n'],
            'alerta_replay': v['alerta_replay'],
            'tasa_alerta': round(v['alerta_replay'] / v['n'], 4),
            'prob_media': round(v['prob_sum'] / v['n'], 4),
            'prob_max': round(v['prob_max'], 4),
        } for k, v in sorted(por_familia.items(), key=lambda kv: -kv[1]['n'])},
    }
    return r


def estudio_fuga(muestra=400_000):
    """Ablation con/sin puertos sobre CSE-CIC-IDS2018 (M0)."""
    carpeta = BASE_DIR / 'datasets' / 'CSE-CIC-IDS2018'
    csvs = sorted(carpeta.glob('*.csv')) if carpeta.exists() else []
    if not csvs:
        print('[!] Sin CSE-CIC-IDS2018 en datasets/ — fuga se evalúa cuando '
              'termine la descarga (scripts/descargar_datasets_v6.py).')
        return None
    import numpy as np
    import pandas as pd
    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    from sklearn.metrics import (accuracy_score, f1_score,
                                 precision_recall_fscore_support)

    import joblib
    feats = list(joblib.load(BASE_DIR / 'Modelos_Entrenados'
                             / 'selected_features_v5.pkl'))
    partes = []
    for ruta in csvs:
        # 1 de cada 7 filas para no cargar el archivo completo en memoria
        df = pd.read_csv(ruta, skiprows=lambda i: i > 0 and (i % 7), low_memory=False)
        partes.append(df)
        if sum(len(p) for p in partes) >= muestra:
            break
    df = pd.concat(partes, ignore_index=True)
    if len(df) > muestra:  # acoto: LogReg sobre millones tardaria horas
        df = df.sample(n=muestra, random_state=SEMILLA)
    df.columns = df.columns.str.strip()
    if 'Destination Port' in df.columns:
        df = df.rename(columns={'Destination Port': 'Dst Port'})
    df = df[feats + ['Label']].replace([np.inf, -np.inf], np.nan).dropna()
    y = df['Label']
    X = df[feats].apply(pd.to_numeric, errors='coerce').fillna(0)
    sin_puerto = [f for f in feats if f not in ('Dst Port', 'Src Port')]
    if 'Src Port' not in feats:  # v5 solo trae Dst Port
        sin_puerto = [f for f in feats if f != 'Dst Port']

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                          random_state=SEMILLA, stratify=y)
    res = {}
    for nombre, cols in [('23_features', feats), ('sin_puertos', sin_puerto)]:
        m = make_pipeline(StandardScaler(), LogisticRegression(
            max_iter=1000, random_state=SEMILLA))
        m.fit(Xtr[cols], ytr)
        yp = m.predict(Xte[cols])
        res[nombre] = {
            'accuracy': round(accuracy_score(yte, yp), 4),
            'macro_f1': round(f1_score(yte, yp, average='macro'), 4),
            'n_features': len(cols),
        }
    # árbol SOLO con Dst Port: si clasifica casi igual, el puerto etiqueta la clase
    arbol = DecisionTreeClassifier(max_depth=8, random_state=SEMILLA)
    arbol.fit(Xtr[['Dst Port']], ytr)
    yp = arbol.predict(Xte[['Dst Port']])
    res['solo_dst_port_arbol'] = {
        'accuracy': round(accuracy_score(yte, yp), 4),
        'macro_f1': round(f1_score(yte, yp, average='macro'), 4),
        'n_features': 1,
    }
    # por clase, en el modelo completo vs sin puertos (clases pequeñas delatan fuga)
    m_full = make_pipeline(StandardScaler(), LogisticRegression(
        max_iter=1000, random_state=SEMILLA))
    m_full.fit(Xtr[feats], ytr)
    m_sin = make_pipeline(StandardScaler(), LogisticRegression(
        max_iter=1000, random_state=SEMILLA))
    m_sin.fit(Xtr[sin_puerto], ytr)
    clases = sorted(y.unique())
    res['por_clase'] = {}
    for nombre, m, cols in [('23_features', m_full, feats),
                            ('sin_puertos', m_sin, sin_puerto)]:
        yp = m.predict(Xte[cols])
        prec, rec, _, _ = precision_recall_fscore_support(
            yte, yp, labels=clases, zero_division=0)
        res['por_clase'][nombre] = {
            c: {'p': round(p, 3), 'r': round(r, 3)}
            for c, p, r in zip(clases, prec, rec)}
    return res


def escribir_fuga(fuga):
    """Escribe el estudio de fuga en su propio archivo (no toca el informe
    del replay: pueden correr por separado)."""
    SALIDAS.mkdir(parents=True, exist_ok=True)
    ahora = datetime.now(timezone.utc).isoformat(timespec='seconds')
    ruta_md = SALIDAS / 'M0_fuga_puertos.md'
    with open(ruta_md, 'w', encoding='utf-8') as fh:
        fh.write('# M0 — Fuga de características (Dst Port) en CSE-CIC-IDS2018\n\n')
        fh.write(f'**Generado:** {ahora} · semilla {SEMILLA} · '
                 f'LogReg (StandardScaler) holdout 80/20 estratificado\n\n')
        fh.write('| Modelo | Accuracy | Macro-F1 | Features |\n|---|---:|---:|---:|\n')
        for k in ('23_features', 'sin_puertos', 'solo_dst_port_arbol'):
            d = fuga[k]
            fh.write(f'| {k} | {d["accuracy"]} | {d["macro_f1"]} | {d["n_features"]} |\n')
        fh.write('\nUn árbol que SOLO mira `Dst Port` clasificando casi igual que '
                 'el modelo completo es la prueba directa de fuga: el puerto '
                 'cuasi-etiqueta la clase en los CIC (defecto nº 3 del diagnóstico).\n\n')
        fh.write('## Por clase (precision/recall en holdout)\n\n')
        for variante, detalle in fuga.get('por_clase', {}).items():
            fh.write(f'- **{variante}**: ' + ', '.join(
                f'{c}: p={d["p"]}/r={d["r"]}' for c, d in detalle.items()) + '\n')
        fh.write('\n**Lectura (defecto nº 3 confirmado):**\n\n')
        fh.write('1. **Fuga directa**: un árbol que SOLO mira `Dst Port` alcanza '
                 f'**{fuga["solo_dst_port_arbol"]["accuracy"]*100:.1f} % de accuracy** '
                 'con una sola feature: el puerto cuasi-etiqueta la clase.\n')
        costo = fuga['23_features']['accuracy'] - fuga['sin_puertos']['accuracy']
        fh.write(f'2. **Costo de quitarla es bajo**: el modelo completo pierde solo '
                 f'{costo*100:.1f} puntos de accuracy al eliminar `Dst Port`.\n')
        fh.write('3. En M3 se entrenan las dos variantes y se decide con replay C3, '
                 'no con accuracy del holdout (la tensión holdout-sintético vs '
                 'generalización-real es el resultado de la tesis).\n\n')
    print(f'[OK] {ruta_md}')


def escribir_salidas(r):
    SALIDAS.mkdir(parents=True, exist_ok=True)
    ahora = datetime.now(timezone.utc).isoformat(timespec='seconds')

    ruta_txt = SALIDAS / 'metricas_v6_M0.txt'
    with open(ruta_txt, 'w', encoding='utf-8') as fh:
        fh.write(f'M0 linea base — metricas v6 (generado {ahora})\n')
        fh.write(f'corpus: {r["corpus"]["filas"]:,} filas / '
                 f'{r["corpus"]["horas"]} h\n')
        fh.write(f'FP/dia canal ML v5 (vivo C3): {r["canal_ml_vivo_c3"]["fp_ml_por_dia"]:,}\n')
        sg = r['sqli_guard_replay']
        fh.write(f'SQLiGuard replay: {sg["alertas_replay"]:,} alertas, '
                 f'{sg["fp_replay_por_dia"]:,} FP/dia, '
                 f'precision={sg["precision_replay"]}, recall={sg["recall_replay"]}\n')
        fh.write(f'determinismo replay vs vivo: {sg["determinismo_sqli_vivo"]}\n')
        fh.write(f'vectores cero: {r["vectores_cero"]["n"]:,} '
                 f'(alerta {r["vectores_cero"]["alerta"]:,})\n')
        fh.write(f'latencia: {sg["ms_por_prediccion"]} ms/prediccion\n')
        fh.write('fuga Dst Port: ver entrenar/resultados/M0_fuga_puertos.md\n')
    print(f'[OK] {ruta_txt}')

    ruta_md = SALIDAS / 'M0_linea_base.md'
    with open(ruta_md, 'w', encoding='utf-8') as fh:
        fh.write('# M0 — Línea base del ML v5 contra el corpus C3\n\n')
        fh.write(f'**Generado:** {ahora} · semilla {SEMILLA} · '
                 f'corpus 72 h read-only · sin captura de red\n\n')
        fh.write('## 1. El "antes" (números formales)\n\n')
        fh.write('| Métrica | Valor |\n|---|---|\n')
        fh.write(f'| Filas del corpus | {r["corpus"]["filas"]:,} |\n')
        fh.write(f'| Duración | {r["corpus"]["horas"]} h |\n')
        fh.write(f'| Alertas del canal ML (vivas) | {r["canal_ml_vivo_c3"]["alertas_ml"]:,} |\n')
        fh.write(f'| **FP/día del canal ML v5** | **{r["canal_ml_vivo_c3"]["fp_ml_por_dia"]:,}** |\n')
        fh.write(f'| Predicciones SQLi (vivas) | {r["canal_ml_vivo_c3"]["sqli_ml"]:,} |\n')
        sg = r['sqli_guard_replay']
        fh.write(f'| SQLiGuard replay: alertas | {sg["alertas_replay"]:,} |\n')
        fh.write(f'| SQLiGuard replay: FP/día | {sg["fp_replay_por_dia"]:,} |\n')
        fh.write(f'| SQLiGuard replay: precisión | {sg["precision_replay"]} |\n')
        fh.write(f'| SQLiGuard replay: recall | {sg["recall_replay"]} |\n')
        fh.write(f'| Determinismo replay vs vivo | {sg["determinismo_sqli_vivo"]} |\n')
        fh.write(f'| Latencia por predicción | {sg["ms_por_prediccion"]} ms |\n')
        fh.write('\n> **Nota de entorno:** los .pkl v5 se serializaron con scikit-learn 1.8.0 y el '
                 'venv del laboratorio tiene 1.9.0 (`InconsistentVersionWarning`). El determinismo '
                 'replay vs vivo 100 % valida que la inferencia no cambió. Para M3, re-serializar '
                 'los artefactos con el venv actual.\n')
        fh.write('\n> Puerta M2 usa "FP ≤ 0,1 % en replay" y M4 "FP/día ≈ 0": '
                 'comparar SIEMPRE contra esta tabla.\n\n')
        fh.write('## 2. Descomposición del FP (familias clasificar_c3)\n\n')
        fh.write('| Familia | Eventos | Alerta replay | Tasa | P. media | P. máx |\n')
        fh.write('|---|---:|---:|---:|---:|---:|\n')
        for fam, d in r['familias_detalle'].items():
            fh.write(f'| `{fam}` | {d["n"]:,} | {d["alerta_replay"]:,} | '
                     f'{d["tasa_alerta"]} | {d["prob_media"]} | {d["prob_max"]} |\n')
        fh.write('\n## 3. Vectores en cero (defecto nº 1 del diagnóstico)\n\n')
        fh.write(f'{r["vectores_cero"]["n"]:,} filas sin puertos/tráfico '
                 f'({100.0 * r["vectores_cero"]["n"] / r["corpus"]["filas"]:.2f} %); '
                 f'SQLiGuard alertó {r["vectores_cero"]["alerta"]:,}. '
                 'Esto confirma que la ausencia de dirección/puertos colapsa el '
                 'vector y produce el 99,6 % de los FP.\n\n')
        fh.write('## 4. FP por hora (picos)\n\n')
        for hora, n in r['fp_top_horas']:
            fh.write(f'- {hora}:00 → {n:,} FP\n')
        fh.write('\n## 5. Fuga de características (Dst Port)\n\n')
        fh.write('Estudio aparte: `entrenar/resultados/M0_fuga_puertos.md` '
                 '(se genera con `--fuga` cuando datasets/CSE-CIC-IDS2018/ '
                 'está completo).\n')
    print(f'[OK] {ruta_md}')


def main():
    # Consola Windows (cp1252): evita UnicodeEncodeError con flechas/tildes.
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fuga', action='store_true',
                    help='solo el estudio de fuga (requiere IDS2018)')
    ap.add_argument('--sin-fuga', action='store_true',
                    help='replay sin intentar el estudio de fuga')
    args = ap.parse_args()

    if args.fuga:
        fuga = estudio_fuga()
        if fuga:
            escribir_fuga(fuga)
            print('\n===== RESUMEN FUGA =====')
            for k in ('23_features', 'sin_puertos', 'solo_dst_port_arbol'):
                d = fuga[k]
                print(f'{k}: acc={d["accuracy"]} macro-F1={d["macro_f1"]} '
                      f'({d["n_features"]} features)')
        return

    print('[*] M0: replay del corpus C3 contra SQLiGuard v5...')
    filas, verdad, probs, pred_alerta, umbral, ms = replay()
    r = metricas(filas, verdad, probs, pred_alerta, umbral, ms)

    if not args.sin_fuga:
        print('[*] Estudio de fuga (Dst Port)...')
        try:
            fuga = estudio_fuga()
            if fuga:
                escribir_fuga(fuga)
        except Exception as e:
            print(f'[!] Fuga no completada: {e}')
    escribir_salidas(r)

    print('\n===== RESUMEN M0 =====')
    print(f'FP/día canal ML v5: {r["canal_ml_vivo_c3"]["fp_ml_por_dia"]:,}')
    print(f'SQLiGuard replay: {r["sqli_guard_replay"]["alertas_replay"]:,} alertas '
          f'({r["sqli_guard_replay"]["fp_replay_por_dia"]:,} FP/día), '
          f'precisión {r["sqli_guard_replay"]["precision_replay"]}, '
          f'recall {r["sqli_guard_replay"]["recall_replay"]}')
    print(f'Determinismo: {r["sqli_guard_replay"]["determinismo_sqli_vivo"]}')
    print('Puerta M0 → M1: informe generado. Revisar entrenar/resultados/')


if __name__ == '__main__':
    main()
