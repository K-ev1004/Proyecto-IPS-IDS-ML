# -*- coding: utf-8 -*-
"""
descargar_datasets_v6.py — Descarga de datasets para ML v6 (checklist de arranque).

Uso:
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py              # todo lo necesario
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py --solo IDS2017
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py --listar

Qué descarga y por qué (ver docs/ML_V6_DESARROLLO.md §3):
  IDS2018  CSE-CIC-IDS2018 CICFlowMeter (AWS S3 público)  → clases volumétricas
           y de explotación del multiclase; ablation de fuga de Dst Port en M0/M3.
  IDS2017  CIC-IDS2017 MachineLearningCSV.zip (espejo oficial en Hugging Face)
           → ÚNICA fuente de Port_Scanner + ataques web (viabilidad §5).
           2026-11-04: UNB eliminó las descargas directas (cicresearch.ca y
           205.174.165.80 devuelven una página HTML de 98.455 bytes en cualquier
           ruta); el ZIP espejado tiene el tamaño EXACTO del oficial
           (235.102.953 bytes, log wget 2020) y trae los 8 CSV oficiales
           (Thursday-Afternoon-DDos no forma parte de MachineLearningCSV).
  SQLi     Zenodo 6907252 "SLQ Injection Attack for training (D1).csv"
           (nombre real del archivo; se guarda como D1_train.csv) → M2.

Qué NO descarga (decisión documentada 2026-11-04):
  CIC-DDoS2019  → 30 GB; opcional según el plan ("hoy lo cubre la heurística").
                  Si M3 muestra debilidad en DDoS/UDP, descargar subconjunto
                  (UDPLag 158 MB, Syn 637 MB, DrDoS_LDAP 917 MB).
  CIC-IDS2020   → No está en el plan ni en MAPEO_CLASES del generador; no aporta
                  clases nuevas (solapa con 2018/2019). Alcance de tesis innecesario.
  CSIC2010      → Pendiente MANUAL: la fuente original (isi.csic.es) está caída
                  y los espejos útiles (Kaggle) exigen cuenta. Opcional para M2;
                  se retoma solo si el modelo de payload lo necesita.

Reanudación: cada archivo baja a <destino>.part y se retoma con Range si se corta.
Verificación: tamaño contra Content-Length y cabecera legible por pandas.
Reporte: entrenar/resultados/descargas_v6.txt (append; sin datos personales).
"""
import argparse
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

URL_IDS2018 = ('https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'
               'Processed%20Traffic%20Data%20for%20ML%20Algorithms/')
URL_IDS2017_ZIP = ('https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/'
                   'main/csvs/MachineLearningCSV.zip')
URL_ZENODO_D1 = ('https://zenodo.org/api/records/6907252/files/'
                 'SLQ%20Injection%20Attack%20for%20training%20(D1).csv/content')

# El bucket S3 publica los CICFlowMeter por día (nombres largos); los guardamos
# con la nomenclatura de MachineLearningCSV usada en docs/ml/viabilidad-datasets.md.
MAPEO_2018 = [
    ('Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv', '02-14-2018.csv'),
    ('Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv',  '02-15-2018.csv'),
    ('Friday-16-02-2018_TrafficForML_CICFlowMeter.csv',    '02-16-2018.csv'),
    ('Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv',  '02-20-2018.csv'),
    ('Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv', '02-21-2018.csv'),
    ('Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv',  '02-22-2018.csv'),
    ('Friday-23-02-2018_TrafficForML_CICFlowMeter.csv',    '02-23-2018.csv'),
    ('Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv', '02-28-2018.csv'),
    ('Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv',  '03-01-2018.csv'),
    ('Friday-02-03-2018_TrafficForML_CICFlowMeter.csv',    '03-02-2018.csv'),
]

# (dataset, nombre_local, url, dir_destino)
MANIFIESTO = (
    [('IDS2018', local, URL_IDS2018 + remoto, 'datasets/CSE-CIC-IDS2018')
     for remoto, local in MAPEO_2018]
    # IDS2017: ZIP completo (8 CSV oficiales dentro); se extrae plano.
    + [('IDS2017', 'MachineLearningCSV.zip', URL_IDS2017_ZIP, 'datasets/CIC-IDS2017')]
    + [('SQLi', 'D1_train.csv', URL_ZENODO_D1, 'datasets/SQLi_Zenodo')]
)

REPORTE = BASE_DIR / 'entrenar' / 'resultados' / 'descargas_v6.txt'


def descargar(nombre, url, destino: Path, reintentos=3):
    import requests
    from tqdm import tqdm

    if destino.exists() and destino.stat().st_size > 0:
        return ('ya_estaba', destino.stat().st_size)

    destino.parent.mkdir(parents=True, exist_ok=True)
    parte = destino.with_suffix(destino.suffix + '.part')
    descargado = parte.stat().st_size if parte.exists() else 0

    for intento in range(1, reintentos + 1):
        try:
            cabeceras = {'Range': f'bytes={descargado}-'} if descargado else {}
            with requests.get(url, stream=True, timeout=60, headers=cabeceras) as r:
                if descargado and r.status_code == 416:
                    r.close()
                    parte.rename(destino)
                    return ('reanudado_ok', destino.stat().st_size)
                r.raise_for_status()
                total = int(r.headers.get('Content-Length', 0)) + (descargado if descargado else 0)
                modo = 'ab' if descargado else 'wb'
                with open(parte, modo) as fh, tqdm(
                        total=total, initial=descargado, unit='B', unit_scale=True,
                        desc=f'  {nombre}', ncols=90, leave=False) as barra:
                    for bloque in r.iter_content(chunk_size=1024 * 1024):
                        fh.write(bloque)
                        barra.update(len(bloque))
            # Verificación: tamaño si el servidor lo dio (y no hubo Range parcial)
            if total and parte.stat().st_size != total:
                raise IOError(f'tamaño {parte.stat().st_size} != esperado {total}')
            parte.rename(destino)
            return ('ok', destino.stat().st_size)
        except Exception as e:
            descargado = parte.stat().st_size if parte.exists() else 0
            print(f'  [!] intento {intento}/{reintentos} falló: {e}')
            time.sleep(3 * intento)
    return ('fallo', 0)


def verificar_csv(ruta: Path):
    """Chequeo barato: el CSV abre y tiene más de 1 columna."""
    try:
        import pandas as pd
        cab = pd.read_csv(ruta, nrows=2)
        return len(cab.columns)
    except Exception:
        return -1


def verificar_y_extraer_zip(ruta_zip: Path, destino: Path):
    """Verifica el ZIP y extrae los CSV PLANOS (el generador lista la carpeta
    sin recursion). Devuelve (ok, detalle)."""
    import zipfile
    try:
        with zipfile.ZipFile(ruta_zip) as z:
            malo = z.testzip()
            if malo:
                return False, f'miembro corrupto: {malo}'
            csvs = [n for n in z.namelist()
                    if n.lower().endswith('.csv') and not n.endswith('/')]
            # El ZIP oficial trae 8 CSV (Thursday-Afternoon-DDos NO esta en
            # MachineLearningCSV; el DDoS de 2017 entra por Friday-Afternoon-DDos).
            if len(csvs) != 8:
                return False, f'esperaba 8 CSV, hay {len(csvs)}: {csvs}'
            destino.mkdir(parents=True, exist_ok=True)
            for n in csvs:
                (destino / Path(n).name).write_bytes(z.read(n))
        # verificación final con pandas (los 9 deben abrir con ~80 columnas)
        import pandas as pd
        cols_min = min(len(pd.read_csv(destino / Path(n).name, nrows=1).columns)
                       for n in csvs)
        if cols_min < 70:  # 79 features + Label
            return False, f'CSVs extraidos con pocas columnas: {cols_min}'
        return True, f'{len(csvs)} CSV extraidos, min {cols_min} columnas'
    except Exception as e:
        return False, str(e)


def main():
    # Sin TTY el stdout va bufferizado: forzar línea a línea para ver progreso
    try:
        sys.stdout.reconfigure(line_buffering=True, errors='replace')
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--solo', choices=['IDS2018', 'IDS2017', 'SQLi'],
                    help='descarga solo un dataset')
    ap.add_argument('--listar', action='store_true', help='muestra el manifiesto y sale')
    args = ap.parse_args()

    items = [m for m in MANIFIESTO if (not args.solo or m[0] == args.solo)]
    if args.listar:
        for ds, nombre, url, ddir in items:
            print(f'[{ds}] {ddir}/{nombre}')
        return

    REPORTE.parent.mkdir(parents=True, exist_ok=True)
    resultados = []
    print(f'[*] {len(items)} archivos en cola ({", ".join(sorted(set(m[0] for m in items)))})')
    for ds, nombre, url, ddir in items:
        destino = BASE_DIR / ddir / nombre
        print(f'[*] [{ds}] {nombre}')
        estado, tam = descargar(nombre, url, destino)
        if ds == 'IDS2017' and estado != 'fallo' and destino.exists():
            # verificación de integridad + extracción plana de los 9 CSV
            ok_zip, detalle = verificar_y_extraer_zip(destino, BASE_DIR / ddir)
            print(f'    -> zip: {detalle} {"[OK]" if ok_zip else "[REVISAR]"}')
            resultado = (ds, nombre, 'ok' if ok_zip else 'fallo',
                         destino.stat().st_size, detalle, ok_zip)
        else:
            cols = verificar_csv(destino) if estado != 'fallo' and destino.exists() else -1
            ok = estado != 'fallo' and cols > 1
            print(f'    -> {estado} ({tam:,} bytes, {cols} columnas)'
                  f'{" [OK]" if ok else " [REVISAR]"}')
            resultado = (ds, nombre, estado, tam, cols, ok)
        resultados.append(resultado)

    # Reporte versionable (sin datos personales: solo tamaños y estados)
    from datetime import datetime, timezone
    with open(REPORTE, 'a', encoding='utf-8') as fh:
        fh.write(f'\n## corrida {datetime.now(timezone.utc).isoformat(timespec="seconds")}\n')
        for ds, nombre, estado, tam, cols, ok in resultados:
            fh.write(f'| {ds} | {nombre} | {estado} | {tam:,} | {cols} | '
                     f'{"OK" if ok else "REVISAR"} |\n')
    print(f'\n[OK] Reporte: {REPORTE}')
    fallos = [r for r in resultados if not r[5]]
    if fallos:
        print(f'[!] {len(fallos)} archivo(s) pendientes:')
        for ds, nombre, estado, *_ in fallos:
            print(f'     - [{ds}] {nombre} ({estado})')
        sys.exit(2)


if __name__ == '__main__':
    main()
