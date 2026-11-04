# -*- coding: utf-8 -*-
"""
descargar_datasets_v6.py — Descarga de datasets para ML v6 (checklist de arranque).

Uso:
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py              # todo lo necesario
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py --solo IDS2017
    venv\\Scripts\\python.exe scripts\\descargar_datasets_v6.py --listar

Qué descarga y por qué (ver docs/ML_V6_DESARROLLO.md §3):
  IDS2018  CSE-CIC-IDS2018 MachineLearningCSV (AWS S3 público)  → clases volumétricas
           y de explotación del multiclase; ablation de fuga de Dst Port en M0/M3.
  IDS2017  CIC-IDS2017 MachineLearningCSV (cicresearch.ca)      → ÚNICA fuente de
           Port_Scanner + ataques web (Bruteforce/XSS/SQLi del viernes).
  SQLi     Zenodo 6907252 D1_train.csv (Union SQLi)             → entrenamiento M2.
  CSIC2010 espejos públicos de la ISI (opcional, M2)            → HTTP benigno.

Qué NO descarga (decisión documentada 2026-11-04):
  CIC-DDoS2019  → 30 GB; opcional según el plan ("hoy lo cubre la heurística").
                  Si M3 muestra debilidad en DDoS/UDP, descargar subconjunto
                  (UDPLag 158 MB, Syn 637 MB, DrDoS_LDAP 917 MB).
  CIC-IDS2020   → No está en el plan ni en MAPEO_CLASES del generador; no aporta
                  clases nuevas (solapa con 2018/2019). Alcance de tesis innecesario.

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

URL_IDS2018 = 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/MachineLearningCSV/MachineLearningCVE/'
URL_IDS2017 = 'http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV/MachineLearningCVE/'
URL_ZENODO_D1 = 'https://zenodo.org/records/6907252/files/D1_train.csv?download=1'

ARCHIVOS_2018 = [
    '02-14-2018.csv', '02-15-2018.csv', '02-16-2018.csv', '02-20-2018.csv',
    '02-21-2018.csv', '02-22-2018.csv', '02-23-2018.csv', '02-28-2018.csv',
    '03-01-2018.csv', '03-02-2018.csv',
]
ARCHIVOS_2017 = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

# (dataset, nombre_local, url, dir_destino)
MANIFIESTO = (
    [('IDS2018', f, URL_IDS2018 + f, 'datasets/CSE-CIC-IDS2018') for f in ARCHIVOS_2018]
    + [('IDS2017', f, URL_IDS2017 + f, 'datasets/CIC-IDS2017') for f in ARCHIVOS_2017]
    + [('SQLi', 'D1_train.csv', URL_ZENODO_D1, 'datasets/SQLi_Zenodo')]
    # CSIC 2010: la fuente original (isi.csic.es) suele estar caída; espejos
    # requieren registro (Kaggle). Se intenta el espejo público más conocido;
    # si falla queda documentado como pendiente manual.
    + [('CSIC2010', 'normal_traffic_train.csv',
        'http://www.isi.csic.es/dataset/normal_traffic_train.csv', 'datasets/CSIC2010')]
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
    except Exception as e:
        return -1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--solo', choices=['IDS2018', 'IDS2017', 'SQLi', 'CSIC2010'],
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
        cols = verificar_csv(destino) if estado != 'fallo' and destino.exists() else -1
        ok = estado != 'fallo' and cols > 1
        print(f'    -> {estado} ({tam:,} bytes, {cols} columnas){" [OK]" if ok else " [REVISAR]"}')
        resultados.append((ds, nombre, estado, tam, cols, ok))

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
