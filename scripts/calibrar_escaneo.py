# -*- coding: utf-8 -*-
"""
calibrar_escaneo.py — Percentiles del detector de escaneo v5 (fase C3).

Uso (tras >= 72 h de captura en modo observación):
    python scripts/calibrar_escaneo.py [--horas 72] [--bd intrusiones_v5.db]

Lee `ataques` de la BD v5 y calcula P50/P90/P95/P99 de n_puertos y
n_destinos, separando destino interno/externo y franja horaria. El umbral
definitivo es P99 + margen: ese número, no "50 a ojo".
"""
import argparse
import os
import sqlite3
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def percentiles(valores, cortes=(50, 90, 95, 99)):
    if not valores:
        return {}
    v = sorted(valores)
    out = {}
    for p in cortes:
        idx = min(len(v) - 1, max(0, int(round((p / 100.0) * (len(v) - 1)))))
        out[p] = v[idx]
    out['n'] = len(v)
    out['max'] = v[-1]
    return out


def es_interna(ip):
    return ip and (ip.startswith(('172.10.', '172.20.', '172.30.', '10.',
                                  '192.168.')))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bd', default=os.environ.get('IDS_DB_PATH')
                    or os.path.join(BASE_DIR, 'intrusiones_v5.db'))
    ap.add_argument('--horas', type=int, default=72)
    args = ap.parse_args()

    if not os.path.exists(args.bd):
        print(f"[X] No existe {args.bd}")
        sys.exit(1)

    conn = sqlite3.connect(f"file:{args.bd}?mode=ro", uri=True)
    cur = conn.cursor()

    total, observacion = cur.execute(
        "SELECT COUNT(*), SUM(modo='observacion') FROM ataques").fetchone()
    print(f"BD: {args.bd}")
    print(f"Eventos totales: {total} | en modo observación: {observacion or 0}")
    print(f"(Ventana de referencia del análisis: últimas {args.horas} h de ts_utc)\n")

    filas = cur.execute('''
        SELECT tipo_ataque, origen, n_puertos, n_destinos, ventana_s, umbral,
               ip_dst, ts_utc
        FROM ataques
        WHERE ts_utc >= datetime('now', ?)
        ORDER BY ts_utc
    ''', (f'-{args.horas} hours',)).fetchall()

    if not filas:
        print("[!] Sin eventos en la ventana. ¿Lleva el sniffer 72 h en marcha?")
        sys.exit(0)

    for titulo, col in [('n_puertos (escaneo vertical)', 2),
                        ('n_destinos (barrido horizontal)', 3)]:
        datos = [f for f in filas if f[col] and f[col] > 0]
        if not datos:
            print(f"== {titulo}: sin datos ==")
            continue
        print(f"== {titulo}: {len(datos)} eventos ==")
        for segmento, pred in [('destino interno', lambda f: es_interna(f[6])),
                               ('destino externo', lambda f: not es_interna(f[6]))]:
            sub = [f[col] for f in datos if pred(f)]
            pct = percentiles(sub)
            if pct:
                print(f"  {segmento:<16} n={pct['n']:>5}  "
                      f"P50={pct[50]:>4}  P90={pct[90]:>4}  "
                      f"P95={pct[95]:>4}  P99={pct[99]:>4}  MAX={pct['max']:>5}")
        print()

    print("== Alertas por día (ritmo) ==")
    por_dia = {}
    for f in filas:
        por_dia[f[7][:10]] = por_dia.get(f[7][:10], 0) + 1
    for dia in sorted(por_dia):
        print(f"  {dia}  {por_dia[dia]:>5}")

    print("\nSugerencia: umbral = P99 del segmento + margen de seguridad.")
    print("Documenta el valor elegido y su percentil en el informe de calibración.")
    conn.close()


if __name__ == '__main__':
    main()
