# -*- coding: utf-8 -*-
"""
calibrar_escaneo.py — Percentiles REALES del detector de escaneo v5.

Uso:
    python scripts/calibrar_escaneo.py [--horas 24]
    python scripts/calibrar_escaneo.py --desde 2026-11-04T10:00:00 --hasta 2026-11-05T10:00:00
    python scripts/calibrar_escaneo.py --bd intrusiones_v5.db --horas 72

Fuente principal: `metricas_escaneo`, que guarda muestras por par (src, dst)
aunque NO se haya superado el umbral. Así el P99 no es circular.

Si la BD es anterior a esa tabla (p. ej. el corpus C3), cae a `ataques` y lo
advierte: en ese caso solo mide la cola de lo ya alertado.

La ventana se ancla en `max(ts_utc)` de la BD, no en "ahora": una corrida
terminada se puede analizar días después.
"""
import argparse
import math
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

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
    return bool(ip) and ip.startswith(('172.10.', '172.20.', '172.30.', '10.',
                                       '192.168.'))


def _norm_ts(texto, fin=False):
    """Normaliza a ISO-8601 UTC comparable con ts_utc."""
    if not texto:
        return None
    try:
        dt = datetime.fromisoformat(texto)
    except ValueError:
        print(f"[X] Fecha no válida: {texto!r} (usa ISO-8601, p. ej. 2026-11-04T10:00:00)")
        sys.exit(2)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


def _max_ts(cur):
    for tabla in ('metricas_escaneo', 'ataques'):
        try:
            valor = cur.execute(f'SELECT MAX(ts_utc) FROM {tabla}').fetchone()[0]
        except sqlite3.OperationalError:
            valor = None
        if valor:
            return valor
    return None


def _tabla_existe(cur, nombre):
    return cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (nombre,)).fetchone() is not None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bd', default=os.environ.get('IDS_DB_PATH')
                    or os.path.join(BASE_DIR, 'intrusiones_v5.db'))
    ap.add_argument('--horas', type=int, default=24,
                    help='tamaño de la ventana si no se da --desde/--hasta (defecto 24)')
    ap.add_argument('--desde', help='inicio ISO-8601 (UTC si no lleva zona)')
    ap.add_argument('--hasta', help='fin ISO-8601 (UTC si no lleva zona)')
    args = ap.parse_args()

    if not os.path.exists(args.bd):
        print(f"[X] No existe {args.bd}")
        sys.exit(1)

    conn = sqlite3.connect(f"file:{args.bd}?mode=ro", uri=True)
    cur = conn.cursor()

    if args.desde:
        desde = _norm_ts(args.desde)
        hasta = _norm_ts(args.hasta) if args.hasta else None
        if hasta is None:
            dt = datetime.fromisoformat(desde) + timedelta(hours=args.horas)
            hasta = dt.isoformat(timespec='seconds')
    elif args.hasta:
        hasta = _norm_ts(args.hasta)
        dt = datetime.fromisoformat(hasta) - timedelta(hours=args.horas)
        desde = dt.isoformat(timespec='seconds')
    else:
        hasta = _max_ts(cur)
        if not hasta:
            print("[!] La BD no tiene eventos; nada que calibrar.")
            sys.exit(0)
        dt = datetime.fromisoformat(hasta) - timedelta(hours=args.horas)
        desde = dt.isoformat(timespec='seconds')

    print(f"BD: {args.bd}")
    print(f"Ventana analizada: {desde}  ->  {hasta}  ({args.horas} h nominales)")
    print(f"(anclada en max(ts_utc) de la BD, no en la hora actual)\n")

    usar_metricas = _tabla_existe(cur, 'metricas_escaneo')
    filas = []
    if usar_metricas:
        filas = cur.execute('''
            SELECT n_puertos, n_destinos, ip_dst, ts_utc, tipo
            FROM metricas_escaneo
            WHERE ts_utc >= ? AND ts_utc <= ?
            ORDER BY ts_utc
        ''', (desde, hasta)).fetchall()

    fuente = 'metricas_escaneo (bajo umbral)'
    if not filas:
        fuente = 'ataques (SOLO eventos que ya superaron el umbral: P99 circular)'
        try:
            filas = cur.execute('''
                SELECT n_puertos, n_destinos, ip_dst, ts_utc, tipo_ataque
                FROM ataques
                WHERE ts_utc >= ? AND ts_utc <= ?
                  AND (n_puertos > 0 OR n_destinos > 0)
                ORDER BY ts_utc
            ''', (desde, hasta)).fetchall()
        except sqlite3.OperationalError:
            filas = []
        print("[!] Sin muestras en metricas_escaneo para esta ventana.")
        print("    Se usa la tabla de alertas; el percentil NO sirve para fijar")
        print("    el umbral (solo describe lo que ya alertó).\n")

    print(f"Fuente: {fuente} | filas: {len(filas)}")
    try:
        alertas = cur.execute(
            "SELECT COUNT(*) FROM ataques WHERE ts_utc >= ? AND ts_utc <= ?",
            (desde, hasta)).fetchone()[0]
        print(f"Alertas/eventos en la ventana: {alertas}\n")
    except sqlite3.OperationalError:
        pass

    if not filas:
        print("[!] No hay datos en la ventana indicada.")
        conn.close()
        sys.exit(0)

    # --- Vertical: puertos distintos hacia un destino ---
    vertical = [f for f in filas if f[0] and f[0] > 0
                and 'horizontal' not in str(f[4]).lower()]
    print(f"== n_puertos (escaneo vertical): {len(vertical)} muestras ==")
    for segmento, pred in [('destino interno', lambda f: es_interna(f[2])),
                           ('destino externo', lambda f: not es_interna(f[2]))]:
        sub = [f[0] for f in vertical if pred(f)]
        pct = percentiles(sub)
        if pct:
            print(f"  {segmento:<16} n={pct['n']:>5}  "
                  f"P50={pct[50]:>4}  P90={pct[90]:>4}  "
                  f"P95={pct[95]:>4}  P99={pct[99]:>4}  MAX={pct['max']:>5}")
    print()

    # --- Horizontal: destinos distintos para un mismo puerto ---
    horizontal = [f for f in filas if f[1] and f[1] > 0]
    print(f"== n_destinos (barrido horizontal): {len(horizontal)} muestras ==")
    for segmento, pred in [('destino interno', lambda f: es_interna(f[2])),
                           ('destino externo', lambda f: not es_interna(f[2]))]:
        sub = [f[1] for f in horizontal if pred(f)]
        pct = percentiles(sub)
        if pct:
            print(f"  {segmento:<16} n={pct['n']:>5}  "
                  f"P50={pct[50]:>4}  P90={pct[90]:>4}  "
                  f"P95={pct[95]:>4}  P99={pct[99]:>4}  MAX={pct['max']:>5}")
    print()

    # --- Ritmo diario ---
    print("== Eventos por día ==")
    por_dia = {}
    for f in filas:
        por_dia[f[3][:10]] = por_dia.get(f[3][:10], 0) + 1
    for dia in sorted(por_dia):
        print(f"  {dia}  {por_dia[dia]:>6}")

    print("\n== Umbral sugerido (P99 + 20 %, redondeado hacia arriba) ==")
    horizontales_set = [f for f in filas if 'horizontal' in str(f[4]).lower()]
    for nombre, col, es_horiz, interno in (
            ('vertical externo', 0, False, False),
            ('vertical interno', 0, False, True),
            ('horizontal externo', 1, True, False),
            ('horizontal interno', 1, True, True)):
        if es_horiz:
            sub = [f[col] for f in horizontales_set
                   if f[col] and (es_interna(f[2]) == interno)]
        else:
            sub = [f[col] for f in filas
                   if f[col] and 'horizontal' not in str(f[4]).lower()
                   and (es_interna(f[2]) == interno)]
        pct = percentiles(sub)
        if pct:
            sugerido = max(1, math.ceil(pct[99] * 1.2))
            print(f"  {nombre:<18} P99={pct[99]:>4}  ->  {sugerido}  (n={pct['n']})")
    print("\nDocumenta el valor elegido y su percentil en el informe de calibración.")
    conn.close()


if __name__ == '__main__':
    main()
