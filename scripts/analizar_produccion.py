# -*- coding: utf-8 -*-
"""
analizar_produccion.py — Reproduce el post-mortem de la v1 y mide políticas.

Uso:
    python scripts/analizar_produccion.py [ruta_csv] [--anonimizar salida.csv]

Por defecto analiza `alertas_sospechosas_falso_positivo.csv` (18.288 alertas,
2026-08-21 → 2026-10-28) e imprime:
  - volumen por día, concentración por IP (top-N que suma el 80 %),
  - reparto interno/externo,
  - efecto exacto de cada exención candidata (CDN/DNS),
  - alerta tras alerta para una IP concreta (ritmo del throttle).

Con --anonimizar escribe una copia con las IPs internas/externas mapeadas
(IN-001, EX-001…) apta para versionar o publicar (ver
docs/informe_privacidad_ips.md).
"""
import argparse
import collections
import csv
import ipaddress
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_DEFECTO = os.path.join(BASE_DIR, 'alertas_sospechosas_falso_positivo.csv')

# Mismas exenciones que ids.py (una sola fuente de verdad conceptual).
IPS_EXENTAS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9',
               '208.67.222.222', '208.67.220.220'}
RANGOS_EXENTOS = [
    ipaddress.ip_network('34.117.0.0/16'),
    ipaddress.ip_network('57.144.0.0/16'),
    ipaddress.ip_network('149.154.0.0/16'),
    ipaddress.ip_network('172.217.0.0/16'),
    ipaddress.ip_network('142.250.0.0/15'),
    ipaddress.ip_network('104.16.0.0/13'),
]


def parse_ts(texto):
    for fmt in ('%a %b %d %H:%M:%S %Y',):
        try:
            return datetime.strptime(texto, fmt)
        except ValueError:
            continue
    return None


def es_exenta(ip):
    if ip in IPS_EXENTAS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in r for r in RANGOS_EXENTOS)


def es_interna(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or ip.startswith(('172.10.', '172.20.', '172.30.'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('csv', nargs='?', default=CSV_DEFECTO)
    ap.add_argument('--anonimizar', metavar='SALIDA')
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        print(f"[X] No existe {args.csv}")
        sys.exit(1)

    filas = []
    with open(args.csv, encoding='utf-8', errors='replace', newline='') as f:
        for r in csv.DictReader(f):
            r['ts'] = parse_ts(r.get('timestamp', ''))
            filas.append(r)
    con_ts = [r for r in filas if r['ts']]
    print(f"Archivo: {args.csv}")
    print(f"Filas: {len(filas)} (con marca temporal válida: {len(con_ts)})")
    if con_ts:
        print(f"Rango: {min(r['ts'] for r in con_ts)} -> {max(r['ts'] for r in con_ts)}")

    print("\n== Volumen por tipo ==")
    for tipo, n in collections.Counter(r['tipo'] for r in filas).most_common():
        print(f"  {n:>7}  {tipo}")

    escaneos = [r for r in filas if 'Escaneo' in r['tipo']]
    if escaneos:
        print(f"\n== Escaneos: {len(escaneos)} ==")
        print("== Por día ==")
        for dia, n in sorted(collections.Counter(r['ts'].strftime('%Y-%m-%d') for r in escaneos if r['ts']).items()):
            print(f"  {dia}  {n:>6}")

        cont = collections.Counter(r['ip_src'] for r in escaneos)
        print(f"\n== Concentración == IPs distintas: {len(cont)}")
        acc, top = 0, 0
        for ip, n in cont.most_common():
            acc += n
            top += 1
            if acc >= 0.8 * len(escaneos):
                break
        print(f"  El 80 % del ruido proviene de {top} IPs")
        print("  Top 10:")
        for ip, n in cont.most_common(10):
            print(f"  {n:>7}  {ip}")

        internos = sum(1 for r in escaneos if es_interna(r['ip_src']))
        print(f"\n== Origen == interno: {internos} ({100*internos/len(escaneos):.1f} %) | "
              f"externo: {len(escaneos)-internos}")

        print("\n== Efecto de exenciones (por IP origen) ==")
        grupos = {
            'DNS públicos': lambda ip: ip in IPS_EXENTAS,
            'Google LB 34.117/16': lambda ip: ip.startswith('34.117.'),
            'Telegram 149.154/16': lambda ip: ip.startswith('149.154.'),
            'Meta 57.144/16': lambda ip: ip.startswith('57.144.'),
        }
        for nombre, pred in grupos.items():
            n = sum(1 for r in escaneos if pred(r['ip_src']))
            print(f"  {nombre:<22} {n:>7}  ({100*n/len(escaneos):.1f} %)")
        n_exentas = sum(1 for r in escaneos if es_exenta(r['ip_src']))
        print(f"  {'TOTAL exentas':<22} {n_exentas:>7}  ({100*n_exentas/len(escaneos):.1f} %)")

    if args.anonimizar:
        mapeo = {}
        contadores = {'IN': 0, 'EX': 0}

        def anon(ip):
            if ip not in mapeo:
                clave = 'IN' if es_interna(ip) else 'EX'
                contadores[clave] += 1
                mapeo[ip] = f"{clave}-{contadores[clave]:03d}"
            return mapeo[ip]

        with open(args.anonimizar, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            campos = ['id', 'timestamp', 'ip_src_anon', 'ip_dst_anon', 'tipo',
                      'tipo_completo', 'protocolo', 'puerto', 'vlan_id',
                      'confianza_ml', 'motivo']
            w.writerow(campos)
            for r in filas:
                w.writerow([
                    r.get('id', ''), r.get('timestamp', ''),
                    anon(r.get('ip_src', '')), anon(r.get('ip_dst', '')),
                    r.get('tipo', ''), r.get('tipo_completo', ''),
                    r.get('protocolo', ''), r.get('puerto', ''),
                    r.get('vlan_id', ''), r.get('confianza_ml', ''),
                    r.get('motivo', ''),
                ])
        print(f"\n[OK] Copia anonimizada: {args.anonimizar} ({len(mapeo)} IPs mapeadas)")


if __name__ == '__main__':
    main()
