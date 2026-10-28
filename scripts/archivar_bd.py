# -*- coding: utf-8 -*-
"""
archivar_bd.py — Archiva la base de datos anterior dejando rastro auditable.

Uso:
    python scripts/archivar_bd.py [--origen intrusiones.db] [--etiqueta test]

Qué hace:
  1. Mueve la BD (y sus -wal/-shm si existen) a evidencia/db_archive/.
  2. Calcula el SHA-256 de cada archivo movido.
  3. Escribe una ficha en texto plano con: fecha, procedencia, nº de filas,
     rango temporal de las alertas y hash.

La BD NO se versiona en git (*.db está en .gitignore): el rastro auditable en
el repositorio es la ficha + los hashes, no el binario.
"""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(ruta, bloque=1024 * 1024):
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for chunk in iter(lambda: f.read(bloque), b''):
            h.update(chunk)
    return h.hexdigest()


def resumen_bd(ruta):
    """Devuelve (total, min_ts, max_ts, por_tipo) leyendo la tabla ataques."""
    try:
        conn = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True)
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM ataques").fetchone()[0]
        rango = cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM ataques").fetchone()
        tipos = cur.execute(
            "SELECT tipo_ataque, COUNT(*) FROM ataques GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return total, rango[0], rango[1], tipos
    except Exception as e:
        return None, None, None, [(f"<no consultable: {e}>", 0)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--origen', default=os.path.join(BASE_DIR, 'intrusiones.db'))
    ap.add_argument('--etiqueta', default='test', help='procedencia (test|produccion)')
    args = ap.parse_args()

    if not os.path.exists(args.origen):
        print(f"[X] No existe {args.origen}. Nada que archivar.")
        sys.exit(1)

    destino_dir = os.path.join(BASE_DIR, 'evidencia', 'db_archive')
    os.makedirs(destino_dir, exist_ok=True)

    marca = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    nombre = f"{os.path.splitext(os.path.basename(args.origen))[0]}_{args.etiqueta}_{marca}.db"
    destino = os.path.join(destino_dir, nombre)

    total, min_ts, max_ts, tipos = resumen_bd(args.origen)
    hashes = {}

    try:
        shutil.move(args.origen, destino)
        hashes[nombre] = sha256(destino)
        for extra in (args.origen + '-wal', args.origen + '-shm'):
            if os.path.exists(extra):
                nombre_extra = os.path.basename(extra) + '_' + marca
                shutil.move(extra, os.path.join(destino_dir, nombre_extra))
                hashes[nombre_extra] = sha256(os.path.join(destino_dir, nombre_extra))
    except PermissionError as e:
        print(f"[X] La BD está en uso (¿interfaz o sniffer abiertos?): {e}")
        print("    Detén el monitoreo y cierra la interfaz antes de archivar.")
        sys.exit(2)

    ficha = {
        'archivado_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'procedencia': args.etiqueta,
        'archivo': nombre,
        'filas_ataques': total,
        'primera_alerta': min_ts,
        'ultima_alerta': max_ts,
        'tipos': tipos,
        'sha256': hashes,
        'nota': 'BD archivada al lanzar la v5 (docs/PLAN_LANZAMIENTO_V5.md).',
    }
    ruta_ficha = os.path.join(destino_dir, nombre + '.ficha.json')
    with open(ruta_ficha, 'w', encoding='utf-8') as f:
        json.dump(ficha, f, ensure_ascii=False, indent=2)

    print("[OK] Base de datos archivada:")
    print(f"     -> {destino}")
    print(f"     -> {ruta_ficha}")
    print(f"     Filas: {total} | Rango: {min_ts} .. {max_ts}")
    for t, n in tipos:
        print(f"       {n:>7}  {t}")


if __name__ == '__main__':
    main()
